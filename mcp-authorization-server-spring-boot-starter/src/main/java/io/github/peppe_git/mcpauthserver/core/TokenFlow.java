// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.util.MultiValueMap;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;
import io.github.peppe_git.mcpauthserver.oauth.OAuthException;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.oauth.Pkce;
import io.github.peppe_git.mcpauthserver.oauth.ResourceIdentifiers;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipalResolver;
import io.github.peppe_git.mcpauthserver.store.AuthorizationStateStore;
import io.github.peppe_git.mcpauthserver.store.Grant;
import io.github.peppe_git.mcpauthserver.store.GrantStore;
import io.github.peppe_git.mcpauthserver.store.IssuedCode;
import io.github.peppe_git.mcpauthserver.store.Rotation;
import io.github.peppe_git.mcpauthserver.store.TokenHashes;

/**
 * The token endpoint ({@code authorization_code} and {@code refresh_token}) and the revocation endpoint
 * (RFC 7009), for public clients only.
 */
public final class TokenFlow {

	private final McpServerSettings settings;

	private final AuthorizationStateStore state;

	private final GrantStore grants;

	private final McpPrincipalResolver principals;

	private final Clock clock;

	private final Consumer<McpAuthorizationEvent> events;

	public TokenFlow(McpServerSettings settings, AuthorizationStateStore state, GrantStore grants,
			McpPrincipalResolver principals, Clock clock, Consumer<McpAuthorizationEvent> events) {
		this.settings = settings;
		this.state = state;
		this.grants = grants;
		this.principals = principals;
		this.clock = clock;
		this.events = events;
	}

	/**
	 * {@code POST /oauth2/token}.
	 * @param form the form parameters
	 * @param clientAuthenticationHeader true if the request carried an {@code Authorization} header:
	 * confidential client authentication is not supported
	 */
	public Map<String, Object> token(MultiValueMap<String, String> form, boolean clientAuthenticationHeader) {
		checkPublicClient(form, clientAuthenticationHeader);
		String grantType = single(form, "grant_type");
		if ("authorization_code".equals(grantType)) {
			return exchangeCode(form);
		}
		if ("refresh_token".equals(grantType)) {
			return refresh(form);
		}
		throw OAuthException.unsupportedGrantType("Supported grant types: authorization_code, refresh_token.");
	}

	private Map<String, Object> exchangeCode(MultiValueMap<String, String> form) {
		String code = required(form, "code");
		String verifier = required(form, "code_verifier");
		String clientId = required(form, "client_id");
		String redirectUri = required(form, "redirect_uri");
		String resource = single(form, "resource");
		Instant now = Instant.now(this.clock);
		// The code is consumed before any check: a wrong verifier burns it, so it cannot be guessed at.
		IssuedCode issued = this.state.takeCode(OpaqueTokens.hash(code), now)
			.orElseThrow(() -> OAuthException.invalidGrant("Unknown, expired or already used code."));
		if (!issued.clientId().equals(clientId) || !issued.redirectUri().equals(redirectUri)) {
			throw OAuthException.invalidGrant("client_id or redirect_uri does not match the authorization request.");
		}
		if (resource != null && !ResourceIdentifiers.same(resource, issued.resource())) {
			throw OAuthException.invalidTarget("Unknown resource.");
		}
		if (!Pkce.verify(verifier, issued.codeChallenge())) {
			throw OAuthException.invalidGrant("PKCE verification failed.");
		}
		if (!this.principals.isActive(issued.subject())) {
			throw OAuthException.invalidGrant("The user can no longer authorize this client.");
		}
		String access = OpaqueTokens.newAccessToken();
		String refresh = OpaqueTokens.newRefreshToken();
		Grant grant = this.grants.createGrant(issued.subject(), issued.clientId(), issued.clientName(), issued.scopes(),
				issued.resource(), hashes(access, refresh, now));
		this.events.accept(new McpAuthorizationEvent.GrantCreated(now, grant.grantId(), grant.subject(),
				grant.clientId(), grant.scopes()));
		return response(access, refresh, grant.scopes());
	}

	private Map<String, Object> refresh(MultiValueMap<String, String> form) {
		String refresh = required(form, "refresh_token");
		String clientId = required(form, "client_id");
		String scope = single(form, "scope");
		String resource = single(form, "resource");
		if (!refresh.startsWith(OpaqueTokens.REFRESH_TOKEN_PREFIX)) {
			throw OAuthException.invalidGrant("Unknown refresh token.");
		}
		Instant now = Instant.now(this.clock);
		String access = OpaqueTokens.newAccessToken();
		String next = OpaqueTokens.newRefreshToken();
		Rotation r = this.grants.rotate(OpaqueTokens.hash(refresh), clientId, hashes(access, next, now),
				this.settings.refreshPolicy(), this.principals::isActive, g -> {
					if (scope != null && !Set.copyOf(g.scopes()).containsAll(scopeSet(scope))) {
						return "invalid_scope";
					}
					if (resource != null && !ResourceIdentifiers.same(resource, g.resource())) {
						return "invalid_target";
					}
					return null;
				});
		switch (r.outcome()) {
			case ROTATED -> {
				// A narrower scope is not issued per token: the response states the grant's actual scope.
				return response(access, next, r.grant().scopes());
			}
			case REUSE_DETECTED -> {
				Grant g = r.grant();
				this.events.accept(new McpAuthorizationEvent.RefreshTokenReuseDetected(now, g.grantId(), g.subject(),
						g.clientId()));
				this.events.accept(new McpAuthorizationEvent.GrantRevoked(now, g.grantId(), g.subject(), g.clientId(),
						RevocationReason.REFRESH_TOKEN_REUSE));
				throw OAuthException.invalidGrant("Refresh token reuse detected: the authorization was revoked.");
			}
			default -> {
				if (r.revokedNow() && r.grant() != null) {
					Grant g = r.grant();
					this.events.accept(new McpAuthorizationEvent.GrantRevoked(now, g.grantId(), g.subject(),
							g.clientId(), RevocationReason.SUBJECT_INACTIVE));
				}
				if ("invalid_scope".equals(r.reason())) {
					throw OAuthException.invalidScope("The requested scope exceeds the original grant.");
				}
				if ("invalid_target".equals(r.reason())) {
					throw OAuthException.invalidTarget("Unknown resource.");
				}
				throw OAuthException.invalidGrant(describe(r.reason()));
			}
		}
	}

	/** {@code POST /oauth2/revoke}: always 200 for a well-formed request, known token or not (RFC 7009 §2.2). */
	public void revoke(MultiValueMap<String, String> form, boolean clientAuthenticationHeader) {
		checkPublicClient(form, clientAuthenticationHeader);
		String token = required(form, "token");
		String clientId = required(form, "client_id");
		single(form, "token_type_hint");
		Instant now = Instant.now(this.clock);
		Optional<Grant> revoked = this.grants.revokeByToken(OpaqueTokens.hash(token), clientId, now);
		revoked.ifPresent(g -> this.events.accept(new McpAuthorizationEvent.GrantRevoked(now, g.grantId(), g.subject(),
				g.clientId(), RevocationReason.CLIENT)));
	}

	private void checkPublicClient(MultiValueMap<String, String> form, boolean clientAuthenticationHeader) {
		for (Map.Entry<String, List<String>> e : form.entrySet()) {
			if (e.getValue().size() > 1) {
				throw OAuthException.invalidRequest("Parameter " + e.getKey() + " is repeated.");
			}
		}
		if (clientAuthenticationHeader || form.containsKey("client_secret") || form.containsKey("client_assertion")) {
			throw OAuthException.invalidClient("Only public clients are supported (token_endpoint_auth_method=none).");
		}
	}

	private TokenHashes hashes(String access, String refresh, Instant now) {
		return new TokenHashes(OpaqueTokens.hash(access), OpaqueTokens.hash(refresh), now,
				now.plus(this.settings.accessTokenTtl()), now.plus(this.settings.refreshTokenTtl()));
	}

	private Map<String, Object> response(String access, String refresh, List<String> scopes) {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("access_token", access);
		body.put("token_type", "Bearer");
		body.put("expires_in", this.settings.accessTokenTtl().toSeconds());
		body.put("refresh_token", refresh);
		body.put("scope", String.join(" ", scopes));
		return body;
	}

	static String describe(String reason) {
		return switch (reason == null ? "" : reason) {
			case "expired" -> "Refresh token expired: authorize again.";
			case "revoked" -> "The authorization was revoked: the user must connect the client again.";
			case "wrong_client" -> "The refresh token was issued to a different client.";
			case "subject_inactive" -> "The user can no longer use this authorization.";
			default -> "Unknown refresh token.";
		};
	}

	private static Set<String> scopeSet(String scope) {
		return Set.of(scope.strip().split(" +"));
	}

	private static String required(MultiValueMap<String, String> form, String name) {
		String value = single(form, name);
		if (value == null || value.isBlank()) {
			throw OAuthException.invalidRequest("Missing parameter: " + name + ".");
		}
		return value;
	}

	private static String single(MultiValueMap<String, String> form, String name) {
		return form.getFirst(name);
	}

}
