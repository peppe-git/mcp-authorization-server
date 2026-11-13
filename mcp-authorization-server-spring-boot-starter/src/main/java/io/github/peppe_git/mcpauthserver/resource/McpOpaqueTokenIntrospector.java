// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.resource;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import io.github.peppe_git.mcpauthserver.core.McpServerSettings;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.oauth.ResourceIdentifiers;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipalResolver;
import io.github.peppe_git.mcpauthserver.spi.ScopePolicy;
import io.github.peppe_git.mcpauthserver.store.AccessTokenInfo;
import io.github.peppe_git.mcpauthserver.store.Grant;
import io.github.peppe_git.mcpauthserver.store.GrantStore;

/**
 * Checks an access token in-process, against the grant store: no network call, and a revocation takes
 * effect on the next request.
 *
 * <p>A token is accepted only if its pair is active and not expired, its grant is not revoked, its
 * audience is this server's resource (RFC 8707) and {@link McpPrincipalResolver#isActive} still holds.
 * The authenticated principal exposes {@code sub}, {@code client_id}, {@code scope}, {@code aud},
 * {@code iat}, {@code exp} and {@code grant_id}.
 */
public final class McpOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	private static final Log logger = LogFactory.getLog(McpOpaqueTokenIntrospector.class);

	private final GrantStore grants;

	private final McpServerSettings settings;

	private final McpPrincipalResolver principals;

	private final ScopePolicy scopePolicy;

	private final Clock clock;

	public McpOpaqueTokenIntrospector(GrantStore grants, McpServerSettings settings, McpPrincipalResolver principals,
			ScopePolicy scopePolicy, Clock clock) {
		this.grants = grants;
		this.settings = settings;
		this.principals = principals;
		this.scopePolicy = scopePolicy;
		this.clock = clock;
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		if (token == null || !token.startsWith(OpaqueTokens.ACCESS_TOKEN_PREFIX)) {
			throw new BadOpaqueTokenException("Not an access token of this server.");
		}
		Instant now = Instant.now(this.clock);
		Optional<AccessTokenInfo> found = this.grants.findActiveAccessToken(OpaqueTokens.hash(token), now);
		if (found.isEmpty()) {
			throw new BadOpaqueTokenException("The access token is invalid, expired or revoked.");
		}
		Grant g = found.get().grant();
		if (!ResourceIdentifiers.same(g.resource(), this.settings.resource())) {
			throw new BadOpaqueTokenException("The access token was issued for another resource.");
		}
		if (!this.principals.isActive(g.subject())) {
			throw new BadOpaqueTokenException("The user can no longer use this authorization.");
		}
		try {
			this.grants.recordUse(g.grantId(), found.get().tokenId(), now);
		}
		catch (RuntimeException ex) {
			// Bookkeeping only: it must never fail a valid request.
			logger.warn("Could not record the use of grant " + g.grantId() + ": " + ex.getMessage());
		}
		Map<String, Object> attributes = new LinkedHashMap<>();
		attributes.put(OAuth2TokenIntrospectionClaimNames.SUB, g.subject());
		attributes.put(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, g.clientId());
		attributes.put(OAuth2TokenIntrospectionClaimNames.SCOPE, g.scopes());
		attributes.put(OAuth2TokenIntrospectionClaimNames.AUD, List.of(g.resource()));
		attributes.put(OAuth2TokenIntrospectionClaimNames.IAT, found.get().issuedAt());
		attributes.put(OAuth2TokenIntrospectionClaimNames.EXP, found.get().expiresAt());
		attributes.put("grant_id", g.grantId());
		return new DefaultOAuth2AuthenticatedPrincipal(g.subject(), attributes,
				this.scopePolicy.authorities(Set.copyOf(g.scopes())));
	}

}
