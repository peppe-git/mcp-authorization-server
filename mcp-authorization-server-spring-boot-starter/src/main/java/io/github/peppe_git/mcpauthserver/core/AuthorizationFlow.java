// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.util.MultiValueMap;

import io.github.peppe_git.mcpauthserver.client.ClientResolver;
import io.github.peppe_git.mcpauthserver.client.RegisteredClient;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.oauth.Pkce;
import io.github.peppe_git.mcpauthserver.oauth.RedirectUris;
import io.github.peppe_git.mcpauthserver.oauth.ResourceIdentifiers;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipal;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipalResolver;
import io.github.peppe_git.mcpauthserver.spi.ScopePolicy;
import io.github.peppe_git.mcpauthserver.store.AuthorizationStateStore;
import io.github.peppe_git.mcpauthserver.store.IssuedCode;
import io.github.peppe_git.mcpauthserver.store.PendingAuthorization;

/**
 * The browser half of the authorization code flow: validation of {@code /oauth2/authorize}, then the
 * user's decision on the consent page.
 *
 * <p><b>Two kinds of errors.</b> Until the client and its redirect URI are verified, an error must not
 * go back to the redirect URI (that would be an open redirect to an arbitrary address): it is shown on
 * an error page. Afterwards errors go back to the client as RFC 6749 §4.1.2.1 describes, with
 * {@code state} and {@code iss} (RFC 9207).
 */
public final class AuthorizationFlow {

	/** Outcome of a request to the authorization endpoint or of a consent decision. */
	public sealed interface Result {

		/** Show an error page; nothing is sent to the client. */
		record ShowError(int status, String error, String description) implements Result {
		}

		/** Redirect the browser to the client (success or a client-facing error). */
		record RedirectToClient(String location) implements Result {
		}

		/** Send the user to the consent page for this pending request. */
		record AskConsent(String requestId) implements Result {
		}

		/** Render the consent page. */
		record RenderConsent(PendingAuthorization request, McpPrincipal principal, List<String> scopes)
				implements Result {
		}

	}

	private static final int MAX_STATE_LENGTH = 1024;

	private final McpServerSettings settings;

	private final ClientResolver clients;

	private final AuthorizationStateStore state;

	private final McpPrincipalResolver principals;

	private final ScopePolicy scopePolicy;

	private final Clock clock;

	private final Consumer<McpAuthorizationEvent> events;

	public AuthorizationFlow(McpServerSettings settings, ClientResolver clients, AuthorizationStateStore state,
			McpPrincipalResolver principals, ScopePolicy scopePolicy, Clock clock,
			Consumer<McpAuthorizationEvent> events) {
		this.settings = settings;
		this.clients = clients;
		this.state = state;
		this.principals = principals;
		this.scopePolicy = scopePolicy;
		this.clock = clock;
		this.events = events;
	}

	/** {@code GET /oauth2/authorize}. */
	public Result authorize(MultiValueMap<String, String> params) {
		if (count(params, "client_id") != 1 || count(params, "redirect_uri") > 1) {
			return new Result.ShowError(400, "invalid_request", "client_id must be present exactly once.");
		}
		Optional<RegisteredClient> resolved = this.clients.resolve(params.getFirst("client_id"));
		if (resolved.isEmpty()) {
			return new Result.ShowError(400, "invalid_client",
					"The client is unknown, or its metadata document could not be used.");
		}
		RegisteredClient client = resolved.get();
		String redirectUri = params.getFirst("redirect_uri");
		if (redirectUri == null || !RedirectUris.matchesAny(redirectUri, client.redirectUris())
				|| (!this.settings.allowedRedirectUris().isEmpty()
						&& !RedirectUris.matchesAny(redirectUri, this.settings.allowedRedirectUris()))) {
			return new Result.ShowError(400, "invalid_request",
					"redirect_uri is missing or is not registered for this client.");
		}

		// From here on the redirect URI is trusted: errors go back to the client.
		String state = params.getFirst("state");
		for (Map.Entry<String, List<String>> e : params.entrySet()) {
			if (e.getValue().size() > 1) {
				return backToClient(redirectUri, "invalid_request", "Parameter " + e.getKey() + " is repeated.",
						(e.getKey().equals("state") ? null : state));
			}
		}
		if (state != null && state.length() > MAX_STATE_LENGTH) {
			return backToClient(redirectUri, "invalid_request", "state is too long.", null);
		}
		if (params.containsKey("request") || params.containsKey("request_uri")) {
			return backToClient(redirectUri, "request_not_supported", "Request objects are not supported.", state);
		}
		if (!"code".equals(params.getFirst("response_type"))) {
			return backToClient(redirectUri, "unsupported_response_type", "Only response_type=code is supported.",
					state);
		}
		if (!Pkce.S256.equals(params.getFirst("code_challenge_method"))
				|| !Pkce.isValidChallenge(params.getFirst("code_challenge"))) {
			return backToClient(redirectUri, "invalid_request", "PKCE with code_challenge_method=S256 is required.",
					state);
		}
		Optional<List<String>> scopes = this.settings.scopes().parse(params.getFirst("scope"));
		if (scopes.isEmpty()) {
			return backToClient(redirectUri, "invalid_scope", "Unknown scope.", state);
		}
		String resource = params.getFirst("resource");
		if (resource != null && !ResourceIdentifiers.same(resource, this.settings.resource())) {
			return backToClient(redirectUri, "invalid_target", "Unknown resource.", state);
		}

		PendingAuthorization pending = new PendingAuthorization(OpaqueTokens.random(), client.clientId(),
				client.clientName(), client.verification(), client.verifiedDomain(), redirectUri,
				params.getFirst("code_challenge"), scopes.get(), state, this.settings.resource(),
				Instant.now(this.clock).plus(this.settings.authorizationRequestTtl()));
		this.state.saveRequest(pending);
		return new Result.AskConsent(pending.requestId());
	}

	/** {@code GET /oauth2/consent}: what to show to the signed-in user. */
	public Result prepareConsent(String requestId, Authentication authentication) {
		Optional<PendingAuthorization> pending = this.state.findRequest(requestId, Instant.now(this.clock));
		if (pending.isEmpty()) {
			return expired();
		}
		Optional<McpPrincipal> principal = this.principals.resolve(authentication);
		if (principal.isEmpty()) {
			return new Result.ShowError(403, "access_denied", "This account cannot authorize applications.");
		}
		List<String> grantable = grantable(principal.get(), pending.get());
		if (grantable.isEmpty() && !pending.get().scopes().isEmpty()) {
			this.state.takeRequest(requestId, Instant.now(this.clock));
			return deny(pending.get(), principal.get(), "The account cannot grant the requested scopes.");
		}
		return new Result.RenderConsent(pending.get(), principal.get(), grantable);
	}

	/** {@code POST /oauth2/consent}: the user's decision. The request is consumed either way. */
	public Result decide(String requestId, Authentication authentication, boolean approve) {
		Optional<McpPrincipal> principal = this.principals.resolve(authentication);
		if (principal.isEmpty()) {
			return new Result.ShowError(403, "access_denied", "This account cannot authorize applications.");
		}
		Instant now = Instant.now(this.clock);
		Optional<PendingAuthorization> taken = this.state.takeRequest(requestId, now);
		if (taken.isEmpty()) {
			return expired();
		}
		PendingAuthorization p = taken.get();
		if (!approve) {
			return deny(p, principal.get(), null);
		}
		List<String> grantable = grantable(principal.get(), p);
		if (grantable.isEmpty() && !p.scopes().isEmpty()) {
			return deny(p, principal.get(), "The account cannot grant the requested scopes.");
		}
		String code = OpaqueTokens.random();
		this.state.saveCode(OpaqueTokens.hash(code), new IssuedCode(p.clientId(), p.clientName(), p.redirectUri(),
				p.codeChallenge(), grantable, p.resource(), principal.get().subject(),
				now.plus(this.settings.authorizationCodeTtl())));
		Map<String, String> q = new LinkedHashMap<>();
		q.put("code", code);
		q.put("state", p.state());
		q.put("iss", this.settings.issuer());
		return new Result.RedirectToClient(withQuery(p.redirectUri(), q));
	}

	private List<String> grantable(McpPrincipal principal, PendingAuthorization p) {
		Set<String> requested = new LinkedHashSet<>(p.scopes());
		Set<String> allowed = this.scopePolicy.grantableScopes(principal, p.clientId(), Set.copyOf(requested));
		requested.retainAll(allowed == null ? Set.of() : allowed);
		return this.settings.scopes().ordered(requested);
	}

	private Result deny(PendingAuthorization p, McpPrincipal principal, String description) {
		this.events.accept(new McpAuthorizationEvent.ConsentDenied(Instant.now(this.clock), principal.subject(),
				p.clientId()));
		return backToClient(p.redirectUri(), "access_denied", description, p.state());
	}

	private static Result expired() {
		return new Result.ShowError(400, "invalid_request",
				"This authorization request has expired or was already used. Start again from the application.");
	}

	private Result backToClient(String redirectUri, String error, String description, String state) {
		Map<String, String> q = new LinkedHashMap<>();
		q.put("error", error);
		q.put("error_description", description);
		q.put("state", state);
		q.put("iss", this.settings.issuer());
		return new Result.RedirectToClient(withQuery(redirectUri, q));
	}

	private static int count(MultiValueMap<String, String> params, String name) {
		List<String> values = params.get(name);
		return (values == null) ? 0 : values.size();
	}

	/** Appends parameters to an already validated redirect URI (which has no fragment). */
	static String withQuery(String base, Map<String, String> params) {
		StringBuilder sb = new StringBuilder(base);
		char sep = base.contains("?") ? '&' : '?';
		for (Map.Entry<String, String> e : params.entrySet()) {
			if (e.getValue() == null) {
				continue;
			}
			sb.append(sep).append(encode(e.getKey())).append('=').append(encode(e.getValue()));
			sep = '&';
		}
		return sb.toString();
	}

	private static String encode(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
	}

}
