// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.client;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import io.github.peppe_git.mcpauthserver.core.McpServerSettings;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;
import io.github.peppe_git.mcpauthserver.oauth.OAuthException;
import io.github.peppe_git.mcpauthserver.oauth.OpaqueTokens;
import io.github.peppe_git.mcpauthserver.oauth.RedirectUris;
import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

/**
 * RFC 7591 dynamic registration, restricted to public clients of the authorization code flow
 * (ADR-0003). Off by default.
 */
public final class DynamicClientRegistration {

	private static final List<String> GRANT_TYPES = List.of("authorization_code", "refresh_token");

	private final McpServerSettings settings;

	private final ClientStore store;

	private final Clock clock;

	private final Consumer<McpAuthorizationEvent> events;

	public DynamicClientRegistration(McpServerSettings settings, ClientStore store, Clock clock,
			Consumer<McpAuthorizationEvent> events) {
		this.settings = settings;
		this.store = store;
		this.clock = clock;
		this.events = events;
	}

	/** Registers a client and returns the RFC 7591 §3.2.1 response body. */
	public Map<String, Object> register(Map<String, Object> request) {
		if (request == null) {
			throw metadata("The request body must be a JSON object.");
		}
		Object authMethod = request.get("token_endpoint_auth_method");
		if (authMethod != null && !"none".equals(authMethod)) {
			throw metadata("Only public clients are supported: token_endpoint_auth_method must be none.");
		}
		Object grantTypes = request.get("grant_types");
		if (grantTypes != null && (!(grantTypes instanceof List<?> g) || !g.contains("authorization_code")
				|| !GRANT_TYPES.containsAll(g))) {
			throw metadata("grant_types must be authorization_code, optionally with refresh_token.");
		}
		Object responseTypes = request.get("response_types");
		if (responseTypes != null && !List.of("code").equals(responseTypes)) {
			throw metadata("response_types must be [\"code\"].");
		}
		Object rawRedirects = request.get("redirect_uris");
		if (!(rawRedirects instanceof List<?> list) || list.isEmpty() || list.size() > this.settings.dcrMaxRedirectUris()) {
			throw redirect("redirect_uris must list 1 to " + this.settings.dcrMaxRedirectUris() + " URIs.");
		}
		List<String> redirects = new ArrayList<>();
		for (Object r : list) {
			if (!(r instanceof String s) || !RedirectUris.isWellFormed(s)) {
				throw redirect("Every redirect URI must be https or loopback http, without fragment.");
			}
			if (!this.settings.allowedRedirectUris().isEmpty()
					&& !RedirectUris.matchesAny(s, this.settings.allowedRedirectUris())) {
				throw redirect("A redirect URI is not accepted by this server.");
			}
			redirects.add(s);
		}
		Object name = request.get("client_name");
		if (name != null && !(name instanceof String)) {
			throw metadata("client_name must be a string.");
		}
		String clientName = ClientNames.sanitize((String) name, "Unnamed client");
		RegisteredClient client = new RegisteredClient(OpaqueTokens.newDynamicClientId(), clientName, redirects,
				ClientVerification.NONE, null);
		this.store.save(client);
		Instant now = Instant.now(this.clock);
		this.events.accept(new McpAuthorizationEvent.ClientRegistered(now, client.clientId(), clientName, redirects));

		Map<String, Object> body = new LinkedHashMap<>();
		body.put("client_id", client.clientId());
		body.put("client_id_issued_at", now.getEpochSecond());
		body.put("client_name", clientName);
		body.put("redirect_uris", redirects);
		body.put("token_endpoint_auth_method", "none");
		body.put("grant_types", GRANT_TYPES);
		body.put("response_types", List.of("code"));
		return body;
	}

	private static OAuthException metadata(String description) {
		return new OAuthException("invalid_client_metadata", description, 400);
	}

	private static OAuthException redirect(String description) {
		return new OAuthException("invalid_redirect_uri", description, 400);
	}

}
