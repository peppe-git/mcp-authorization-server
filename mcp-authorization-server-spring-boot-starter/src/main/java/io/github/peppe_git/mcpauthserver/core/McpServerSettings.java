// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

import io.github.peppe_git.mcpauthserver.oauth.RedirectUris;
import io.github.peppe_git.mcpauthserver.oauth.ResourceIdentifiers;
import io.github.peppe_git.mcpauthserver.store.RefreshPolicy;

/**
 * The validated, resolved configuration of the server. Construction fails fast on anything unsafe.
 *
 * @param issuer the issuer identifier (RFC 8414), without trailing slash
 * @param resource the canonical identifier of the protected MCP resource
 * @param resourceName optional human-readable name of the resource
 * @param loginPage where an unauthenticated user is sent before the consent page
 * @param scopes the scope registry
 * @param accessTokenTtl access token lifetime
 * @param refreshTokenTtl refresh token lifetime (sliding: every rotation issues a new one)
 * @param authorizationRequestTtl how long a pending request waits for the user
 * @param authorizationCodeTtl how long a code may wait before the exchange
 * @param refreshPolicy rotation grace windows
 * @param allowedRedirectUris optional server-wide allow list of redirect URIs (empty: no extra limit)
 * @param cimdEnabled whether metadata-document clients are accepted
 * @param dcrEnabled whether dynamic registration is open
 * @param dcrMaxRedirectUris maximum redirect URIs of a dynamically registered client
 */
public record McpServerSettings(String issuer, String resource, String resourceName, String loginPage,
		ScopeRegistry scopes, Duration accessTokenTtl, Duration refreshTokenTtl, Duration authorizationRequestTtl,
		Duration authorizationCodeTtl, RefreshPolicy refreshPolicy, List<String> allowedRedirectUris,
		boolean cimdEnabled, boolean dcrEnabled, int dcrMaxRedirectUris) {

	public McpServerSettings {
		issuer = validateIssuer(issuer);
		resource = ResourceIdentifiers.canonical(resource)
			.filter(McpServerSettings::isHttpsOrLoopback)
			.orElseThrow(() -> new IllegalStateException(
					"mcp.authorization-server.resource must be an absolute https URL (http only on localhost)"));
		positive(accessTokenTtl, "tokens.access-token-ttl");
		positive(refreshTokenTtl, "tokens.refresh-token-ttl");
		positive(authorizationRequestTtl, "tokens.authorization-request-ttl");
		positive(authorizationCodeTtl, "tokens.authorization-code-ttl");
		if (authorizationCodeTtl.compareTo(Duration.ofMinutes(10)) > 0) {
			throw new IllegalStateException("tokens.authorization-code-ttl must not exceed 10 minutes");
		}
		if (refreshPolicy.reuseGrace().isNegative() || refreshPolicy.lostResponseGrace().isNegative()) {
			throw new IllegalStateException("refresh grace windows must not be negative");
		}
		allowedRedirectUris = List.copyOf(allowedRedirectUris);
		for (String uri : allowedRedirectUris) {
			if (!RedirectUris.isWellFormed(uri)) {
				throw new IllegalStateException("allowed-redirect-uris contains a URI that is not https or loopback http: " + uri);
			}
		}
		if (loginPage == null || !loginPage.startsWith("/")) {
			throw new IllegalStateException("mcp.authorization-server.login-page must be a path starting with /");
		}
		if (dcrMaxRedirectUris < 1 || dcrMaxRedirectUris > 20) {
			throw new IllegalStateException("dcr.max-redirect-uris must be between 1 and 20");
		}
	}

	public String authorizationEndpoint() {
		return this.issuer + McpEndpoints.AUTHORIZE;
	}

	public String tokenEndpoint() {
		return this.issuer + McpEndpoints.TOKEN;
	}

	public String revocationEndpoint() {
		return this.issuer + McpEndpoints.REVOKE;
	}

	public String registrationEndpoint() {
		return this.issuer + McpEndpoints.REGISTER;
	}

	/** RFC 9728 §3.1: the well-known path inserted between the resource's origin and its path. */
	public String resourceMetadataUrl() {
		URI r = URI.create(this.resource);
		String origin = this.resource.substring(0, this.resource.length() - pathOf(r).length());
		return origin + McpEndpoints.PROTECTED_RESOURCE_METADATA + pathOf(r);
	}

	/** The path (and query) of the resource identifier, possibly empty. */
	public String resourcePath() {
		return pathOf(URI.create(this.resource));
	}

	/** The path of the issuer, possibly empty (RFC 8414 §3.1 path insertion). */
	public String issuerPath() {
		String p = URI.create(this.issuer).getRawPath();
		return (p == null) ? "" : p;
	}

	private static String pathOf(URI u) {
		String path = (u.getRawPath() == null) ? "" : u.getRawPath();
		return (u.getRawQuery() == null) ? path : path + "?" + u.getRawQuery();
	}

	private static String validateIssuer(String issuer) {
		if (issuer == null || issuer.isBlank()) {
			throw new IllegalStateException("mcp.authorization-server.issuer is required");
		}
		URI u;
		try {
			u = new URI(issuer.strip());
		}
		catch (URISyntaxException ex) {
			throw new IllegalStateException("mcp.authorization-server.issuer is not a valid URL");
		}
		if (!u.isAbsolute() || u.getHost() == null || u.getRawQuery() != null || u.getRawFragment() != null
				|| u.getRawUserInfo() != null) {
			throw new IllegalStateException("mcp.authorization-server.issuer must be an absolute URL without query or fragment");
		}
		String value = u.toString();
		while (value.endsWith("/")) {
			value = value.substring(0, value.length() - 1);
		}
		if (!isHttpsOrLoopback(value)) {
			throw new IllegalStateException("mcp.authorization-server.issuer must use https (http only on localhost)");
		}
		return value;
	}

	private static boolean isHttpsOrLoopback(String value) {
		URI u = URI.create(value);
		String scheme = u.getScheme().toLowerCase(Locale.ROOT);
		String host = u.getHost().toLowerCase(Locale.ROOT);
		return scheme.equals("https")
				|| (scheme.equals("http") && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]")));
	}

	private static void positive(Duration d, String name) {
		if (d == null || d.isZero() || d.isNegative()) {
			throw new IllegalStateException("mcp.authorization-server." + name + " must be positive");
		}
	}

}
