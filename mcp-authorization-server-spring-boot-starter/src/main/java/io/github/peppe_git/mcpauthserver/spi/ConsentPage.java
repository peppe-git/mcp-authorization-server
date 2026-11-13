// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.spi;

import java.util.List;

/**
 * Everything a consent page must show. All strings are raw: a renderer must escape them.
 *
 * @param requestId the pending request, to post back with the decision
 * @param clientId the client identifier as presented (for a metadata-document client, an HTTPS URL)
 * @param clientName the client's name, sanitized but self-asserted unless {@code verification} says
 * otherwise
 * @param verification how much the client's identity is verified
 * @param verifiedDomain for {@link ClientVerification#DOMAIN}, the host of the client identifier URL
 * @param redirectUri where the browser goes after the decision
 * @param redirectHost the host of {@code redirectUri}; the MCP specification requires showing it
 * @param loopbackRedirect true when the redirect goes to this computer ({@code localhost}); the page
 * should warn that a local program will receive the authorization
 * @param scopes the scopes the user is about to grant
 * @param principal the user approving
 * @param formAction the URL the decision form must post to
 * @param csrfParameterName the name of the CSRF form field
 * @param csrfToken the CSRF token value
 */
public record ConsentPage(String requestId, String clientId, String clientName, ClientVerification verification,
		String verifiedDomain, String redirectUri, String redirectHost, boolean loopbackRedirect,
		List<ScopeView> scopes, McpPrincipal principal, String formAction, String csrfParameterName,
		String csrfToken) {

	/** How the client identity was established. */
	public enum ClientVerification {

		/** Configured by the operator of this server. */
		OPERATOR,

		/** A Client ID Metadata Document served from {@code verifiedDomain} over HTTPS. */
		DOMAIN,

		/** Self-asserted through dynamic registration: the name proves nothing. */
		NONE

	}

	/** A scope and its human-readable description. */
	public record ScopeView(String name, String description) {
	}

}
