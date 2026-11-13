// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.spi;

import java.util.Optional;

import org.springframework.security.core.Authentication;

/**
 * Tells the authorization server who the authenticated user is, and whether that user may still use
 * the grants they approved.
 *
 * <p>The default implementation uses {@link Authentication#getName()} and considers every subject
 * active. Applications that can disable or delete users should implement {@link #isActive(String)}:
 * it is called on every MCP request and on every refresh, so access ends on the next request instead of
 * when the refresh token expires.
 */
public interface McpPrincipalResolver {

	/**
	 * The principal approving the request, or empty to refuse it (the consent page answers 403).
	 * @param authentication the application's authentication of the current browser session
	 */
	Optional<McpPrincipal> resolve(Authentication authentication);

	/**
	 * Whether the subject may still use its grants. When this returns false, MCP requests fail with
	 * {@code invalid_token} and the next refresh revokes the grant.
	 */
	default boolean isActive(String subject) {
		return true;
	}

}
