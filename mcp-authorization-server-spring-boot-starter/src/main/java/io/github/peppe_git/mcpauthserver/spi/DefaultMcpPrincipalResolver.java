// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.spi;

import java.util.Optional;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Uses {@link Authentication#getName()} as subject and display name, refuses anonymous users, and
 * considers every subject active. Replace it when user names can change or users can be disabled.
 */
public class DefaultMcpPrincipalResolver implements McpPrincipalResolver {

	@Override
	public Optional<McpPrincipal> resolve(Authentication authentication) {
		if (authentication == null || !authentication.isAuthenticated()
				|| authentication instanceof AnonymousAuthenticationToken || authentication.getName() == null
				|| authentication.getName().isBlank()) {
			return Optional.empty();
		}
		return Optional.of(new McpPrincipal(authentication.getName(), authentication.getName()));
	}

}
