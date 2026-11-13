// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.spi;

import java.util.Objects;

/**
 * The user who approves an authorization request.
 *
 * @param subject a stable, unique identifier of the user; it is stored in the grant and exposed to the
 * MCP server as the {@code sub} attribute. Never an e-mail address that the user can change.
 * @param displayName how the consent page greets the user
 */
public record McpPrincipal(String subject, String displayName) {

	public McpPrincipal {
		Objects.requireNonNull(subject, "subject");
		if (subject.isBlank() || subject.length() > 255) {
			throw new IllegalArgumentException("subject must be 1 to 255 characters");
		}
		displayName = (displayName == null || displayName.isBlank()) ? subject : displayName;
	}

}
