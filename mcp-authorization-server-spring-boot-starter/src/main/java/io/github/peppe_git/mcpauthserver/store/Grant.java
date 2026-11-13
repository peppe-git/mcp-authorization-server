// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;
import java.util.List;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;

/**
 * A user's consent for one client, with its family of token pairs.
 *
 * @param grantId random identifier
 * @param subject the user
 * @param clientId the client
 * @param clientName the client's display name when the grant was created
 * @param scopes the granted scopes
 * @param resource the canonical resource identifier (the audience of every token)
 * @param createdAt creation time
 * @param lastUsedAt last MCP request, updated at most every few minutes; may be null
 * @param revokedAt revocation time, null while active
 * @param revokedReason why the grant was revoked, null while active
 */
public record Grant(String grantId, String subject, String clientId, String clientName, List<String> scopes,
		String resource, Instant createdAt, Instant lastUsedAt, Instant revokedAt, RevocationReason revokedReason) {

	public Grant {
		scopes = List.copyOf(scopes);
	}

	public boolean isRevoked() {
		return this.revokedAt != null;
	}

}
