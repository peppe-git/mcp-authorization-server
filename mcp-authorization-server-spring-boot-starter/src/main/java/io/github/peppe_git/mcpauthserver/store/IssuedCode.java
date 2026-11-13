// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;
import java.util.List;

/**
 * An authorization code minted by the consent step. Only the hash of the code is used as key.
 *
 * @param clientId the client the code was issued to
 * @param clientName the client's display name, copied to the grant
 * @param redirectUri the redirect URI that must be repeated at the token endpoint
 * @param codeChallenge the S256 PKCE challenge
 * @param scopes the scopes the user granted
 * @param resource the canonical resource identifier
 * @param subject the user who approved
 * @param expiresAt when the code expires
 */
public record IssuedCode(String clientId, String clientName, String redirectUri, String codeChallenge,
		List<String> scopes, String resource, String subject, Instant expiresAt) {

	public IssuedCode {
		scopes = List.copyOf(scopes);
	}

}
