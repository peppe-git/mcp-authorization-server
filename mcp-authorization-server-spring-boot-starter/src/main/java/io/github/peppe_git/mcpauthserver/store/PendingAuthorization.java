// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;
import java.util.List;

import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;

/**
 * An authorization request validated by the authorization endpoint and waiting for the user's decision.
 *
 * @param requestId random identifier, bound to the browser session that started the request
 * @param clientId the client identifier
 * @param clientName the client's display name at the time of the request
 * @param verification how the client identity was established
 * @param verifiedDomain the verified domain of a metadata-document client, otherwise null
 * @param redirectUri the validated redirect URI
 * @param codeChallenge the S256 PKCE challenge
 * @param scopes the requested, supported scopes
 * @param state the client's {@code state}, returned unchanged; may be null
 * @param resource the canonical resource identifier the grant will be bound to
 * @param expiresAt when the request expires
 */
public record PendingAuthorization(String requestId, String clientId, String clientName,
		ClientVerification verification, String verifiedDomain, String redirectUri, String codeChallenge,
		List<String> scopes, String state, String resource, Instant expiresAt) {

	public PendingAuthorization {
		scopes = List.copyOf(scopes);
	}

}
