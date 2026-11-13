// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;

/**
 * A freshly issued token pair, as stored: hashes and lifetimes, never the token values.
 *
 * @param accessHash SHA-256 of the access token
 * @param refreshHash SHA-256 of the refresh token
 * @param issuedAt issue time; also "now" for the operation that issues the pair
 * @param accessExpiresAt access token expiry
 * @param refreshExpiresAt refresh token expiry
 */
public record TokenHashes(String accessHash, String refreshHash, Instant issuedAt, Instant accessExpiresAt,
		Instant refreshExpiresAt) {
}
