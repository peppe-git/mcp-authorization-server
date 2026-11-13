// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;

/**
 * An active access token and its grant.
 *
 * @param grant the (non-revoked) grant
 * @param tokenId the identifier of the token pair
 * @param issuedAt issue time of the pair
 * @param expiresAt access token expiry
 */
public record AccessTokenInfo(Grant grant, String tokenId, Instant issuedAt, Instant expiresAt) {
}
