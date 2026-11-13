// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;

/**
 * Grants and their token families. Implementations must serialise {@link #rotate} per grant (a lock on
 * the grant) and apply {@link RotationRules} so that every store behaves the same; the shared contract
 * test checks it.
 */
public interface GrantStore {

	/** Creates a grant with its first token pair. */
	Grant createGrant(String subject, String clientId, String clientName, List<String> scopes, String resource,
			TokenHashes firstPair);

	/** The access token if its pair is active, it has not expired at {@code now} and the grant is active. */
	Optional<AccessTokenInfo> findActiveAccessToken(String accessHash, Instant now);

	/**
	 * Presents a refresh token (ADR-0004). The new pair is stored only when the outcome is
	 * {@link Rotation.Outcome#ROTATED}.
	 * @param refreshHash hash of the presented refresh token
	 * @param clientId the client presenting it
	 * @param next the pair to issue; {@code next.issuedAt()} is "now"
	 * @param policy the grace windows
	 * @param subjectActive called with the grant's subject while the grant is locked; false revokes the
	 * grant
	 * @param refuse checks the request against the grant (scope, resource) before anything changes;
	 * returns null to proceed or an OAuth error code, which becomes the {@link Rotation#reason()} of an
	 * {@link Rotation.Outcome#INVALID} result
	 */
	Rotation rotate(String refreshHash, String clientId, TokenHashes next, RefreshPolicy policy,
			Predicate<String> subjectActive, Function<Grant, String> refuse);

	/**
	 * Revokes the grant owning a token (access or refresh, of any pair of the family) if it belongs to
	 * {@code clientId}. Returns the grant if this call revoked it.
	 */
	Optional<Grant> revokeByToken(String tokenHash, String clientId, Instant now);

	/**
	 * Revokes a grant. When {@code subject} is not null the grant must belong to it. Returns the grant if
	 * this call revoked it.
	 */
	Optional<Grant> revokeGrant(String grantId, String subject, RevocationReason reason, Instant now);

	/** Revokes every active grant of a subject; returns the grants this call revoked. */
	List<Grant> revokeAllForSubject(String subject, RevocationReason reason, Instant now);

	/** The active grants of a subject, newest first. */
	List<Grant> findActiveGrants(String subject);

	/** Records that a token pair was used: first use of the pair, and the grant's last use. */
	void recordUse(String grantId, String tokenId, Instant now);

	/** Deletes token pairs past their refresh expiry, pairs of grants revoked over a day ago, and empty grants. */
	int purgeExpired(Instant now);

}
