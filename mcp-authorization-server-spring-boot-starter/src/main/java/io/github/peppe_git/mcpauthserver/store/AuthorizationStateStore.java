// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Instant;
import java.util.Optional;

/**
 * Short-lived state of the authorization step: pending requests (minutes) and authorization codes
 * (seconds). With more than one application instance this store must be shared (JDBC), because the
 * token request may reach another instance.
 *
 * <p>Implementations must make {@code take*} atomic: of two concurrent calls with the same key, at most
 * one returns a value. That is what makes a request produce at most one code and a code be exchanged at
 * most once, even when the exchange fails.
 */
public interface AuthorizationStateStore {

	void saveRequest(PendingAuthorization request);

	/** The request if it exists and has not expired at {@code now}. */
	Optional<PendingAuthorization> findRequest(String requestId, Instant now);

	/** Removes and returns the request if it exists and has not expired at {@code now}. */
	Optional<PendingAuthorization> takeRequest(String requestId, Instant now);

	void saveCode(String codeHash, IssuedCode code);

	/** Removes and returns the code if it exists and has not expired at {@code now}. */
	Optional<IssuedCode> takeCode(String codeHash, Instant now);

	/** Deletes expired entries; returns how many. */
	int purgeExpired(Instant now);

}
