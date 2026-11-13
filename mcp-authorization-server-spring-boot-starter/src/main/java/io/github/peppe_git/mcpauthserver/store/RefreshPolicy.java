// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Duration;

/**
 * The two grace windows of refresh-token rotation (ADR-0004).
 *
 * @param reuseGrace a rotated refresh token presented again within this window, while the family still
 * has an active pair, yields a sibling pair (concurrent refreshes). Zero disables it.
 * @param lostResponseGrace the immediate predecessor of the latest rotation, presented again within this
 * window while its successors were never used, supersedes them and yields a new pair once (a response
 * lost in transit). Zero disables it.
 */
public record RefreshPolicy(Duration reuseGrace, Duration lostResponseGrace) {

	/** No grace at all: every replay is reuse. */
	public static final RefreshPolicy STRICT = new RefreshPolicy(Duration.ZERO, Duration.ZERO);

}
