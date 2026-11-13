// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * The single decision function of refresh-token rotation, shared by every {@link GrantStore}. It is
 * pure: the store loads the family under a lock, asks for a decision and applies it.
 */
public final class RotationRules {

	/** Status of a token pair in its family. */
	public enum Status {

		/** Usable. */
		ACTIVE,

		/** Its refresh token was exchanged for a new pair. */
		ROTATED,

		/** Never used, and replaced when its predecessor recovered a lost response. */
		SUPERSEDED

	}

	/**
	 * A token pair as the rules see it.
	 *
	 * @param tokenId identifier of the pair
	 * @param createdAt issue time
	 * @param refreshExpiresAt refresh token expiry
	 * @param status current status
	 * @param endedAt when it stopped being active (rotated or superseded), else null
	 * @param firstUsedAt first use of the pair (an MCP request or a refresh), else null
	 */
	public record TokenState(String tokenId, Instant createdAt, Instant refreshExpiresAt, Status status,
			Instant endedAt, Instant firstUsedAt) {
	}

	/** What to do with a presented refresh token. */
	public enum Action {

		/** The token is active: mark it rotated and issue the next pair. */
		ROTATE,

		/** Rotated moments ago while the family is alive: issue a sibling pair, change nothing else. */
		SIBLING,

		/** Lost response: supersede {@link Decision#supersede()} and issue a new pair. */
		RECOVER,

		/** Reuse: revoke the grant. */
		REUSE,

		/** Expired: refuse without revoking. */
		EXPIRED

	}

	/** A decision and, for {@link Action#RECOVER}, the pairs to supersede. */
	public record Decision(Action action, List<String> supersede) {

		static Decision of(Action action) {
			return new Decision(action, List.of());
		}

	}

	private RotationRules() {
	}

	/**
	 * @param presented the pair whose refresh token was presented, as re-read under the grant lock
	 * @param family every pair of the grant, including {@code presented}
	 * @param now the current time
	 * @param policy the grace windows
	 */
	public static Decision decide(TokenState presented, List<TokenState> family, Instant now, RefreshPolicy policy) {
		if (!presented.refreshExpiresAt().isAfter(now)) {
			return Decision.of(Action.EXPIRED);
		}
		if (presented.status() == Status.ACTIVE) {
			return Decision.of(Action.ROTATE);
		}
		if (presented.status() == Status.ROTATED) {
			List<TokenState> active = family.stream().filter(t -> t.status() == Status.ACTIVE).toList();
			if (within(presented.endedAt(), now, policy.reuseGrace()) && !active.isEmpty()) {
				return Decision.of(Action.SIBLING);
			}
			boolean immediatePredecessor = family.stream()
				.noneMatch(t -> t.endedAt() != null && t.endedAt().isAfter(presented.endedAt()));
			List<TokenState> successors = active.stream()
				.filter(t -> !t.createdAt().isBefore(presented.endedAt()))
				.toList();
			boolean successorsUnused = successors.stream().allMatch(t -> t.firstUsedAt() == null);
			if (immediatePredecessor && successorsUnused && within(presented.endedAt(), now, policy.lostResponseGrace())) {
				return new Decision(Action.RECOVER, successors.stream().map(TokenState::tokenId).toList());
			}
		}
		return Decision.of(Action.REUSE);
	}

	/** {@code at} happened no more than {@code window} before {@code now}; a zero window never matches. */
	static boolean within(Instant at, Instant now, Duration window) {
		if (at == null || window == null || window.isZero() || window.isNegative()) {
			return false;
		}
		return !at.plus(window).isBefore(now);
	}

}
