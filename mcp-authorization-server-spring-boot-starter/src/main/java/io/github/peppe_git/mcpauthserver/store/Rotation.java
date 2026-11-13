// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.store;

/**
 * Result of presenting a refresh token.
 *
 * @param outcome what happened
 * @param grant the grant, when the token was known
 * @param reason for {@link Outcome#INVALID}: {@code unknown}, {@code expired}, {@code revoked},
 * {@code wrong_client} or {@code subject_inactive}
 * @param revokedNow true if this call revoked the grant (reuse, or inactive subject)
 */
public record Rotation(Outcome outcome, Grant grant, String reason, boolean revokedNow) {

	/** What a refresh produced. */
	public enum Outcome {

		/** A new pair was issued (rotation, sibling or recovery). */
		ROTATED,

		/** The token was a replay outside the grace windows: the grant is now revoked. */
		REUSE_DETECTED,

		/** The token cannot be used; nothing was issued. */
		INVALID

	}

	public static Rotation rotated(Grant grant) {
		return new Rotation(Outcome.ROTATED, grant, null, false);
	}

	public static Rotation reuse(Grant grant) {
		return new Rotation(Outcome.REUSE_DETECTED, grant, "reuse", true);
	}

	public static Rotation invalid(String reason) {
		return new Rotation(Outcome.INVALID, null, reason, false);
	}

	public static Rotation invalid(String reason, Grant grant, boolean revokedNow) {
		return new Rotation(Outcome.INVALID, grant, reason, revokedNow);
	}

}
