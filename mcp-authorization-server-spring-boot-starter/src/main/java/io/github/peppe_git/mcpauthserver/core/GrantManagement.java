// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;

import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent;
import io.github.peppe_git.mcpauthserver.event.McpAuthorizationEvent.RevocationReason;
import io.github.peppe_git.mcpauthserver.store.Grant;
import io.github.peppe_git.mcpauthserver.store.GrantStore;

/**
 * Application-facing management of grants: a "connected apps" page and account recovery. Access ends on
 * the next MCP request after a revocation.
 */
public final class GrantManagement {

	private final GrantStore grants;

	private final Clock clock;

	private final Consumer<McpAuthorizationEvent> events;

	public GrantManagement(GrantStore grants, Clock clock, Consumer<McpAuthorizationEvent> events) {
		this.grants = grants;
		this.clock = clock;
		this.events = events;
	}

	/** The subject's active grants, newest first. */
	public List<Grant> activeGrants(String subject) {
		return this.grants.findActiveGrants(subject);
	}

	/** Revokes one of the subject's grants; false if it does not exist, is not theirs or is already revoked. */
	public boolean revoke(String subject, String grantId) {
		Instant now = Instant.now(this.clock);
		return this.grants.revokeGrant(grantId, subject, RevocationReason.USER, now).map(g -> {
			this.events.accept(new McpAuthorizationEvent.GrantRevoked(now, g.grantId(), g.subject(), g.clientId(),
					RevocationReason.USER));
			return true;
		}).orElse(false);
	}

	/**
	 * Revokes every grant of a subject, for example after a password reset or an account takeover.
	 * Returns how many grants were revoked.
	 */
	public int revokeAll(String subject) {
		Instant now = Instant.now(this.clock);
		List<Grant> revoked = this.grants.revokeAllForSubject(subject, RevocationReason.ADMINISTRATIVE, now);
		revoked.forEach(g -> this.events.accept(new McpAuthorizationEvent.GrantRevoked(now, g.grantId(), g.subject(),
				g.clientId(), RevocationReason.ADMINISTRATIVE)));
		return revoked.size();
	}

}
