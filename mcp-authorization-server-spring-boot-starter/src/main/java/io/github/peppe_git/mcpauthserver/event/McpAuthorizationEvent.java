// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.event;

import java.time.Instant;
import java.util.List;

/**
 * Audit events, published with Spring's {@code ApplicationEventPublisher}. Listen with
 * {@code @EventListener}.
 *
 * <p>Events never carry a token, a code, a verifier or a hash of them. Listener failures are logged and
 * do not change the OAuth response.
 */
public sealed interface McpAuthorizationEvent {

	Instant occurredAt();

	/** Why a grant ended. */
	enum RevocationReason {

		/** The client revoked a token (RFC 7009). */
		CLIENT,

		/** The user disconnected the client. */
		USER,

		/** {@code McpPrincipalResolver#isActive} returned false during a refresh. */
		SUBJECT_INACTIVE,

		/** A rotated refresh token was presented outside the grace windows. */
		REFRESH_TOKEN_REUSE,

		/** Revoked by the application for every grant of a subject (for example on account recovery). */
		ADMINISTRATIVE

	}

	/** A client registered through RFC 7591 dynamic registration. */
	record ClientRegistered(Instant occurredAt, String clientId, String clientName, List<String> redirectUris)
			implements McpAuthorizationEvent {
	}

	/** A Client ID Metadata Document could not be used. {@code reason} is for operators. */
	record ClientMetadataRejected(Instant occurredAt, String clientId, String reason) implements McpAuthorizationEvent {
	}

	/** The user refused the request on the consent page. */
	record ConsentDenied(Instant occurredAt, String subject, String clientId) implements McpAuthorizationEvent {
	}

	/** A code was exchanged: a new grant exists. */
	record GrantCreated(Instant occurredAt, String grantId, String subject, String clientId, List<String> scopes)
			implements McpAuthorizationEvent {
	}

	/** A rotated refresh token was replayed; the grant has been revoked. */
	record RefreshTokenReuseDetected(Instant occurredAt, String grantId, String subject, String clientId)
			implements McpAuthorizationEvent {
	}

	/** A grant was revoked. */
	record GrantRevoked(Instant occurredAt, String grantId, String subject, String clientId, RevocationReason reason)
			implements McpAuthorizationEvent {
	}

}
