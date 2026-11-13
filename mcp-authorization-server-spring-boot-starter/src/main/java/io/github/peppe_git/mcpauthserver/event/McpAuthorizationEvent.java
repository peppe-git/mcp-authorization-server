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

	/** @return when the event happened */
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

	/**
	 * A client registered through RFC 7591 dynamic registration.
	 * @param occurredAt when it happened
	 * @param clientId the issued client identifier
	 * @param clientName the sanitized, self-asserted name
	 * @param redirectUris the registered redirect URIs
	 */
	record ClientRegistered(Instant occurredAt, String clientId, String clientName, List<String> redirectUris)
			implements McpAuthorizationEvent {
	}

	/**
	 * A Client ID Metadata Document could not be used.
	 * @param occurredAt when it happened
	 * @param clientId the client identifier URL, as presented
	 * @param reason why, for operators (never shown to the browser)
	 */
	record ClientMetadataRejected(Instant occurredAt, String clientId, String reason) implements McpAuthorizationEvent {
	}

	/**
	 * The user refused the request on the consent page, or could not grant any requested scope.
	 * @param occurredAt when it happened
	 * @param subject the user
	 * @param clientId the client
	 */
	record ConsentDenied(Instant occurredAt, String subject, String clientId) implements McpAuthorizationEvent {
	}

	/**
	 * A code was exchanged: a new grant exists.
	 * @param occurredAt when it happened
	 * @param grantId the new grant
	 * @param subject the user who approved
	 * @param clientId the client
	 * @param scopes the granted scopes
	 */
	record GrantCreated(Instant occurredAt, String grantId, String subject, String clientId, List<String> scopes)
			implements McpAuthorizationEvent {
	}

	/**
	 * A rotated refresh token was replayed; the grant has been revoked. Worth an alert.
	 * @param occurredAt when it happened
	 * @param grantId the revoked grant
	 * @param subject the user
	 * @param clientId the client
	 */
	record RefreshTokenReuseDetected(Instant occurredAt, String grantId, String subject, String clientId)
			implements McpAuthorizationEvent {
	}

	/**
	 * A grant was revoked.
	 * @param occurredAt when it happened
	 * @param grantId the revoked grant
	 * @param subject the user
	 * @param clientId the client
	 * @param reason why
	 */
	record GrantRevoked(Instant occurredAt, String grantId, String subject, String clientId, RevocationReason reason)
			implements McpAuthorizationEvent {
	}

}
