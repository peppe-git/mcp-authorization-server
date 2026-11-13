// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.oauth;

/**
 * An OAuth protocol error, rendered as {@code {"error": ..., "error_description": ...}} (RFC 6749 §5.2)
 * or as {@code error} and {@code error_description} parameters on a redirect.
 *
 * <p>The description is read by client developers, never by end users. It must never contain a token,
 * a code or a verifier.
 */
public final class OAuthException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final String error;

	private final int status;

	public OAuthException(String error, String description, int status) {
		super(description, null, false, false);
		this.error = error;
		this.status = status;
	}

	public static OAuthException invalidRequest(String description) {
		return new OAuthException("invalid_request", description, 400);
	}

	public static OAuthException invalidGrant(String description) {
		return new OAuthException("invalid_grant", description, 400);
	}

	public static OAuthException invalidClient(String description) {
		return new OAuthException("invalid_client", description, 401);
	}

	public static OAuthException invalidScope(String description) {
		return new OAuthException("invalid_scope", description, 400);
	}

	public static OAuthException invalidTarget(String description) {
		return new OAuthException("invalid_target", description, 400);
	}

	public static OAuthException unsupportedGrantType(String description) {
		return new OAuthException("unsupported_grant_type", description, 400);
	}

	/** The OAuth error code, e.g. {@code invalid_grant}. */
	public String error() {
		return this.error;
	}

	/** The HTTP status for a direct (non-redirect) response. */
	public int status() {
		return this.status;
	}

}
