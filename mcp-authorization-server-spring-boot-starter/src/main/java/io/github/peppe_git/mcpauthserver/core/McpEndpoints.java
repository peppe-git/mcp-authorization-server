// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.core;

/** Paths of the endpoints served by the starter, relative to the application root. */
public final class McpEndpoints {

	public static final String AUTHORIZE = "/oauth2/authorize";

	public static final String CONSENT = "/oauth2/consent";

	public static final String TOKEN = "/oauth2/token";

	public static final String REVOKE = "/oauth2/revoke";

	public static final String REGISTER = "/oauth2/register";

	/** RFC 8414 authorization server metadata. */
	public static final String AUTHORIZATION_SERVER_METADATA = "/.well-known/oauth-authorization-server";

	/** RFC 9728 protected resource metadata. */
	public static final String PROTECTED_RESOURCE_METADATA = "/.well-known/oauth-protected-resource";

	private McpEndpoints() {
	}

}
