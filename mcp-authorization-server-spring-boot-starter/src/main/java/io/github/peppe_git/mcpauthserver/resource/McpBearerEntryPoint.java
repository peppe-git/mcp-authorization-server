// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.resource;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import io.github.peppe_git.mcpauthserver.core.McpServerSettings;

/**
 * The 401 of the MCP endpoint (RFC 6750 §3, RFC 9728 §5.1): {@code WWW-Authenticate: Bearer} with
 * {@code resource_metadata}, so the client can discover the authorization server, and {@code scope}, so
 * it knows what to ask for. {@code error="invalid_token"} is added when a token was presented but is not
 * valid, so the client refreshes instead of starting over. No description is given: it would only help
 * someone probing tokens.
 */
public final class McpBearerEntryPoint implements AuthenticationEntryPoint {

	private final McpServerSettings settings;

	public McpBearerEntryPoint(McpServerSettings settings) {
		this.settings = settings;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) {
		StringBuilder header = new StringBuilder("Bearer ");
		if (ex instanceof OAuth2AuthenticationException oauth && "invalid_token".equals(oauth.getError().getErrorCode())) {
			header.append("error=\"invalid_token\", ");
		}
		header.append("resource_metadata=\"").append(this.settings.resourceMetadataUrl()).append('"');
		String scope = String.join(" ", this.settings.scopes().defaults());
		if (!scope.isEmpty()) {
			header.append(", scope=\"").append(scope).append('"');
		}
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, header.toString());
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

}
