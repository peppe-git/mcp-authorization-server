// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.resource;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import io.github.peppe_git.mcpauthserver.core.McpServerSettings;

/**
 * The 403 of the MCP endpoint for a valid token that lacks a scope (MCP step-up): {@code
 * error="insufficient_scope"} and {@code resource_metadata}. The required scopes depend on the
 * application's authorization rules, which this handler cannot see; replace the bean to add them.
 */
public final class McpBearerAccessDeniedHandler implements AccessDeniedHandler {

	private final McpServerSettings settings;

	public McpBearerAccessDeniedHandler(McpServerSettings settings) {
		this.settings = settings;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) {
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_scope\", resource_metadata=\""
				+ this.settings.resourceMetadataUrl() + "\"");
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
	}

}
