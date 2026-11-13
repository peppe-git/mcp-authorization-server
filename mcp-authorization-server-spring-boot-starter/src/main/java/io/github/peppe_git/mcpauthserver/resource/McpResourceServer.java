// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.resource;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Applies the MCP resource-server rules to a security filter chain: bearer tokens checked in-process,
 * stateless, no CSRF (no cookie is involved), MCP-shaped 401 and 403.
 *
 * <p>The starter uses it for its own chain on {@code mcp.authorization-server.resource-server.path-patterns}.
 * Call it from your own chain if you disable that one:
 *
 * <pre>{@code
 * http.securityMatcher("/mcp/**")
 *     .authorizeHttpRequests(a -> a.anyRequest().hasAuthority("SCOPE_tools.read"));
 * McpResourceServer.apply(http, introspector, entryPoint, accessDeniedHandler);
 * }</pre>
 */
public final class McpResourceServer {

	private McpResourceServer() {
	}

	public static HttpSecurity apply(HttpSecurity http, OpaqueTokenIntrospector introspector,
			AuthenticationEntryPoint entryPoint, AccessDeniedHandler accessDeniedHandler) {
		http.oauth2ResourceServer(rs -> rs.opaqueToken(o -> o.introspector(introspector))
			.authenticationEntryPoint(entryPoint)
			.accessDeniedHandler(accessDeniedHandler))
			.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.csrf(c -> c.disable())
			.exceptionHandling(e -> e.authenticationEntryPoint(entryPoint).accessDeniedHandler(accessDeniedHandler));
		return http;
	}

}
