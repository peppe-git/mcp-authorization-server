// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.autoconfigure;

import java.util.stream.Stream;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.github.peppe_git.mcpauthserver.core.McpEndpoints;
import io.github.peppe_git.mcpauthserver.core.McpServerSettings;
import io.github.peppe_git.mcpauthserver.resource.McpBearerAccessDeniedHandler;
import io.github.peppe_git.mcpauthserver.resource.McpBearerEntryPoint;
import io.github.peppe_git.mcpauthserver.resource.McpOpaqueTokenIntrospector;
import io.github.peppe_git.mcpauthserver.resource.McpResourceServer;

/**
 * The security filter chains of the starter.
 *
 * <ol>
 * <li><b>Authorization server</b> (highest precedence): OAuth endpoints and discovery documents. Only
 * the consent page requires the user to be signed in (through the application's own login, found in the
 * session); it is the only CSRF-protected form. Token, revocation and registration ignore CSRF: they
 * use no cookie.</li>
 * <li><b>Resource server</b>: the MCP path requires a valid access token.</li>
 * <li><b>Fallback</b>: only if the application has no chain of its own, every other route requires a
 * signed-in user (form login), like Spring Boot's default.</li>
 * </ol>
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class McpAuthorizationServerSecurityConfiguration {

	static final String AUTHORIZATION_SERVER_CHAIN = "mcpAuthorizationServerSecurityFilterChain";

	static final String RESOURCE_SERVER_CHAIN = "mcpResourceServerSecurityFilterChain";

	static final String FALLBACK_CHAIN = "mcpFallbackSecurityFilterChain";

	@Bean(AUTHORIZATION_SERVER_CHAIN)
	@Order(Ordered.HIGHEST_PRECEDENCE + 10)
	SecurityFilterChain mcpAuthorizationServerSecurityFilterChain(HttpSecurity http, McpServerSettings settings)
			throws Exception {
		RequestMatcher endpoints = new OrRequestMatcher(Stream
			.of(McpEndpoints.AUTHORIZE, McpEndpoints.CONSENT, McpEndpoints.TOKEN, McpEndpoints.REVOKE,
					McpEndpoints.REGISTER, McpEndpoints.AUTHORIZATION_SERVER_METADATA,
					McpEndpoints.AUTHORIZATION_SERVER_METADATA + "/**", McpEndpoints.PROTECTED_RESOURCE_METADATA,
					McpEndpoints.PROTECTED_RESOURCE_METADATA + "/**")
			.<RequestMatcher>map(p -> PathPatternRequestMatcher.withDefaults().matcher(p))
			.toList());
		// The container's error dispatch for one of these endpoints (415, 404, 405...) must keep its status:
		// without this the application's chain would answer it, typically with a 401 or a login redirect.
		RequestMatcher errorOfEndpoints = McpAuthorizationServerSecurityConfiguration::isErrorDispatchOfOwnEndpoint;
		http.securityMatcher(new OrRequestMatcher(endpoints, errorOfEndpoints))
			.authorizeHttpRequests(a -> a.dispatcherTypeMatchers(DispatcherType.ERROR)
				.permitAll()
				.requestMatchers(McpEndpoints.CONSENT)
				.authenticated()
				.anyRequest()
				.permitAll())
			.csrf(c -> c.ignoringRequestMatchers(PathPatternRequestMatcher.withDefaults().matcher(McpEndpoints.TOKEN),
					PathPatternRequestMatcher.withDefaults().matcher(McpEndpoints.REVOKE),
					PathPatternRequestMatcher.withDefaults().matcher(McpEndpoints.REGISTER), errorOfEndpoints))
			.exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint(settings.loginPage()), AnyRequestMatcher.INSTANCE));
		return http.build();
	}

	static boolean isErrorDispatchOfOwnEndpoint(HttpServletRequest request) {
		if (request.getDispatcherType() != DispatcherType.ERROR
				|| !(request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI) instanceof String uri)) {
			return false;
		}
		String path = uri.startsWith(request.getContextPath()) ? uri.substring(request.getContextPath().length()) : uri;
		return path.startsWith("/oauth2/") || path.startsWith(McpEndpoints.AUTHORIZATION_SERVER_METADATA)
				|| path.startsWith(McpEndpoints.PROTECTED_RESOURCE_METADATA);
	}

	@Bean(RESOURCE_SERVER_CHAIN)
	@Order(Ordered.HIGHEST_PRECEDENCE + 20)
	@ConditionalOnProperty(prefix = "mcp.authorization-server.resource-server", name = "enabled", havingValue = "true",
			matchIfMissing = true)
	SecurityFilterChain mcpResourceServerSecurityFilterChain(HttpSecurity http,
			McpAuthorizationServerProperties properties, McpOpaqueTokenIntrospector introspector,
			McpBearerEntryPoint entryPoint, McpBearerAccessDeniedHandler accessDeniedHandler) throws Exception {
		http.securityMatcher(properties.getResourceServer().getPathPatterns().toArray(String[]::new))
			.authorizeHttpRequests(a -> a.anyRequest().authenticated());
		McpResourceServer.apply(http, introspector, entryPoint, accessDeniedHandler);
		return http.build();
	}

	@Bean(FALLBACK_CHAIN)
	@Order(Ordered.LOWEST_PRECEDENCE - 10)
	@Conditional(NoApplicationSecurityFilterChainCondition.class)
	SecurityFilterChain mcpFallbackSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults())
			.httpBasic(Customizer.withDefaults());
		return http.build();
	}

}
