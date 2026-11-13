// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.autoconfigure;

import java.time.Clock;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import io.github.peppe_git.mcpauthserver.cimd.ClientIdUrls;
import io.github.peppe_git.mcpauthserver.cimd.ClientMetadataResolver;
import io.github.peppe_git.mcpauthserver.cimd.MetadataDocumentFetcher;
import io.github.peppe_git.mcpauthserver.client.ClientNames;
import io.github.peppe_git.mcpauthserver.client.ClientResolver;
import io.github.peppe_git.mcpauthserver.client.ClientStore;
import io.github.peppe_git.mcpauthserver.client.DynamicClientRegistration;
import io.github.peppe_git.mcpauthserver.client.InMemoryClientStore;
import io.github.peppe_git.mcpauthserver.client.JdbcClientStore;
import io.github.peppe_git.mcpauthserver.client.RegisteredClient;
import io.github.peppe_git.mcpauthserver.core.AuthorizationFlow;
import io.github.peppe_git.mcpauthserver.core.EventSink;
import io.github.peppe_git.mcpauthserver.core.GrantManagement;
import io.github.peppe_git.mcpauthserver.core.McpServerSettings;
import io.github.peppe_git.mcpauthserver.core.ScopeRegistry;
import io.github.peppe_git.mcpauthserver.core.TokenFlow;
import io.github.peppe_git.mcpauthserver.oauth.RedirectUris;
import io.github.peppe_git.mcpauthserver.resource.McpBearerAccessDeniedHandler;
import io.github.peppe_git.mcpauthserver.resource.McpBearerEntryPoint;
import io.github.peppe_git.mcpauthserver.resource.McpOpaqueTokenIntrospector;
import io.github.peppe_git.mcpauthserver.spi.ConsentPage.ClientVerification;
import io.github.peppe_git.mcpauthserver.spi.ConsentPageRenderer;
import io.github.peppe_git.mcpauthserver.spi.DefaultMcpPrincipalResolver;
import io.github.peppe_git.mcpauthserver.spi.McpPrincipalResolver;
import io.github.peppe_git.mcpauthserver.spi.ScopePolicy;
import io.github.peppe_git.mcpauthserver.store.AuthorizationStateStore;
import io.github.peppe_git.mcpauthserver.store.GrantStore;
import io.github.peppe_git.mcpauthserver.store.InMemoryAuthorizationStateStore;
import io.github.peppe_git.mcpauthserver.store.InMemoryGrantStore;
import io.github.peppe_git.mcpauthserver.store.JdbcAuthorizationStateStore;
import io.github.peppe_git.mcpauthserver.store.JdbcGrantStore;
import io.github.peppe_git.mcpauthserver.store.RefreshPolicy;
import io.github.peppe_git.mcpauthserver.web.AuthorizationController;
import io.github.peppe_git.mcpauthserver.web.DefaultConsentPageRenderer;
import io.github.peppe_git.mcpauthserver.web.MetadataController;
import io.github.peppe_git.mcpauthserver.web.RegistrationController;
import io.github.peppe_git.mcpauthserver.web.TokenController;

/**
 * Auto-configuration of the MCP authorization server. Every SPI bean backs off when the application
 * defines its own.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ HttpSecurity.class, OpaqueTokenIntrospector.class })
@ConditionalOnProperty(prefix = "mcp.authorization-server", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(McpAuthorizationServerProperties.class)
@Import({ McpAuthorizationServerAutoConfiguration.MemoryStores.class, McpAuthorizationServerAutoConfiguration.JdbcStores.class,
		McpAuthorizationServerSecurityConfiguration.class })
public class McpAuthorizationServerAutoConfiguration {

	private static final Log logger = LogFactory.getLog(McpAuthorizationServerAutoConfiguration.class);

	@Bean
	McpServerSettings mcpServerSettings(McpAuthorizationServerProperties p) {
		McpAuthorizationServerProperties.Tokens t = p.getTokens();
		ScopeRegistry scopes = new ScopeRegistry(p.getScopes()
			.stream()
			.map(s -> new ScopeRegistry.ScopeDefinition(s.getName(), s.getDescription(), s.isDefaultScope()))
			.toList());
		return new McpServerSettings(p.getIssuer(), p.getResource(), p.getResourceName(), p.getLoginPage(), scopes,
				t.getAccessTokenTtl(), t.getRefreshTokenTtl(), t.getAuthorizationRequestTtl(), t.getAuthorizationCodeTtl(),
				new RefreshPolicy(t.getRefreshReuseGrace(), t.getRefreshLostResponseGrace()), p.getAllowedRedirectUris(),
				p.getCimd().isEnabled(), p.getDcr().isEnabled(), p.getDcr().getMaxRedirectUris());
	}

	@Bean
	EventSink mcpAuthorizationEventSink(ApplicationEventPublisher publisher) {
		return new EventSink(publisher::publishEvent);
	}

	@Bean
	@ConditionalOnMissingBean
	McpPrincipalResolver mcpPrincipalResolver() {
		return new DefaultMcpPrincipalResolver();
	}

	@Bean
	@ConditionalOnMissingBean
	ScopePolicy mcpScopePolicy() {
		return ScopePolicy.defaults();
	}

	@Bean
	@ConditionalOnMissingBean
	ConsentPageRenderer mcpConsentPageRenderer() {
		return new DefaultConsentPageRenderer();
	}

	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnProperty(prefix = "mcp.authorization-server.cimd", name = "enabled", havingValue = "true",
			matchIfMissing = true)
	MetadataDocumentFetcher mcpMetadataDocumentFetcher(McpAuthorizationServerProperties p) {
		return new MetadataDocumentFetcher(p.getCimd().getTimeout(), p.getCimd().getMaxDocumentBytes());
	}

	@Bean
	@ConditionalOnBean(MetadataDocumentFetcher.class)
	ClientMetadataResolver mcpClientMetadataResolver(MetadataDocumentFetcher fetcher, McpAuthorizationServerProperties p,
			ObjectProvider<Clock> clock, EventSink events) {
		McpAuthorizationServerProperties.Cimd c = p.getCimd();
		return new ClientMetadataResolver(fetcher,
				new ClientMetadataResolver.Settings(new HashSet<>(c.getAllowedPorts()), new HashSet<>(c.getAllowedHosts()),
						c.getCacheMin(), c.getCacheMax(), c.getCacheDefault(), c.getMaxCacheEntries(),
						c.getMaxConcurrentFetches(), c.getMaxFetchesPerHostPerMinute()),
				clock(clock), events);
	}

	@Bean
	ClientResolver mcpClientResolver(McpAuthorizationServerProperties p, ClientStore store,
			ObjectProvider<ClientMetadataResolver> metadataDocuments) {
		Map<String, RegisteredClient> configured = new LinkedHashMap<>();
		for (McpAuthorizationServerProperties.Client c : p.getClients()) {
			if (c.getClientId() == null || c.getClientId().isBlank() || ClientIdUrls.looksLikeUrl(c.getClientId())
					|| c.getClientId().length() > 255) {
				throw new IllegalStateException("mcp.authorization-server.clients: invalid client-id " + c.getClientId());
			}
			if (c.getRedirectUris().isEmpty() || !c.getRedirectUris().stream().allMatch(RedirectUris::isWellFormed)) {
				throw new IllegalStateException("mcp.authorization-server.clients: client " + c.getClientId()
						+ " needs redirect URIs that are https or loopback http");
			}
			configured.put(c.getClientId(), new RegisteredClient(c.getClientId(),
					ClientNames.sanitize(c.getClientName(), c.getClientId()), c.getRedirectUris(),
					ClientVerification.OPERATOR, null));
		}
		return new ClientResolver(configured, store, metadataDocuments.getIfAvailable());
	}

	@Bean
	AuthorizationFlow mcpAuthorizationFlow(McpServerSettings settings, ClientResolver clients,
			AuthorizationStateStore state, McpPrincipalResolver principals, ScopePolicy scopePolicy,
			ObjectProvider<Clock> clock, EventSink events) {
		return new AuthorizationFlow(settings, clients, state, principals, scopePolicy, clock(clock), events);
	}

	@Bean
	TokenFlow mcpTokenFlow(McpServerSettings settings, AuthorizationStateStore state, GrantStore grants,
			McpPrincipalResolver principals, ObjectProvider<Clock> clock, EventSink events) {
		return new TokenFlow(settings, state, grants, principals, clock(clock), events);
	}

	@Bean
	@ConditionalOnMissingBean
	GrantManagement mcpGrantManagement(GrantStore grants, ObjectProvider<Clock> clock, EventSink events) {
		return new GrantManagement(grants, clock(clock), events);
	}

	@Bean
	DynamicClientRegistration mcpDynamicClientRegistration(McpServerSettings settings, ClientStore store,
			ObjectProvider<Clock> clock, EventSink events) {
		return new DynamicClientRegistration(settings, store, clock(clock), events);
	}

	@Bean
	AuthorizationController mcpAuthorizationController(AuthorizationFlow flow, ConsentPageRenderer renderer,
			McpServerSettings settings) {
		return new AuthorizationController(flow, renderer, settings);
	}

	@Bean
	TokenController mcpTokenController(TokenFlow flow) {
		return new TokenController(flow);
	}

	@Bean
	MetadataController mcpMetadataController(McpServerSettings settings) {
		return new MetadataController(settings);
	}

	@Bean
	@ConditionalOnProperty(prefix = "mcp.authorization-server.dcr", name = "enabled", havingValue = "true")
	RegistrationController mcpRegistrationController(DynamicClientRegistration registration) {
		return new RegistrationController(registration);
	}

	@Bean
	@ConditionalOnMissingBean
	McpOpaqueTokenIntrospector mcpOpaqueTokenIntrospector(GrantStore grants, McpServerSettings settings,
			McpPrincipalResolver principals, ScopePolicy scopePolicy, ObjectProvider<Clock> clock) {
		return new McpOpaqueTokenIntrospector(grants, settings, principals, scopePolicy, clock(clock));
	}

	@Bean
	@ConditionalOnMissingBean
	McpBearerEntryPoint mcpBearerEntryPoint(McpServerSettings settings) {
		return new McpBearerEntryPoint(settings);
	}

	@Bean
	@ConditionalOnMissingBean
	McpBearerAccessDeniedHandler mcpBearerAccessDeniedHandler(McpServerSettings settings) {
		return new McpBearerAccessDeniedHandler(settings);
	}

	@Bean
	@ConditionalOnProperty(prefix = "mcp.authorization-server.maintenance", name = "enabled", havingValue = "true",
			matchIfMissing = true)
	McpStoreMaintenance mcpStoreMaintenance(AuthorizationStateStore state, GrantStore grants,
			ObjectProvider<Clock> clock, McpAuthorizationServerProperties p) {
		return new McpStoreMaintenance(state, grants, clock(clock), p.getMaintenance().getInterval());
	}

	static Clock clock(ObjectProvider<Clock> clock) {
		return clock.getIfAvailable(Clock::systemUTC);
	}

	/** In-memory stores: the default, for a single instance. */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = "mcp.authorization-server", name = "store", havingValue = "memory",
			matchIfMissing = true)
	static class MemoryStores {

		MemoryStores() {
			logger.info("MCP authorization server uses in-memory stores: grants are lost on restart and "
					+ "the server must run as a single instance (set mcp.authorization-server.store=jdbc otherwise)");
		}

		@Bean
		@ConditionalOnMissingBean
		ClientStore mcpClientStore() {
			return new InMemoryClientStore();
		}

		@Bean
		@ConditionalOnMissingBean
		AuthorizationStateStore mcpAuthorizationStateStore() {
			return new InMemoryAuthorizationStateStore();
		}

		@Bean
		@ConditionalOnMissingBean
		GrantStore mcpGrantStore() {
			return new InMemoryGrantStore();
		}

	}

	/** JDBC stores on the application's DataSource (schema-postgresql.sql). */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnClass(JdbcTemplate.class)
	@ConditionalOnProperty(prefix = "mcp.authorization-server", name = "store", havingValue = "jdbc")
	static class JdbcStores {

		@Bean
		@ConditionalOnMissingBean
		ClientStore mcpClientStore(JdbcTemplate jdbc, ObjectProvider<Clock> clock) {
			return new JdbcClientStore(jdbc, clock(clock));
		}

		@Bean
		@ConditionalOnMissingBean
		AuthorizationStateStore mcpAuthorizationStateStore(JdbcTemplate jdbc, PlatformTransactionManager tm) {
			return new JdbcAuthorizationStateStore(jdbc, new TransactionTemplate(tm));
		}

		@Bean
		@ConditionalOnMissingBean
		GrantStore mcpGrantStore(JdbcTemplate jdbc, PlatformTransactionManager tm) {
			return new JdbcGrantStore(jdbc, new TransactionTemplate(tm));
		}

	}

}
