// SPDX-License-Identifier: Apache-2.0
package io.github.peppe_git.mcpauthserver.autoconfigure;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration of the MCP authorization server ({@code mcp.authorization-server.*}). */
@ConfigurationProperties("mcp.authorization-server")
public class McpAuthorizationServerProperties {

	/** Whether the starter is active. */
	private boolean enabled = true;

	/** Issuer identifier (RFC 8414): the public origin of this server, e.g. https://mcp.example.com. Required. */
	private String issuer;

	/** Identifier of the protected MCP resource (RFC 8707/9728), e.g. https://mcp.example.com/mcp. Required. */
	private String resource;

	/** Human-readable name of the resource, published in the protected resource metadata. */
	private String resourceName;

	/** Path of the application's login page, where unauthenticated users are sent before consent. */
	private String loginPage = "/login";

	/** The scopes the server grants, in display order. */
	private List<Scope> scopes = new ArrayList<>();

	/** Optional server-wide allow list of redirect URIs (exact match, any port for loopback). */
	private List<String> allowedRedirectUris = new ArrayList<>();

	/** Public clients registered by the operator. */
	private List<Client> clients = new ArrayList<>();

	private Tokens tokens = new Tokens();

	private Cimd cimd = new Cimd();

	private Dcr dcr = new Dcr();

	private ResourceServer resourceServer = new ResourceServer();

	/** Where clients, pending requests, codes and grants are stored. */
	private StoreType store = StoreType.MEMORY;

	private Maintenance maintenance = new Maintenance();

	/** Storage back end. */
	public enum StoreType {

		/** In memory: single instance only, lost on restart. */
		MEMORY,

		/** JDBC tables of schema-postgresql.sql, through the application's DataSource. */
		JDBC

	}

	/** A scope definition. */
	public static class Scope {

		/** Scope token, e.g. tools.read. */
		private String name;

		/** Text shown on the consent page. */
		private String description;

		/** Granted when a client asks for no scope. If no scope is marked default, all are. */
		private boolean defaultScope;

		public String getName() {
			return this.name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getDescription() {
			return this.description;
		}

		public void setDescription(String description) {
			this.description = description;
		}

		public boolean isDefaultScope() {
			return this.defaultScope;
		}

		public void setDefaultScope(boolean defaultScope) {
			this.defaultScope = defaultScope;
		}

	}

	/** A pre-registered public client. */
	public static class Client {

		/** Client identifier; must not start with https:// (those are metadata documents). */
		private String clientId;

		/** Name shown on the consent page. */
		private String clientName;

		/** Registered redirect URIs: https, or loopback http (any port). */
		private List<String> redirectUris = new ArrayList<>();

		public String getClientId() {
			return this.clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getClientName() {
			return this.clientName;
		}

		public void setClientName(String clientName) {
			this.clientName = clientName;
		}

		public List<String> getRedirectUris() {
			return this.redirectUris;
		}

		public void setRedirectUris(List<String> redirectUris) {
			this.redirectUris = redirectUris;
		}

	}

	/** Lifetimes and rotation grace windows. */
	public static class Tokens {

		/** Access token lifetime. */
		private Duration accessTokenTtl = Duration.ofHours(1);

		/** Refresh token lifetime; every rotation issues a new one. */
		private Duration refreshTokenTtl = Duration.ofDays(30);

		/** How long a pending authorization request waits for the user. */
		private Duration authorizationRequestTtl = Duration.ofMinutes(10);

		/** How long an authorization code may wait before the exchange (at most 10 minutes). */
		private Duration authorizationCodeTtl = Duration.ofSeconds(60);

		/** A rotated refresh token replayed within this window yields a sibling pair (concurrent refreshes). */
		private Duration refreshReuseGrace = Duration.ofSeconds(30);

		/** Lost-response recovery window for the immediate predecessor; zero disables it. */
		private Duration refreshLostResponseGrace = Duration.ZERO;

		public Duration getAccessTokenTtl() {
			return this.accessTokenTtl;
		}

		public void setAccessTokenTtl(Duration accessTokenTtl) {
			this.accessTokenTtl = accessTokenTtl;
		}

		public Duration getRefreshTokenTtl() {
			return this.refreshTokenTtl;
		}

		public void setRefreshTokenTtl(Duration refreshTokenTtl) {
			this.refreshTokenTtl = refreshTokenTtl;
		}

		public Duration getAuthorizationRequestTtl() {
			return this.authorizationRequestTtl;
		}

		public void setAuthorizationRequestTtl(Duration authorizationRequestTtl) {
			this.authorizationRequestTtl = authorizationRequestTtl;
		}

		public Duration getAuthorizationCodeTtl() {
			return this.authorizationCodeTtl;
		}

		public void setAuthorizationCodeTtl(Duration authorizationCodeTtl) {
			this.authorizationCodeTtl = authorizationCodeTtl;
		}

		public Duration getRefreshReuseGrace() {
			return this.refreshReuseGrace;
		}

		public void setRefreshReuseGrace(Duration refreshReuseGrace) {
			this.refreshReuseGrace = refreshReuseGrace;
		}

		public Duration getRefreshLostResponseGrace() {
			return this.refreshLostResponseGrace;
		}

		public void setRefreshLostResponseGrace(Duration refreshLostResponseGrace) {
			this.refreshLostResponseGrace = refreshLostResponseGrace;
		}

	}

	/** Client ID Metadata Documents. */
	public static class Cimd {

		/** Accept clients whose client_id is an https URL to a metadata document. */
		private boolean enabled = true;

		/** Maximum document size in bytes (CIMD draft recommends 5 KB; at most 65536). */
		private int maxDocumentBytes = 5 * 1024;

		/** Total deadline of one fetch: connect, TLS, request and body. */
		private Duration timeout = Duration.ofSeconds(5);

		/** Ports a client_id URL may use. */
		private List<Integer> allowedPorts = new ArrayList<>(List.of(443));

		/** If not empty, only client_id URLs on these hosts are accepted. */
		private List<String> allowedHosts = new ArrayList<>();

		/** Minimum caching time of a valid document, whatever its Cache-Control says. */
		private Duration cacheMin = Duration.ofMinutes(1);

		/** Maximum caching time of a valid document. */
		private Duration cacheMax = Duration.ofHours(24);

		/** Caching time when the response has no Cache-Control max-age. */
		private Duration cacheDefault = Duration.ofMinutes(10);

		/** Maximum number of cached documents. */
		private int maxCacheEntries = 1000;

		/** Maximum fetches running at the same time. */
		private int maxConcurrentFetches = 4;

		/** Maximum fetches per host per minute. */
		private int maxFetchesPerHostPerMinute = 10;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public int getMaxDocumentBytes() {
			return this.maxDocumentBytes;
		}

		public void setMaxDocumentBytes(int maxDocumentBytes) {
			this.maxDocumentBytes = maxDocumentBytes;
		}

		public Duration getTimeout() {
			return this.timeout;
		}

		public void setTimeout(Duration timeout) {
			this.timeout = timeout;
		}

		public List<Integer> getAllowedPorts() {
			return this.allowedPorts;
		}

		public void setAllowedPorts(List<Integer> allowedPorts) {
			this.allowedPorts = allowedPorts;
		}

		public List<String> getAllowedHosts() {
			return this.allowedHosts;
		}

		public void setAllowedHosts(List<String> allowedHosts) {
			this.allowedHosts = allowedHosts;
		}

		public Duration getCacheMin() {
			return this.cacheMin;
		}

		public void setCacheMin(Duration cacheMin) {
			this.cacheMin = cacheMin;
		}

		public Duration getCacheMax() {
			return this.cacheMax;
		}

		public void setCacheMax(Duration cacheMax) {
			this.cacheMax = cacheMax;
		}

		public Duration getCacheDefault() {
			return this.cacheDefault;
		}

		public void setCacheDefault(Duration cacheDefault) {
			this.cacheDefault = cacheDefault;
		}

		public int getMaxCacheEntries() {
			return this.maxCacheEntries;
		}

		public void setMaxCacheEntries(int maxCacheEntries) {
			this.maxCacheEntries = maxCacheEntries;
		}

		public int getMaxConcurrentFetches() {
			return this.maxConcurrentFetches;
		}

		public void setMaxConcurrentFetches(int maxConcurrentFetches) {
			this.maxConcurrentFetches = maxConcurrentFetches;
		}

		public int getMaxFetchesPerHostPerMinute() {
			return this.maxFetchesPerHostPerMinute;
		}

		public void setMaxFetchesPerHostPerMinute(int maxFetchesPerHostPerMinute) {
			this.maxFetchesPerHostPerMinute = maxFetchesPerHostPerMinute;
		}

	}

	/** RFC 7591 Dynamic Client Registration (deprecated by MCP; off by default). */
	public static class Dcr {

		/** Open the registration endpoint. Put a rate limit in front of it if you do. */
		private boolean enabled = false;

		/** Maximum redirect URIs per registered client. */
		private int maxRedirectUris = 10;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public int getMaxRedirectUris() {
			return this.maxRedirectUris;
		}

		public void setMaxRedirectUris(int maxRedirectUris) {
			this.maxRedirectUris = maxRedirectUris;
		}

	}

	/** The security filter chain protecting the MCP endpoint. */
	public static class ResourceServer {

		/** Register a filter chain that requires a valid access token on the paths below. */
		private boolean enabled = true;

		/** Paths of the MCP endpoint. */
		private List<String> pathPatterns = new ArrayList<>(List.of("/mcp", "/mcp/**"));

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public List<String> getPathPatterns() {
			return this.pathPatterns;
		}

		public void setPathPatterns(List<String> pathPatterns) {
			this.pathPatterns = pathPatterns;
		}

	}

	/** Periodic deletion of expired state. */
	public static class Maintenance {

		/** Run the purge job. */
		private boolean enabled = true;

		/** Interval between purges. */
		private Duration interval = Duration.ofHours(1);

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public Duration getInterval() {
			return this.interval;
		}

		public void setInterval(Duration interval) {
			this.interval = interval;
		}

	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getIssuer() {
		return this.issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getResource() {
		return this.resource;
	}

	public void setResource(String resource) {
		this.resource = resource;
	}

	public String getResourceName() {
		return this.resourceName;
	}

	public void setResourceName(String resourceName) {
		this.resourceName = resourceName;
	}

	public String getLoginPage() {
		return this.loginPage;
	}

	public void setLoginPage(String loginPage) {
		this.loginPage = loginPage;
	}

	public List<Scope> getScopes() {
		return this.scopes;
	}

	public void setScopes(List<Scope> scopes) {
		this.scopes = scopes;
	}

	public List<String> getAllowedRedirectUris() {
		return this.allowedRedirectUris;
	}

	public void setAllowedRedirectUris(List<String> allowedRedirectUris) {
		this.allowedRedirectUris = allowedRedirectUris;
	}

	public List<Client> getClients() {
		return this.clients;
	}

	public void setClients(List<Client> clients) {
		this.clients = clients;
	}

	public Tokens getTokens() {
		return this.tokens;
	}

	public void setTokens(Tokens tokens) {
		this.tokens = tokens;
	}

	public Cimd getCimd() {
		return this.cimd;
	}

	public void setCimd(Cimd cimd) {
		this.cimd = cimd;
	}

	public Dcr getDcr() {
		return this.dcr;
	}

	public void setDcr(Dcr dcr) {
		this.dcr = dcr;
	}

	public ResourceServer getResourceServer() {
		return this.resourceServer;
	}

	public void setResourceServer(ResourceServer resourceServer) {
		this.resourceServer = resourceServer;
	}

	public StoreType getStore() {
		return this.store;
	}

	public void setStore(StoreType store) {
		this.store = store;
	}

	public Maintenance getMaintenance() {
		return this.maintenance;
	}

	public void setMaintenance(Maintenance maintenance) {
		this.maintenance = maintenance;
	}

}
