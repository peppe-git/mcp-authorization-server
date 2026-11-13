# Configuration reference

All properties live under `mcp.authorization-server`. The application fails to start on unsafe values:

- a missing or non-HTTPS issuer or resource (HTTP is allowed only on `localhost`);
- an invalid scope name;
- a code lifetime over 10 minutes;
- a malformed redirect URI.

## Core

| Property | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Turns the starter off entirely. |
| `issuer` | required | Issuer identifier (RFC 8414): the public origin, e.g. `https://mcp.example.com`. Endpoint URLs in the metadata are `issuer` + path. Prefer an origin without a path: clients look for metadata at `/.well-known/oauth-authorization-server{issuer-path}`, which an application under a context path cannot serve by itself. |
| `resource` | required | Identifier of the protected MCP resource (RFC 8707, RFC 9728), e.g. `https://mcp.example.com/mcp`. Every token is bound to it. |
| `resource-name` | none | Human-readable name in the protected resource metadata. |
| `login-page` | `/login` | Where an unauthenticated user is sent before the consent page. |
| `allowed-redirect-uris` | empty | Optional server-wide allow list. When set, a redirect URI must match the client's registration **and** this list (exact match, any port for loopback). |
| `store` | `memory` | `memory` (single instance, lost on restart) or `jdbc`. |

## Scopes

```yaml
scopes:
  - name: tools.read          # RFC 6749 scope token
    description: Read your data   # shown on the consent page
    default-scope: true       # granted when the client asks for no scope
```

- When no scope is marked default, all of them are the default.
- `offline_access` is always accepted and advertised. It is not stored, because refresh tokens are
  always issued.
- An unknown scope is refused with `invalid_scope`.

## Pre-registered clients

```yaml
clients:
  - client-id: my-cli                       # must not start with https://
    client-name: My CLI
    redirect-uris: [http://127.0.0.1/callback, https://app.example/callback]
```

## Tokens

| Property | Default | Meaning |
|---|---|---|
| `tokens.access-token-ttl` | `1h` | Access token lifetime. |
| `tokens.refresh-token-ttl` | `30d` | Refresh token lifetime. It is sliding: each rotation issues a new one. |
| `tokens.authorization-request-ttl` | `10m` | How long the consent page waits. |
| `tokens.authorization-code-ttl` | `60s` | Code lifetime, at most `10m`. |
| `tokens.refresh-reuse-grace` | `30s` | A rotated refresh token replayed within this window yields a sibling pair (concurrent refreshes). `0` makes every replay a reuse. |
| `tokens.refresh-lost-response-grace` | `0` | When greater than 0, the immediate predecessor of the latest rotation, replayed within this window with its successors never used, supersedes them once. This recovers a response lost in transit. |

## Client ID Metadata Documents

| Property | Default | Meaning |
|---|---|---|
| `cimd.enabled` | `true` | Accept `https://` client identifiers and advertise `client_id_metadata_document_supported`. |
| `cimd.max-document-bytes` | `5120` | Maximum body size (CIMD draft recommends 5 KB). Range 256 to 65536. |
| `cimd.timeout` | `5s` | One deadline for resolution, connection, TLS, request and body. |
| `cimd.allowed-ports` | `[443]` | Ports a client identifier URL may use. |
| `cimd.allowed-hosts` | empty | When set, only client identifiers on these hosts are accepted. |
| `cimd.cache-min` / `cache-max` / `cache-default` | `1m` / `24h` / `10m` | Caching of valid documents: `Cache-Control: max-age`, clamped to `[min, max]`; `cache-default` without a header. Errors are never cached. |
| `cimd.max-cache-entries` | `1000` | Size of the LRU cache. |
| `cimd.max-concurrent-fetches` | `4` | Fetches running at once; extra requests are refused, not queued. |
| `cimd.max-fetches-per-host-per-minute` | `10` | Per-host budget. |

The fetcher connects directly, without a proxy. A deployment whose egress goes through an HTTP proxy
cannot fetch metadata documents in v0.1.

## Dynamic Client Registration

| Property | Default | Meaning |
|---|---|---|
| `dcr.enabled` | `false` | Open `POST /oauth2/register` (RFC 7591) and advertise it. Deprecated by MCP. Put a rate limit in front of it. |
| `dcr.max-redirect-uris` | `10` | Maximum redirect URIs per client (1 to 20). |

## Resource server

| Property | Default | Meaning |
|---|---|---|
| `resource-server.enabled` | `true` | Register the security filter chain that requires a token on the MCP path. Turn it off to use `McpResourceServer.apply(http, …)` in your own chain. |
| `resource-server.path-patterns` | `[/mcp, /mcp/**]` | Paths of the MCP endpoint. |

## Maintenance

| Property | Default | Meaning |
|---|---|---|
| `maintenance.enabled` | `true` | Purge expired requests, codes and token pairs on a daemon thread. |
| `maintenance.interval` | `1h` | Interval between purges. |

## Endpoints

These paths are fixed in v0.1:

| Path | Purpose |
|---|---|
| `GET /oauth2/authorize` | Authorization endpoint. |
| `GET, POST /oauth2/consent` | Consent page and decision (signed-in user, CSRF). |
| `POST /oauth2/token` | Token endpoint (`authorization_code`, `refresh_token`). |
| `POST /oauth2/revoke` | Revocation (RFC 7009). |
| `POST /oauth2/register` | Dynamic registration (only when enabled). |
| `GET /.well-known/oauth-authorization-server[/{issuer-path}]` | RFC 8414 metadata. |
| `GET /.well-known/oauth-protected-resource[/{resource-path}]` | RFC 9728 metadata. |

## Security filter chains

| Bean | Order | Matches | Rules |
|---|---|---|---|
| `mcpAuthorizationServerSecurityFilterChain` | highest + 10 | the endpoints above | consent needs a signed-in user; CSRF only on the consent form |
| `mcpResourceServerSecurityFilterChain` | highest + 20 | `resource-server.path-patterns` | a valid access token; stateless |
| `mcpFallbackSecurityFilterChain` | lowest − 10 | everything else | only when the application defines no chain of its own: authenticated, form login, HTTP Basic |

## JDBC schema

`classpath:io/github/peppe_git/mcpauthserver/store/schema-postgresql.sql` creates five tables:

| Table | Content |
|---|---|
| `mcp_oauth_client` | dynamically registered clients |
| `mcp_oauth_authorization_request` | pending requests, minutes |
| `mcp_oauth_authorization_code` | codes, by hash, seconds |
| `mcp_oauth_grant` | one row per consent, with its revocation |
| `mcp_oauth_token` | one row per issued pair: hashes, status `ACTIVE`/`ROTATED`/`SUPERSEDED`, expiries |

The starter never runs DDL: apply the file with your migration tool. It is tested on PostgreSQL 17.
Other databases need `TIMESTAMP WITH TIME ZONE` and `SELECT … FOR UPDATE`. Tokens and codes are
stored only as hex SHA-256.

## Beans you can replace

Each of these backs off when you define your own:

- `McpPrincipalResolver`
- `ScopePolicy`
- `ConsentPageRenderer`
- `ClientStore`, `AuthorizationStateStore`, `GrantStore`
- `MetadataDocumentFetcher`
- `GrantManagement`
- `McpOpaqueTokenIntrospector`
- `McpBearerEntryPoint`, `McpBearerAccessDeniedHandler`
