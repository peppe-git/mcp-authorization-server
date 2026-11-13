# Concepts

This page explains what the starter does, in the order an MCP client experiences it.

## The two roles in one application

The MCP specification separates two roles:

- the **resource server**: your MCP endpoint, for example `/mcp`;
- the **authorization server**: it authenticates the user, asks for consent and issues tokens.

This starter runs both in your Spring Boot application:

- it serves the OAuth endpoints under `/oauth2/*` and the discovery documents under `/.well-known/*`;
- it protects the MCP path with Spring Security's resource server, checking each access token
  in-process against its own store.

The MCP protocol itself (JSON-RPC, tools, resources) is not part of the starter. Use the MCP Java SDK,
Spring AI MCP or your own controller on the protected path.

## Discovery

1. The client calls the MCP endpoint without a token and gets
   `401 WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp", scope="…"`.
2. The **protected resource metadata** (RFC 9728) names the resource and its authorization server.
3. The **authorization server metadata** (RFC 8414) lists the endpoints and capabilities:
   - `S256` only;
   - `none` client authentication only;
   - `iss` in responses;
   - metadata-document clients.

Both documents are built from configuration, never from request headers.

## Clients

All clients are **public**: they cannot keep a secret, so PKCE protects the code. A client is
identified in one of three ways:

| Kind | `client_id` | Identity shown on the consent page |
|---|---|---|
| Pre-registered | any string from `mcp.authorization-server.clients` | "registered by the operator" |
| Client ID Metadata Document (CIMD) | an `https://` URL to a JSON document | "published by *domain*": the host of the URL is verified, because whoever controls it wrote the document |
| Dynamic registration (RFC 7591, off by default) | issued by `/oauth2/register` | "not verified": the name is self-asserted |

The MCP revision 2026-07-28 prefers pre-registration, then CIMD, and deprecates dynamic registration.

### Fetching a metadata document safely

A CIMD `client_id` is a URL chosen by whoever calls the public authorization endpoint. Downloading it
is server-side request forgery by construction. The fetcher therefore works like this
([ADR-0002](adr/0002-cimd-fetch-with-pinned-sockets.md)):

- **Resolve once.** It resolves the host once and requires every address to be global unicast.
  IPv4 embedded in IPv6 is judged as the IPv4 address it carries.
- **Connect to what was checked.** It connects to exactly the address it checked, so DNS rebinding has
  no second lookup to poison.
- **Verify TLS.** It verifies the TLS certificate against the host name.
- **No redirects.** It never follows a redirect.
- **Bound everything:**
  - one total deadline (default 5 s);
  - at most 5 KiB of body and 8 KiB of headers;
  - port 443 only;
  - limits on concurrent fetches and on fetches per host;
  - a cache that honours `Cache-Control` within bounds and never stores errors.

## The authorization step

1. **`GET /oauth2/authorize`** checks the request in this order:
   1. Client and redirect URI. If either fails, the browser sees an error page and is **never**
      redirected: that would be an open redirect.
   2. The other parameters: `response_type=code`, PKCE `S256`, scopes, `resource`. Errors from here on
      go back to the client with `state` and `iss`.
2. The validated request is stored for 10 minutes and **bound to the browser session** that opened it.
3. **`GET /oauth2/consent`** requires the user to be signed in, through your application's own login.
   It shows:
   - the client and how much its identity is verified;
   - the host of the redirect URI;
   - a warning when the redirect goes to `localhost`;
   - the scopes the user is about to grant.
4. **`POST /oauth2/consent`** (CSRF-protected) consumes the request. On approval it mints a 60-second,
   single-use code and redirects with `303 See Other`.

Redirect URIs match exactly, character for character. The only exception is loopback URIs
(`localhost`, `127.0.0.1`, `[::1]`), where the port is free: native clients pick a port at run time
(RFC 8252 §7.3).

## Tokens

**`POST /oauth2/token`** exchanges the code for tokens.

- The code is consumed **before** any check, so a wrong verifier burns it.
- `client_id`, `redirect_uri` and the PKCE verifier must match.
- `resource`, if sent, must match.

Tokens are opaque: 256 random bits with a recognisable prefix (`mcp_at_`, `mcp_rt_`). Only their
SHA-256 hash is stored. The access token lasts 1 hour, the refresh token 30 days.

### Rotation, families and reuse detection

Every refresh rotates the refresh token. The user's consent for one client is a **grant**, and the
grant owns a **family** of token pairs ([ADR-0004](adr/0004-opaque-hashed-tokens-and-rotation-families.md)).
What happens when a refresh token is presented:

| The presented refresh token is… | Result |
|---|---|
| the active one | rotated; the old access token stops working |
| rotated less than 30 s ago, while the family is alive | a **sibling** pair: two concurrent refreshes both succeed |
| the last one rotated, within the optional lost-response window, with successors never used | the successors are superseded and a new pair is issued, once |
| anything else | **reuse**: the whole grant is revoked and `RefreshTokenReuseDetected` is published |

Rotations of one grant are serialised by a lock on the grant (`SELECT … FOR UPDATE` in JDBC).

## The MCP request

The resource-server chain checks the bearer token in-process. The token is accepted only if all of
these hold:

- its pair is active and not expired;
- its grant is not revoked;
- its audience is the configured resource;
- `McpPrincipalResolver.isActive(subject)` is true.

The authenticated principal exposes `sub`, `client_id`, `scope`, `aud`, `iat`, `exp` and `grant_id`.
Scopes become `SCOPE_*` authorities. A revocation takes effect on the next request.

## Extension points

| SPI | Default | Typical replacement |
|---|---|---|
| `McpPrincipalResolver` | `Authentication.getName()`, always active | a stable user id, and `isActive` reading your user store |
| `ScopePolicy` | grant what is requested, `SCOPE_x` authorities | narrow scopes per role |
| `ConsentPageRenderer` | a plain, self-contained HTML page | your branded page (keep the CSRF field and the shown facts) |
| `ClientStore`, `AuthorizationStateStore`, `GrantStore` | in memory | JDBC (`store: jdbc`), or your own |
| audit events | none | `@EventListener` on `McpAuthorizationEvent` |

`GrantManagement` is the API for a "connected apps" page:

- `activeGrants(subject)` lists the grants;
- `revoke(subject, grantId)` disconnects one;
- `revokeAll(subject)` disconnects everything, for account recovery.
