# ADR-0001: A minimal authorization server on Spring Security primitives, not on Spring Authorization Server

- Status: accepted (v0.1)
- Context date: November 2026. Spring Security 7.1.2, MCP revision 2026-07-28.

## Context

A remote MCP server must expose an OAuth 2.1 authorization server with a narrow, MCP-specific
profile:

- public clients only, authorization code with PKCE `S256`;
- Client ID Metadata Documents (CIMD) as the primary client identification;
- refresh tokens for public clients, rotated on every use (the MCP spec says MUST);
- RFC 8707 `resource` bound to the grant, RFC 9207 `iss` in the authorization response;
- `localhost` redirect URIs with any port (native and CLI clients).

Two options were evaluated:

- **(a)** build on Spring Authorization Server (SAS), now shipped in Spring Security 7 as
  `spring-security-oauth2-authorization-server`, and add the MCP-specific parts;
- **(b)** build a minimal standalone server that still reuses the stable, public parts of Spring
  Security.

Option (a) was the preferred default, because it means less security code of our own.

## What SAS 7.1.2 covers and what it does not (verified in its sources)

| Need | SAS 7.1.2 |
|---|---|
| Authorization code + PKCE `S256` only, `plain` rejected | yes |
| Refresh token issued to a public client | issued at code exchange, but `PublicClientAuthenticationConverter` only matches `authorization_code` requests carrying `code_verifier`, so a public client cannot authenticate a `refresh_token` request. A custom converter and provider are needed (upstream: "no built-in support") |
| Rotation with reuse detection that revokes the grant (RFC 9700 §4.14.2) | no. A replayed rotated token just finds no authorization. Rotation in `OAuth2RefreshTokenAuthenticationProvider` is a read-modify-write with no lock, so two concurrent refreshes race and the last writer wins |
| Tolerance for concurrent refreshes of the same client | no. One `OAuth2Authorization` holds exactly one refresh token |
| Tokens hashed at rest | no. `oauth2-authorization-schema.sql` stores `access_token_value` and `refresh_token_value` in clear |
| `localhost` redirect with any port | no. Only loopback IP literals get the free port, and `localhost` must match exactly |
| RFC 8707 resource indicators | no (declined upstream) |
| RFC 9207 `iss` in the authorization response | no (open issue) |
| CIMD | no ("no immediate plans" upstream; the work is happening in `mcp-security`) |
| RFC 9728 protected resource metadata | yes, in the resource-server module (7.0+) |

To make (a) work we would have to replace:

- the refresh-token half of the token endpoint (client authentication, rotation, families, lock);
- `OAuth2AuthorizationService`, to hash tokens and to lock a family;
- the redirect validator;
- the authorization response handler (for `iss`);
- the request validation (for `resource`).

We would also have to add CIMD through the client repository and the authorization request
converter. The result would be a layer that depends on SAS internals in about ten places, some of
them final classes and package-private utilities, and it would keep two models of one grant (SAS's
`OAuth2Authorization` with serialized principals, and our token family). Every Spring Security minor
release could change those internals silently.

`spring-ai-community/mcp-security` already follows path (a). It adds CIMD, open registration and a
localhost port validator on top of SAS. It is experimental and leaves out exactly the parts above:
public-client refresh, reuse detection, SSRF-hardened fetching.

## Decision

Option **(b)**: a small, closed authorization server owned by this project. It reuses only stable,
public Spring Security building blocks:

- the application's own login (session `SecurityContext`) to know who is approving;
- `CsrfFilter` for the consent form, and the default security headers (`X-Frame-Options: DENY`);
- the resource server with an in-process `OpaqueTokenIntrospector` for the MCP endpoint.

The protocol surface is deliberately narrow:

- no confidential clients;
- no implicit grant, no password grant, no client credentials;
- no JWT, no OpenID Connect;
- one protected resource per server.

## Consequences

- The authorize, consent and token code paths are ours. This is the main risk. It is covered by:
  - one negative test per rule (`NegativeRulesTest`, `MetadataDocumentFetcherTest`), each seen failing when its rule is removed (`scripts/mutation-check.sh`);
  - a STRIDE threat model (`docs/threat-model.md`);
  - an external review before 1.0.
- Rotation, families and reuse detection come from code that already ran in production. They were
  rewritten without the multi-tenant coupling and are tested against both the in-memory and the
  PostgreSQL store with the same contract.
- Applications whose login does not create a server-side `SecurityContext` (single-page apps with
  tokens only) need a bridge for the consent step. The same is true for SAS.
- If SAS gains public-client refresh with reuse detection, CIMD and RFC 8707, revisit this decision.
  Moving to (a) would then mean deleting code, not adding it.
