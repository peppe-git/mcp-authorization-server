# mcp-authorization-server

A Spring Boot starter that puts an **OAuth 2.1 authorization server** in front of a **remote MCP
server**. It follows the MCP Authorization specification, revision 2026-07-28.

> **Status: 0.1.0-SNAPSHOT, experimental.** Not released, not externally reviewed. The API may change.

## What it solves

A remote MCP server must expose its own OAuth authorization server. Spring gives you the pieces, but
not this profile. The starter adds:

- **Discovery.**
  - A 401 with `WWW-Authenticate: Bearer resource_metadata=…, scope=…`.
  - Protected resource metadata (RFC 9728) and authorization server metadata (RFC 8414).
- **Authorization code with PKCE `S256` only**, for public clients.
  - `iss` in the response (RFC 9207).
  - `resource` bound to the grant (RFC 8707).
  - Loopback redirects (`localhost`, `127.0.0.1`, `[::1]`) with any port; everything else matches
    exactly.
- **Client ID Metadata Documents**, fetched without turning your server into an SSRF proxy:
  - one DNS resolution, then a connection to the validated address;
  - IPv4 embedded in IPv6 blocked (NAT64, 6to4, mapped, compatible);
  - no redirects followed;
  - one total deadline, 5 KiB body, port 443 only.
- **Refresh tokens rotated on every use, with reuse detection** that revokes the whole grant. A
  30-second sibling grace keeps concurrent refreshes from logging users out.
- **Opaque tokens stored only as SHA-256 hashes**, checked in-process: a revocation applies on the
  next request.
- A consent page that shows what the user must know:
  - who the client is, and whether that is verified;
  - where the browser goes next;
  - a warning for `localhost`;
  - which scopes are granted.
- **SPIs** for the consent page, principal resolution, scope policy, storage (in memory, JDBC) and
  audit events.

The MCP protocol itself (JSON-RPC, tools) stays out: use the MCP Java SDK or Spring AI MCP on the
protected path.

## Quickstart

```xml
<dependency>
    <groupId>io.github.peppe-git</groupId>
    <artifactId>mcp-authorization-server-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```yaml
mcp:
  authorization-server:
    issuer: https://mcp.example.com
    resource: https://mcp.example.com/mcp
    scopes:
      - name: tools.read
        description: See your projects
        default-scope: true
```

Your application keeps its own login. The consent page uses the signed-in user. Requests to `/mcp`
now need a token. Full walkthrough: [Put OAuth in front of your MCP server in 10 minutes](docs/guides/quickstart.md).
A runnable example lives in [`samples/sample-mcp-server`](samples/sample-mcp-server).

## Guarantees

With the default configuration, each of these is covered by a negative test. `scripts/mutation-check.sh`
removes each rule in turn and checks that its test fails.

- **PKCE.** A code is issued only for an `S256` challenge, and redeemed only once, with the matching
  verifier, by the same client, at the same redirect URI. A wrong verifier burns the code.
- **Redirects.** A redirect URI that is not registered for the client is never followed. Errors before
  the client is verified go to an error page.
- **Consent.** It needs a signed-in user, a CSRF token and the same browser session that started the
  request.
- **Refresh.** A refresh token works once. A rotated one presented outside the grace window revokes
  every token of the grant.
- **Access.** An access token works only on the MCP paths, only for the configured resource, only while:
  - its pair is active;
  - its grant is not revoked;
  - `McpPrincipalResolver.isActive` holds.
- **Storage.** Tokens and codes are stored only as SHA-256 hashes.
- **Metadata documents** are never fetched from:
  - a non-global address, including IPv4 embedded in IPv6;
  - a second DNS answer;
  - a redirect target.

  A fetch never runs longer than its deadline, and never reads more than its size limit.

## What is not guaranteed

- **No rate limiting.** `/oauth2/authorize` (which can trigger a metadata fetch), `/oauth2/token` and
  `/oauth2/register` are public. Put a rate limiter in front of them. The right key depends on your
  proxy setup, which the starter cannot know.
- **No protection for your login.** Session security, MFA and password policies are the application's.
- **Not an OpenID Connect provider.** No ID tokens, no JWT access tokens, no confidential clients, no
  client credentials, no device flow, no PAR, no DPoP.
- **One protected resource per server.**
- **Servlet stack (Spring MVC) only.** No WebFlux.
- **No egress proxy for metadata fetches.** A network that only reaches the internet through an HTTP
  proxy cannot use metadata-document clients in v0.1.
- **The in-memory store is single-instance.** With more instances, use `store: jdbc`.
- **A replayed authorization code is refused, but the grant from its first use is not revoked** (planned
  for v0.2).
- **The 30-second sibling grace** lets someone who stole a refresh token use it within that window
  without triggering revocation. You can set it to 0.
- **Spring Boot 4.1+ and Java 17+ only.**
- **No external security review yet.**

The threat model ([docs/threat-model.md](docs/threat-model.md)) lists every threat, its mitigation and
its test, and the residual risks.

## Compared with the alternatives

| | This starter | Spring Authorization Server (in Spring Security 7) | `spring-ai-community/mcp-security` (authorization server module) |
|---|---|---|---|
| Scope | MCP profile only: public clients, code + PKCE | general-purpose OAuth 2.1 and OpenID Connect | MCP extensions on top of Spring Authorization Server |
| Refresh tokens for public clients | yes, rotated | not built in | not yet |
| Reuse detection revoking the grant | yes, with concurrency grace | no | no |
| Client ID Metadata Documents | yes, SSRF-hardened (pinned address, IPv6-embedded IPv4, deadline, size) | no | yes, opt-in, without private-address blocking |
| RFC 8707 `resource` / RFC 9207 `iss` | yes / yes | no / no | `resource` copied to the audience / no |
| Tokens at rest | SHA-256 hashes | values in clear (JDBC schema) | as Spring Authorization Server |
| Dynamic registration | opt-in (deprecated by MCP) | opt-in (7.0+) | on by default |
| Maturity | experimental, small | mature, widely used | experimental |

Pick **Spring Authorization Server** for a general OAuth or OpenID Connect provider. Pick this starter
when you only need what an MCP server needs and want the token lifecycle and the metadata fetch locked
down. Why the starter is not built on Spring Authorization Server: [ADR-0001](docs/adr/0001-standalone-authorization-server.md).

## Documentation

- [Concepts](docs/concepts.md): how the flow, clients, tokens and SPIs fit together.
- [Quickstart guide](docs/guides/quickstart.md).
- [Configuration reference](docs/configuration.md), including the JDBC schema.
- [Threat model](docs/threat-model.md).
- Architecture decisions:
  - [ADR-0001](docs/adr/0001-standalone-authorization-server.md): standalone, not on Spring Authorization Server;
  - [ADR-0002](docs/adr/0002-cimd-fetch-with-pinned-sockets.md): metadata fetch over a pinned socket;
  - [ADR-0003](docs/adr/0003-dynamic-client-registration-off-by-default.md): dynamic registration off by default;
  - [ADR-0004](docs/adr/0004-opaque-hashed-tokens-and-rotation-families.md): hashed opaque tokens and rotation families;
  - [ADR-0005](docs/adr/0005-spring-boot-4-and-java-17.md): Spring Boot 4.1 and Java 17.

## Building

```bash
./mvnw verify                # needs Docker for the PostgreSQL tests (Testcontainers)
./scripts/scrub-check.sh
./scripts/mutation-check.sh  # every security rule is guarded by a failing test
```

## Security and contributing

- Report vulnerabilities privately: [SECURITY.md](SECURITY.md).
- Contributions: [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Releases: [RELEASING.md](RELEASING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
