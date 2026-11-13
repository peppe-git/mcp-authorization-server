# ADR-0003: Dynamic Client Registration is off by default

- Status: accepted (v0.1)

## Context

The MCP revision 2026-07-28 lists clients in order of preference: pre-registered, CIMD, then RFC 7591
Dynamic Client Registration. DCR is marked as deprecated, with removal no earlier than the first
revision released after July 2027.

Open registration is an unauthenticated write into the authorization server's storage. Its client
name is self-asserted, so the consent page cannot show a verified identity for it.

## Decision

- `mcp.authorization-server.dcr.enabled` defaults to `false`. When it is off:
  - `registration_endpoint` is absent from the metadata;
  - `POST /oauth2/register` answers 404.
- When it is on:
  - only public clients are accepted (`token_endpoint_auth_method` absent or `none`);
  - grant and response types are limited to the authorization code flow;
  - 1 to 10 redirect URIs, each HTTPS or loopback HTTP, and each allowed by `allowed-redirect-uris`
    when that list is set;
  - the client name is sanitized and shown as unverified on the consent page.

## Consequences

Older MCP clients that only implement DCR need the flag turned on, and they need a rate limit in
front of `/oauth2/register`. The README says so explicitly.
