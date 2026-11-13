# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Spring Boot 4.1 starter that adds an OAuth 2.1 authorization server in front of a remote MCP server.
- Authorization code flow for public clients, with PKCE `S256` only, `iss` in the authorization
  response (RFC 9207) and `resource` bound to the grant (RFC 8707).
- Client ID Metadata Documents, fetched over a socket pinned to the validated address. IPv4 embedded in
  IPv6 is blocked, and size, time and redirect limits apply.
- Refresh-token rotation with families. A sibling grace covers concurrent refreshes, an optional
  lost-response grace covers lost replies, and reuse detection revokes the whole grant.
- Opaque tokens, stored only as SHA-256 hashes. In-memory and JDBC (PostgreSQL) stores.
- Discovery documents (RFC 8414, RFC 9728) and an MCP-shaped `WWW-Authenticate` challenge.
- Optional RFC 7591 dynamic registration, off by default.
- Service provider interfaces for the consent page, principal resolution, scope policy and storage.
  Audit events are published as Spring events.
