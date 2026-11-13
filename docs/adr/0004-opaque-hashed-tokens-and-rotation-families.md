# ADR-0004: Opaque tokens hashed at rest, refresh rotation in families

- Status: accepted (v0.1)

## Context

The MCP server and the authorization server run in the same application, so the resource server can
check a token in-process. Revocation must take effect on the next request: a user who disconnects an
app, or a detected refresh replay, must cut access at once.

MCP requires refresh-token rotation for public clients. The OAuth security BCP (RFC 9700 §4.14.2)
recommends detecting the reuse of a rotated refresh token and revoking the whole grant.

Real clients refresh concurrently. Two tool calls see an expired access token at the same time and
both refresh with the same refresh token. With a single "current refresh token" per grant, one of the
two responses carries a token that is already superseded. When it is used later, it looks like reuse
and disconnects the user for no reason.

## Decision

- Tokens are 256 random bits in base64url, with the prefixes `mcp_at_` and `mcp_rt_` so that secret
  scanners can find them.
- Only the SHA-256 hash is stored. The codes of the authorization step are hashed the same way.
- A **grant** is the user's consent for one client. It owns a **family** of token pairs, one row per
  issued pair.
- Presenting a refresh token:
  - **active pair** → rotate it: mark it `rotated` and issue the next pair;
  - **rotated within `refresh.reuse-grace`** (default 30 s), while the family still has an active
    pair → issue a sibling pair, so concurrent refreshes all succeed;
  - **the immediate predecessor of the latest rotation, rotated within
    `refresh.lost-response-grace`** (default off), with successors never used → supersede those
    successors and issue a new pair. This recovers a response lost in transit. It works once;
  - **anything else** → reuse: revoke the grant (every pair) and publish
    `RefreshTokenReuseDetectedEvent`.
- Every rotation runs under a lock on the grant row (`SELECT … FOR UPDATE` in JDBC, a per-grant
  monitor in memory). Both stores share one decision function (`RotationRules`) and one contract test.
- An access token is valid only while:
  - its pair is active and not expired;
  - the grant is not revoked;
  - the audience matches the configured resource;
  - `McpPrincipalResolver.isActive(subject)` is true.
- Rotated rows are kept until their refresh expiry, so a late replay is still detected.

## Consequences

- No JWT and no signing keys to rotate. The trade-off is a store lookup on every MCP request.
- A thief who uses a stolen refresh token inside the 30 s window gets a sibling pair instead of
  triggering revocation. This is accepted and documented. Set the grace to 0 to remove it, at the cost
  of false positives on concurrent refreshes.
- Storage grows with one row per rotation per grant until the refresh expiry. The purge job deletes
  older rows.
