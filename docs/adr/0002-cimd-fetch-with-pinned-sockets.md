# ADR-0002: Fetch Client ID Metadata Documents over a socket pinned to the validated address

- Status: accepted (v0.1)

## Context

With CIMD the `client_id` is an HTTPS URL that the authorization server downloads. The URL is chosen
by whoever calls the public `/oauth2/authorize` endpoint, so the fetch is server-side request forgery
by construction. The CIMD draft (-03 §10.7) requires that special-use addresses (RFC 6890) are never
fetched.

The usual guard (resolve the host, check the addresses, then let an HTTP client connect) has three
known gaps:

1. **DNS rebinding.** The HTTP client resolves the name a second time. A hostile resolver can answer
   with a public address to the check and a private one to the connection.
2. **Time.** The JDK `HttpClient` request timeout stops at the response headers. A body read through
   `BodyHandlers.ofInputStream()` has no deadline. A test with a 1 s timeout and a body trickled one
   byte every 0.5 s took 10 s.
3. **IPv6.** The JDK predicates (`isSiteLocalAddress`, `isLoopbackAddress`, …) do not look at IPv4
   embedded in IPv6: NAT64 `64:ff9b::/96`, local-use NAT64 `64:ff9b:1::/48`, 6to4 `2002::/16`,
   IPv4-compatible `::a.b.c.d`, IPv4-translated `::ffff:0:a.b.c.d`, Teredo `2001::/32`. Whether those
   reach internal hosts depends on the deployment network. A library cannot assume it.

A process-wide `InetAddressResolverProvider` that serves pinned answers solves (1). But a library
must not install a JVM-wide resolver: it changes name resolution for the whole application and only
one provider can be active.

## Decision

`MetadataDocumentFetcher` speaks a deliberately small HTTP/1.1 subset over a socket that it opens
itself:

1. Validate the URL: `https`, a host, a path other than `/`, no fragment, no user info, no dot
   segments, length at most 2048, and the port in the allow list (default 443).
2. Resolve the host **once**. Reject unless **every** address passes `AddressPolicy`.
   - IPv4: global unicast only.
   - IPv6: only `2000::/3` minus the special-use blocks.
   - Embedded IPv4 (mapped, NAT64 `/96`, 6to4) is judged as the IPv4 it carries.
   - IPv4-compatible, IPv4-translated, local-use NAT64 and Teredo are rejected outright.
3. Connect to the validated `InetAddress` itself. The TLS layer gets the original host name for SNI
   and for RFC 2818 host name verification (`endpointIdentificationAlgorithm=HTTPS`).
4. Send `GET` with `Connection: close`. Read with one **total deadline**: the socket timeout is set
   to the remaining time before every read.
   - Header block: 8 KiB at most.
   - Status must be 200. No redirect is ever followed.
   - Media type must be `application/json` or `+json`.
   - Body up to `max-document-bytes` (default 5 KiB), whether framed by `Content-Length`, chunked or
     by connection close.
5. Bound the work:
   - a global semaphore on concurrent fetches;
   - a per-host fetch budget per minute;
   - an LRU cache honouring `Cache-Control: max-age` within `[cache-min, cache-max]`;
   - errors are never cached.

## Consequences

- No new dependency and no global state. Validation and connection use the same resolution, so
  rebinding is closed by construction. Tests check it with a resolver that changes its answer.
- We maintain a small HTTP response parser. It reads exactly one response from a server we do not
  trust, so its job is to bound and reject, not to be complete. HTTP/2, proxies and compression are
  not supported. An outbound proxy is a v0.2 item.
- A deployment that needs CIMD from private hosts (an intranet client) cannot do it in v0.1. That is
  intended.
