# Threat model

STRIDE analysis of the three surfaces of the starter:

1. the authorization flow (authorize, consent, code);
2. tokens and refresh;
3. the fetch of Client ID Metadata Documents (SSRF).

Each mitigation names the test that fails when it is removed. `scripts/mutation-check.sh` removes the
main ones one at a time and checks that their tests turn red.

## Assets

- **Access and refresh tokens:** they act as the user on the MCP server.
- **Authorization codes:** they can become tokens.
- **The user's consent:** which client may act, with which scopes.
- **The server's network position:** it can reach internal hosts the attacker cannot.
- **Availability** of the authorization and MCP endpoints.

## Actors and trust boundaries

| Actor | Trust |
|---|---|
| The user's browser, signed in to the application | trusted for the user's own decisions only |
| MCP clients (public, cannot keep secrets) | untrusted; identified by registration, by domain (CIMD), or not at all (DCR) |
| The host serving a metadata document | untrusted; it chooses the content, the DNS answers, the TLS timing |
| Network attacker | sees nothing inside TLS; may control DNS for their own domains |
| The application (login, user store) | trusted; it is outside this component |

## Assumptions

- TLS terminates in front of the application, and the `issuer` is its public HTTPS origin.
- The application's login is sound, and its session cookie is `HttpOnly` and `Secure`.
- With more than one instance, the JDBC store is used.
- The application rate-limits the public endpoints. The starter does not (see "Residual risks").

## 1. Authorization flow

| Threat | STRIDE | Mitigation | Test |
|---|---|---|---|
| Code interception or injection (malicious app on the device, leaked logs) | S, E | PKCE `S256` mandatory; `plain` and a missing method are refused; the verifier is checked in constant time | `NegativeRulesTest.missingPkceIsRefused`, `plainPkceIsRefused`, `aWrongVerifierBurnsTheCode`; `PkceTest` |
| Guessing the verifier for a stolen code | S | the code is consumed before any check, so one wrong verifier burns it; 60 s lifetime; 256-bit codes | `aWrongVerifierBurnsTheCode` |
| Replay of a code | S | atomic single-use take (memory: `remove`; JDBC: `DELETE` count) | `aCodeIsExchangedOnlyOnce`; `AuthorizationStateStoreContract.aCodeIsTakenOnceEvenUnderConcurrency` |
| Open redirect, or code sent to an attacker's URI | S, I | exact redirect matching; any port only for loopback, with the same scheme, host, path and query; errors before verification go to an error page and are never redirected | `RedirectUrisTest`; `anUnregisteredRedirectIsNeverFollowed`; `anUnknownClientIsAnErrorPage` |
| Code used by another client or at another redirect | S | the code is bound to `client_id`, `redirect_uri` and `resource` | `theCodeIsBoundToClientRedirectAndResource` |
| Token for the wrong resource (confused deputy across servers) | E | `resource` validated at authorize and token time; tokens bound to the configured resource; audience checked on every MCP request | `unsupportedResponseTypeScopeAndResource`; `aTokenIssuedForAnotherResourceIsRefused` |
| Mix-up between authorization servers | S | `iss` on every authorization response (RFC 9207), advertised in metadata | `AuthorizationServerFlowTest.fullFlowRotationReuseDetectionAndEvents` |
| CSRF on the consent decision | T, E | Spring Security CSRF token on the consent form; the request id is bound to the browser session that started it | `theConsentFormNeedsCsrf`; `theConsentBelongsToTheBrowserSessionThatStartedIt` |
| Clickjacking the "Allow" button | T | `X-Frame-Options: DENY` and `frame-ancestors 'none'` | `fullFlowRotationReuseDetectionAndEvents` (CSP header) |
| Phishing with a look-alike client name | S | the name is sanitized (control and bidi characters removed, 80 chars); verification is shown (operator, domain, or not verified); the redirect host is shown; `localhost` redirects get a warning | `theConsentPageEscapesTheClientName`; `ClientMetadataDocumentTest.validDocument`; `DynamicRegistrationTest` |
| XSS through client name, scope or URI on the consent page | T, E | every value HTML-escaped; CSP `default-src 'none'`, no script | `theConsentPageEscapesTheClientName` |
| Parameter pollution | T | repeated parameters refused on authorize and token | `repeatedParametersAreRefused`; `malformedTokenRequests` |
| Leaking parameters through query strings on POST | I | the token endpoint refuses query parameters | `malformedTokenRequests` |
| Consent for a scope the user may not grant | E | `ScopePolicy.grantableScopes`, applied again at decision time | `InactiveSubjectTest.theScopePolicyNarrowsTheGrant` |
| Repudiation of consent or revocation | R | `GrantCreated`, `ConsentDenied`, `GrantRevoked` events with subject and client | `fullFlowRotationReuseDetectionAndEvents`, `deniedConsentGoesBackToTheClient` |

## 2. Tokens and refresh

| Threat | STRIDE | Mitigation | Test |
|---|---|---|---|
| Database leak yields usable tokens | I, E | only SHA-256 of tokens and codes is stored | `JdbcGrantStoreTest.onlyHashesAreStored`; `JdbcFlowTest` |
| Stolen refresh token used alongside the legitimate client | S | rotation on every use; a rotated token replayed outside the grace windows revokes the **whole grant** (RFC 9700 §4.14.2), whoever came first | `GrantStoreContract.beyondBothWindowsReuseRevokesTheWholeGrant`; flow test |
| Race between two refreshes defeats detection | T | rotation under a lock on the grant row; one decision function for every store | `parallelRefreshesOfOneToken…` (memory and PostgreSQL) |
| Refresh token used by another client | S | the grant is bound to `client_id`; mismatch is refused | `refreshIsBoundToTheClientAndTheGrantScope`; `refusalsCarryTheirReasonAndChangeNothing` |
| Scope escalation on refresh | E | requested scope must be within the grant; checked before rotation | `refreshIsBoundToTheClientAndTheGrantScope` |
| Access token of a rotated pair still usable | E | only active pairs authenticate | `anActiveTokenRotatesAndItsAccessTokenStopsWorking` |
| Disabled user keeps access until expiry | E | `McpPrincipalResolver.isActive` on every MCP request and refresh; refresh revokes the grant | `InactiveSubjectTest` |
| Revocation does not take effect | E | in-process introspection: no cache, the next request fails; revocation with any token of the family | `theClientRevokesAndAccessEndsAtOnce`; `theClientRevokesWithAnyTokenOfTheFamily` |
| Token valid on other routes of the application | E | the resource-server chain only matches the MCP paths; other routes use the application's own chain | `anAccessTokenOpensNothingButTheMcpEndpoint` |
| Revocation endpoint as an oracle | I | 200 for any well-formed request, known token or not (RFC 7009) | `theClientRevokesAndAccessEndsAtOnce` |
| Confidential-client credentials accepted on a public-only server | S | `client_secret`, `client_assertion` or an `Authorization` header → `invalid_client` | `confidentialClientAuthenticationIsRefused` |
| Secrets in logs or audit events | I | events carry identifiers only; error descriptions never echo inputs | `fullFlowRotationReuseDetectionAndEvents` (events contain no token, code or verifier) |

## 3. Client ID Metadata Documents (SSRF)

| Threat | STRIDE | Mitigation | Test |
|---|---|---|---|
| `client_id` pointing at internal hosts (loopback, RFC 1918, link-local and cloud metadata, CGNAT, ULA) | I, E | allow list of global unicast addresses; every resolved address must pass | `AddressPolicyTest`; `MetadataDocumentFetcherTest.aPrivateAddressIsRejectedWithoutConnecting`; `NegativeRulesTest.aMetadataDocumentClient…` |
| IPv4 embedded in IPv6 reaching internal IPv4 through a translator (NAT64 `64:ff9b::/96`, `64:ff9b:1::/48`, 6to4, IPv4-compatible, IPv4-mapped, IPv4-translated, Teredo) | I, E | embedded IPv4 judged as IPv4; local-use NAT64, IPv4-compatible, IPv4-translated and Teredo refused outright | `AddressPolicyTest.blocked` |
| DNS rebinding (public answer to the check, internal one to the connection) | I, E | one resolution; the socket connects to the validated `InetAddress`; no JVM-wide resolver | `dnsRebindingCannotSwapTheAddressAfterTheCheck` |
| One internal address among public ones (round robin) | I | every address must pass | `oneInternalAddressAmongPublicOnesRejectsTheHost` |
| Redirect to an internal host | I, E | redirects are never followed | `redirectsAreNotFollowed` |
| Slow or stalled server holds threads (slowloris) | D | one total deadline with a watchdog that closes the socket; per-read timeouts | `aSlowBodyHitsTheTotalDeadline`; `aServerThatNeverAnswersHitsTheDeadline` |
| Huge document or header block exhausts memory | D | 5 KiB body (any framing), 8 KiB head, limited chunk sizes | `tooLarge…`; `anOversizedResponseHeadIsRejected` |
| Request smuggling, ambiguous framing, compression bombs | T, D | both `Transfer-Encoding` and `Content-Length`, conflicting lengths, folded headers and non-identity encodings are all refused | `statusMediaTypeEncodingAndFramingAreChecked` |
| Man in the middle on the document | S, T | TLS with RFC 2818 host name verification and SNI | `theCertificateMustMatchTheHostName` |
| A document impersonating another client | S | `client_id` in the document must equal its URL; no client secret; only `none` authentication | `ClientMetadataDocumentTest.aDocumentCannotImpersonateAnotherClient`; `CimdFlowTest` |
| Using the server to knock on a host repeatedly (amplification) | D | cache of valid documents; per-host budget per minute; global concurrency limit; port 443 only | `CimdFlowTest` (cache); `ClientMetadataResolver` limits |
| Path tricks in the URL (`..`, encoded dots, user info, fragments) | T | URL rules of CIMD draft -03 §3 | `ClientMetadataDocumentTest.clientIdUrlRules` |

## Residual risks (not mitigated by the starter)

- **Rate limiting.** `/oauth2/authorize` triggers metadata fetches and `/oauth2/register` writes rows.
  Both are public. The per-host and concurrency limits bound the fetches, but request floods must be
  stopped in front of the application.
- **Sibling grace.** Someone who steals a refresh token and uses it within 30 s of a legitimate
  rotation gets a sibling pair instead of triggering revocation. Set `refresh-reuse-grace=0` to remove
  this, at the cost of false revocations on concurrent refreshes.
- **Code replay does not revoke the grant.** OAuth 2.1 says SHOULD revoke the tokens issued from a
  replayed code. A replay is refused, but the grant from the first exchange stays alive (planned for
  v0.2). PKCE limits who can redeem a code at all.
- **Consent phishing.** A convincing client name on a domain the user does not check will be approved.
  The page shows the domain and the redirect host; it cannot read for the user.
- **The application's login.** Session fixation, weak passwords and missing MFA are outside the
  starter.
- **In-memory store** with more than one instance breaks the flow: codes minted on one instance are
  unknown on another. This is not a security hole, but it is a failure.
- **No external review yet.** The code is new; treat 0.x as experimental.
