# Security policy

This project is an OAuth authorization server, which makes it a security component. Please report
vulnerabilities **privately**.

## How to report

- Open a private report:
  [github.com/peppe-git/mcp-authorization-server/security/advisories/new](https://github.com/peppe-git/mcp-authorization-server/security/advisories/new).
  This is GitHub's private vulnerability reporting: only you and the maintainer see it.
- Do not open a public issue, pull request or discussion about a vulnerability.
- Include:
  - the version or commit;
  - the configuration involved;
  - a reproduction (a failing test is ideal);
  - what an attacker gains.
- Please do not test against deployments you do not own.

There is no e-mail contact. GitHub is the only channel.

## What to expect

The project is maintained by one person in spare time. These are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| First assessment (valid or not, severity) | within 14 days |
| Fix or mitigation for critical and high severity | within 30 days of the assessment |
| Fix for medium and low severity | in a later release, within 90 days |
| Public advisory | when a fixed release is available, crediting you if you wish |

- If a fix needs longer, the maintainer tells you why and agrees a new date with you.
- If a report is declined, you get the reason.
- Please allow up to 90 days before disclosing on your own.

## Supported versions

Until 1.0, only the latest release receives security fixes. The project is pre-1.0 and has not yet had
an external security review.

## Scope

**In scope:** the starter's code and its default configuration:

- the authorization, consent, token, revocation, registration and discovery endpoints;
- the metadata-document fetcher (SSRF);
- the stores;
- the resource-server integration.

**Out of scope:**

- vulnerabilities in Spring, the JDK or other dependencies (report them upstream);
- the application's own login and user management;
- deployments that disable a protection through configuration;
- missing rate limiting, which is documented as the application's responsibility.

See [docs/threat-model.md](docs/threat-model.md) for what the starter defends against and what it
does not.
