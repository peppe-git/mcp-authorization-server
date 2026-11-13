# Security policy

This project is an OAuth authorization server, which makes it a security component. Please report
vulnerabilities **privately**.

## How to report

- Use the repository's **private vulnerability reporting** ("Report a vulnerability" in the Security
  tab). Do not open a public issue, pull request or discussion.
- Include the version or commit, the configuration involved, and a reproduction (a failing test is
  ideal). Say what an attacker gains.
- Please do not test against deployments you do not own.

## What to expect

The project is maintained by one person in spare time. Realistic targets:

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| First assessment (valid or not, severity) | within 14 days |
| Fix or mitigation for high and critical issues | as fast as possible, usually within 30 days |
| Public advisory | after a fixed release is available, crediting you if you wish |

If a report is declined, you get the reason.

## Supported versions

Until 1.0 only the latest release receives fixes. The project is pre-1.0 (`0.1.0-SNAPSHOT`). It has
not yet had an external security review.

## Scope

In scope: the starter's code and its default configuration. That covers the authorization, consent,
token, revocation, registration and discovery endpoints, the metadata-document fetcher (SSRF), the
stores, and the resource-server integration.

Out of scope:

- vulnerabilities in Spring, the JDK or other dependencies (report them upstream);
- the application's own login and user management;
- deployments that disable a protection through configuration;
- missing rate limiting, which is documented as the application's responsibility.

See [docs/threat-model.md](docs/threat-model.md) for what the starter defends against and what it
does not.
