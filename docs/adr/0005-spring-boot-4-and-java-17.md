# ADR-0005: Spring Boot 4.1+ only, Java 17 baseline

- Status: accepted (v0.1), to be confirmed by the maintainer

## Context

Spring Boot 3.5 and 4.x differ in several ways that matter here:

- Spring Security 6 against 7;
- Jackson 2 against Jackson 3;
- the modularized auto-configuration packages;
- the resource-server metadata APIs (7.0 and 7.1).

Supporting both doubles the test matrix and the compatibility code. The maintainer has 5–10 hours a
week, and this is a security surface.

## Decision

- Target Spring Boot **4.1.x** (Spring Security 7.1).
- Compile with `--release 17`. Boot 4 requires Java 17, and nothing here needs a newer language
  level. The project is built and tested on JDK 21.
- No direct Jackson dependency:
  - HTTP JSON goes through the application's message converters;
  - the CIMD document goes through Spring Boot's `JsonParserFactory`;
  - the JDBC stores use plain columns, not serialized JSON.

## Consequences

Boot 3.5 users cannot use v0.1. If there is demand, a 3.5 branch would only need the security and
auto-configuration glue, because the core has no Boot 4-only API.
