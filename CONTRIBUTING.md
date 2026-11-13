# Contributing

Thank you for helping. This project is a small security component maintained in spare time, so the
bar for changes is "smaller and safer", not "more features".

## Before you start

- **Security issues are never reported in public issues or pull requests.** See [SECURITY.md](SECURITY.md).
- Open an issue before a large change. Changes that widen the protocol surface need a strong reason.
  Examples: confidential clients, JWT access tokens, new grant types.
- Every security rule needs a negative test. The test must fail when the rule is removed: add a line to
  `scripts/mutation-check.sh` for new rules.

## Development

```bash
./mvnw verify                      # build and all tests (Docker is needed for the PostgreSQL tests)
./scripts/scrub-check.sh           # no issue ids, dates, client names, secrets or e-mail addresses
./scripts/mutation-check.sh        # every security rule is guarded by a failing test
```

### Private scrub patterns

The scrub check ships only generic rules. Patterns that would themselves reveal what must stay
private (a product name, a former handle, internal host names) live in a file **outside** the
repository, named by the `SCRUB_PRIVATE_PATTERNS` environment variable:

```bash
SCRUB_PRIVATE_PATTERNS="$HOME/private/scrub-patterns.txt" ./scripts/scrub-check.sh
```

The file holds one extended regular expression per line, matched case-insensitively. Blank lines and
lines starting with `#` are ignored:

```text
# names that must never appear in this repository
acme[^a-z0-9]{0,3}internal
\bold-handle-2019\b
```

- Without the variable the script warns on stderr and runs the generic rules only.
- With the variable set to a missing file, or a file with an invalid expression, it exits with 2.
- Never commit the file or its path.

- Java 17 source level, built and tested on JDK 21.
- Every source file starts with `// SPDX-License-Identifier: Apache-2.0`.
- Commit messages follow `type(scope): sentence`. Examples: `fix(cimd): reject ...`,
  `docs: explain ...`.
- Everything public is in English.

## Licensing

By contributing you agree that your contribution is licensed under the Apache License 2.0, like the
rest of the project.
