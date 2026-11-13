#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Proves that the tests guard the security rules: each mutation disables one rule in the main code,
# runs the tests that cover it, and expects them to FAIL. The file is restored afterwards.
# A mutation whose tests still pass is a hole in the test suite and makes this script fail.
#
# Usage: scripts/mutation-check.sh [mutation-name ...]   (default: all)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

SRC=mcp-authorization-server-spring-boot-starter/src/main/java/io/github/peppe_git/mcpauthserver

# name # file # perl substitution (must change the file) # tests
MUTATIONS=(
  "pkce-method#core/AuthorizationFlow.java#s/if \(!Pkce\.S256\.equals\(params\.getFirst\(\"code_challenge_method\"\)\)/if (false/#NegativeRulesTest"
  "pkce-verify#core/TokenFlow.java#s/if \(!Pkce\.verify\(verifier, issued\.codeChallenge\(\)\)\)/if (false)/#NegativeRulesTest"
  "redirect-registered#core/AuthorizationFlow.java#s/if \(redirectUri == null \|\| !RedirectUris\.matchesAny\(redirectUri, client\.redirectUris\(\)\)/if (redirectUri == null/#NegativeRulesTest"
  "redirect-loopback-host#oauth/RedirectUris.java#s/ && c\.getHost\(\)\.equalsIgnoreCase\(r\.getHost\(\)\)//#RedirectUrisTest"
  "reuse-detection#store/RotationRules.java#s/return Decision\.of\(Action\.REUSE\);/return Decision.of(Action.SIBLING);/#InMemoryGrantStoreTest,AuthorizationServerFlowTest"
  "rotation-lock#store/JdbcGrantStore.java#s/WHERE g\.grant_id = \? FOR UPDATE/WHERE g.grant_id = ?/#JdbcGrantStoreTest"
  "refresh-scope#core/TokenFlow.java#s/return \"invalid_scope\";/return null;/#NegativeRulesTest"
  "audience#resource/McpOpaqueTokenIntrospector.java#s/if \(!ResourceIdentifiers\.same\(g\.resource\(\), this\.settings\.resource\(\)\)\)/if (false)/#NegativeRulesTest"
  "subject-active#resource/McpOpaqueTokenIntrospector.java#s/if \(!this\.principals\.isActive\(g\.subject\(\)\)\)/if (false)/#InactiveSubjectTest"
  "session-binding#web/AuthorizationController.java#s/if \(!isBound\(request, requestId\)\) \{\n\t\t\tnotBound\(request, response\);\n\t\t\treturn;\n\t\t\}\n\t\tResult result/if (false) {\n\t\t\tnotBound(request, response);\n\t\t\treturn;\n\t\t}\n\t\tResult result/#NegativeRulesTest"
  "consent-csrf#autoconfigure/McpAuthorizationServerSecurityConfiguration.java#s/c\.ignoringRequestMatchers\(PathPatternRequestMatcher\.withDefaults\(\)\.matcher\(McpEndpoints\.TOKEN\),/c.ignoringRequestMatchers(PathPatternRequestMatcher.withDefaults().matcher(McpEndpoints.CONSENT), PathPatternRequestMatcher.withDefaults().matcher(McpEndpoints.TOKEN),/#NegativeRulesTest"
  "error-dispatch#autoconfigure/McpAuthorizationServerSecurityConfiguration.java#s/if \(request\.getDispatcherType\(\) != DispatcherType\.ERROR/if (true/#RealServerTest"
  "ssrf-policy#cimd/MetadataDocumentFetcher.java#s/if \(address == null \|\| !this\.addressPolicy\.test\(address\)\)/if (address == null)/#MetadataDocumentFetcherTest"
  "ssrf-6to4#cimd/AddressPolicy.java#s/return isGlobalIpv4\(new byte\[\] \{ b\[2\], b\[3\], b\[4\], b\[5\] \}\);/return true;/#AddressPolicyTest"
  "ssrf-nat64#cimd/AddressPolicy.java#s/(\&\& isZero\(b, 4, 12\)\) \{\n\t\t\treturn) isGlobalIpv4\(slice\(b, 12\)\);/\$1 true;/#AddressPolicyTest"
  "dns-rebinding#cimd/MetadataDocumentFetcher.java#s/plain = this\.connector\.connect\(address, port/plain = this.connector.connect(this.resolver.resolve(host)[0], port/#MetadataDocumentFetcherTest"
  "deadline#cimd/MetadataDocumentFetcher.java#s/this\.socket\.setSoTimeout\(remainingMillis\(this\.deadline\)\);/this.socket.setSoTimeout(0);/; s/WATCHDOG\.schedule\(\(\) -> closeQuietly\(plain\), remainingNanos\(deadline\)/WATCHDOG.schedule(() -> closeQuietly(plain), 3_600_000_000_000L/#MetadataDocumentFetcherTest"
  "max-size#cimd/MetadataDocumentFetcher.java#s/if \(length > this\.maxBodyBytes\)/if (false)/#MetadataDocumentFetcherTest"
  "no-redirects#cimd/MetadataDocumentFetcher.java#s/if \(status != 200\)/if (status >= 400)/#MetadataDocumentFetcherTest"
  "cimd-impersonation#cimd/ClientMetadataDocument.java#s/if \(!clientId\.equals\(doc\.get\(\"client_id\"\)\)\)/if (false)/#ClientMetadataDocumentTest,CimdFlowTest"
  "code-single-use#store/InMemoryAuthorizationStateStore.java#s/IssuedCode c = \(codeHash == null\) \? null : this\.codes\.remove\(codeHash\);/IssuedCode c = (codeHash == null) ? null : this.codes.get(codeHash);/#NegativeRulesTest,InMemoryAuthorizationStateStoreTest"
)

MVN=(./mvnw -q -o -pl mcp-authorization-server-spring-boot-starter)

selected=("$@")

# Baseline: without mutations the selected tests must pass, otherwise "red" would prove nothing.
all_tests="$(for e in "${MUTATIONS[@]}"; do IFS='#' read -r _ _ _ t <<<"$e"; printf '%s,' "$t"; done)"
if ! "${MVN[@]}" test -Dtest="${all_tests%,}" -Dsurefire.failIfNoSpecifiedTests=false >/dev/null 2>&1; then
  echo "mutation-check: the tests fail even without mutations; fix them first" >&2
  exit 2
fi

failures=0
results=()
for entry in "${MUTATIONS[@]}"; do
  IFS='#' read -r name file subst tests <<<"$entry"
  if ((${#selected[@]})) && [[ ! " ${selected[*]} " == *" $name "* ]]; then
    continue
  fi
  path="$SRC/$file"
  backup="$(mktemp)"
  cp "$path" "$backup"
  before="$(shasum "$path")"
  perl -0pi -e "$subst" "$path"
  if [[ "$(shasum "$path")" == "$before" ]]; then
    results+=("BROKEN  $name: the substitution did not match")
    failures=$((failures + 1))
    cp "$backup" "$path"; rm -f "$backup"
    continue
  fi
  if ! "${MVN[@]}" test-compile >/dev/null 2>&1; then
    results+=("BROKEN  $name: the mutated code does not compile")
    failures=$((failures + 1))
  elif "${MVN[@]}" test -Dtest="$tests" -Dsurefire.failIfNoSpecifiedTests=false >/dev/null 2>&1; then
    results+=("SURVIVED $name: tests [$tests] still pass with the rule disabled")
    failures=$((failures + 1))
  else
    results+=("RED     $name: tests [$tests] fail with the rule disabled")
  fi
  cp "$backup" "$path"; rm -f "$backup"
done

printf '%s\n' "${results[@]}"
if ((failures > 0)); then
  echo "mutation-check: $failures mutation(s) not caught" >&2
  exit 1
fi
echo "mutation-check: every mutation was caught"
