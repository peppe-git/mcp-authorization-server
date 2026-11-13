#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails when the working tree contains material that must never be published: internal issue
# identifiers, incident dates, real client names, commercial data, e-mail addresses, secrets,
# Italian text or prompt files.
#
# Project-specific patterns (product names, former handles, internal infrastructure) never live in
# this repository. Put them in a file outside it and point SCRUB_PRIVATE_PATTERNS at that file:
# one extended regular expression per line, matched case-insensitively; blank lines and lines
# starting with # are ignored. Without the variable only the generic rules run (with a warning).
#
# Scans tracked files and untracked files that are not ignored, so a dirty file is caught
# before it is committed. Exit code: 0 = clean, 1 = findings, 2 = usage error.
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "scrub-check: not a git repository" >&2; exit 2; }
cd "$root"

self="scripts/scrub-check.sh"

private_patterns=()
if [[ -z "${SCRUB_PRIVATE_PATTERNS:-}" ]]; then
  echo "scrub-check: SCRUB_PRIVATE_PATTERNS is not set: project-specific patterns are NOT checked" >&2
elif [[ ! -f "$SCRUB_PRIVATE_PATTERNS" || ! -r "$SCRUB_PRIVATE_PATTERNS" ]]; then
  echo "scrub-check: SCRUB_PRIVATE_PATTERNS points to a file that does not exist or cannot be read" >&2
  exit 2
else
  n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]] && continue
    # grep exits with 2 on an invalid expression: refuse it instead of silently matching nothing.
    rc=0
    grep -qiE -e "$line" </dev/null 2>/dev/null || rc=$?
    if [[ $rc -eq 2 ]]; then
      echo "scrub-check: invalid pattern on line $n of SCRUB_PRIVATE_PATTERNS" >&2
      exit 2
    fi
    private_patterns+=("$line")
  done <"$SCRUB_PRIVATE_PATTERNS"
fi

files=()
while IFS= read -r -d '' f; do
  [[ "$f" == "$self" ]] && continue
  [[ -f "$f" ]] || continue
  files+=("$f")
done < <(git ls-files -z --cached --others --exclude-standard)

findings=0

report() { # rule, file:line:token
  printf '%s\t%s\n' "$1" "$2"
  findings=$((findings + 1))
}

# scan RULE CASE(i|s) ALLOW_REGEX PATTERN
scan() {
  local rule="$1" mode="$2" allow="$3" pattern="$4"
  ((${#files[@]})) || return 0
  local flags="-noIE"
  [[ "$mode" == "i" ]] && flags="-noIiE"
  local line
  while IFS= read -r line; do
    local token="${line#*:}"; token="${token#*:}"
    if [[ -n "$allow" ]] && printf '%s' "$token" | grep -qE "^(${allow})$"; then
      continue
    fi
    report "$rule" "$line"
  done < <(printf '%s\0' "${files[@]}" | xargs -0 grep $flags -e "$pattern" -- 2>/dev/null || true)
}

# 1. Project-specific patterns from the private file (none when the variable is not set).
for pattern in ${private_patterns[@]+"${private_patterns[@]}"}; do
  scan private i "" "$pattern"
done
# 2. Internal issue / audit identifiers (B123, E45, M50, D24, S16, T-040, V171, it-123).
#    S256 is the PKCE method name, not an identifier.
scan issue-id s 'S256' '\b[BEMDSTV]-?[0-9]{1,4}\b'
scan issue-id s '' '\bit-[0-9]{1,4}\b'
# 3. Calendar dates (incident dates, job dates). MCP protocol revisions are allowed.
scan date s '2024-11-05|2025-03-26|2025-06-18|2025-11-25|2026-07-28' '\b20[0-9]{2}-[01][0-9]-[0-3][0-9]\b'
# 4. Real MCP client names and their endpoints.
scan client-name i "" 'claude|chatgpt|openai|anthropic|copilot|windsurf|cursor\.(com|sh)|\bcodex\b'
# 5. Commercial data: money, plans, credits, price lists.
scan commercial i "" '€|\bEUR\b|[0-9] ?euros?\b|\bcrediti\b|\blistino\b|\bpricing\b|\b(free|pro|team|business) plan\b|\bpiano (free|pro|team|business)\b'
# 6. E-mail addresses (reserved example domains are allowed).
scan email s '[A-Za-z0-9._%+-]+@(example\.(com|org|net)|[A-Za-z0-9.-]+\.(test|invalid|example))' '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
# 7. Secrets.
scan secret s "" '-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|\bsk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|xox[abp]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}'
# 8. Italian left in public files (everything public is English).
scan italian i "" '\b(perché|quindi|della|degli|questo|questa|nella|anche|viene|sono stati|richiesta)\b'

# 9. Forbidden paths: environment files and prompt directories.
for f in "${files[@]}"; do
  case "$f" in
    .env|.env.*|*/.env|*/.env.*) [[ "$f" == *.env.example ]] || report forbidden-path "$f" ;;
  esac
  case "/$f" in
    */prompts/*) report forbidden-path "$f" ;;
  esac
done

if ((findings > 0)); then
  echo "scrub-check: $findings finding(s). Remove them before committing." >&2
  exit 1
fi
echo "scrub-check: clean (${#files[@]} files scanned)"
