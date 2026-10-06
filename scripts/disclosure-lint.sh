#!/usr/bin/env bash
# Disclosure-lint: scan tracked files for forbidden trade-secret terms.
#
# FAIL-CLOSED BY DESIGN.
#
# A passing disclosure-lint run asserts one specific thing: every tracked
# file in this repository was scanned against a non-empty control list and
# nothing matched. A run that scanned nothing cannot make that assertion,
# so an absent, unreadable, or empty term list is a configuration failure
# and not a pass. Do not add an empty-list bypass to make the check green.
#
# Configuration:
#   .disclosure-lint/forbidden.txt    one ERE pattern per line
#                                     '#' comments and blank lines ignored
#                                     leading/trailing whitespace trimmed
#
# Allowlist:
#   Add a trailing comment 'disclosure-allow: <reason>' on any source line
#   to permit an intentional reference. Reviewers should sanity-check these
#   during PR review.
#
# Exit codes:
#   0    scanned against one or more active terms; no violations
#   1    one or more violations found
#   2    not configured: term list absent, unreadable, empty, or malformed,
#        or the working tree yielded no tracked files to scan
#
# Self-test: scripts/disclosure-lint-selftest.sh exercises all three exit
# paths against scratch trees and depends on nothing in Appendix F.

set -euo pipefail

terms_file=".disclosure-lint/forbidden.txt"

# GitHub Actions annotations; plain stderr outside CI.
annotate() {
    local level="$1"
    shift
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::${level}::$*"
    else
        echo "${level}: $*" >&2
    fi
}

# Job summary lines; no-op outside CI.
summarize() {
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
    fi
}

not_configured() {
    annotate error "disclosure-lint is not configured: $1"
    summarize "### Disclosure lint: NOT CONFIGURED"
    summarize ""
    summarize "$1"
    summarize ""
    summarize "This check is fail-closed. It will not report a clean tree until"
    summarize "\`${terms_file}\` holds at least one valid active term."
    summarize "Populate it from the XSOC control list, or remove this workflow"
    summarize "until that list exists. Do not make the check pass by weakening"
    summarize "the scan."
    exit 2
}

if [[ ! -f "$terms_file" ]]; then
    not_configured "no ${terms_file} in the tree."
fi

if [[ ! -r "$terms_file" ]]; then
    not_configured "${terms_file} exists but is not readable."
fi

# Active lines: not blank, not a comment. Leading and trailing whitespace is
# stripped first, so a stray space cannot silently alter the alternation.
active_lines=$(
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$terms_file" \
        | grep -Ev '^(#|$)' || true
)

if [[ -z "$active_lines" ]]; then
    not_configured "${terms_file} holds no active terms (comments and blanks only)."
fi

# Validate each term as an ERE on its own before joining them. A malformed
# entry is then reported by name instead of collapsing the whole scan into an
# opaque grep error, and a pattern that silently fails to compile can never be
# mistaken for a pattern that matched nothing.
bad_terms=0
while IFS= read -r term; do
    rc=0
    printf '' | grep -Eq -- "$term" >/dev/null 2>&1 || rc=$?
    if [[ $rc -gt 1 ]]; then
        annotate error "invalid extended regex in ${terms_file}: ${term}"
        bad_terms=$((bad_terms + 1))
    fi
done <<< "$active_lines"

if [[ $bad_terms -gt 0 ]]; then
    not_configured "${bad_terms} malformed term(s) in ${terms_file}; see the errors above."
fi

pattern=$(printf '%s\n' "$active_lines" | paste -sd '|' -)
term_count=$(printf '%s\n' "$active_lines" | wc -l | tr -d '[:space:]')

# Scan every tracked file except the control list and this script, which
# necessarily contain the terms and the matching logic.
mapfile -t files < <(
    git ls-files | grep -Ev '^\.disclosure-lint/|^scripts/disclosure-lint' || true
)

if [[ ${#files[@]} -eq 0 ]]; then
    not_configured "git ls-files returned no files to scan; is this a checkout?"
fi

echo "disclosure-lint: scanning against ${term_count} active term(s)."

violations=0
scanned=0
for file in "${files[@]}"; do
    if [[ ! -f "$file" ]]; then
        continue
    fi
    scanned=$((scanned + 1))
    # --binary-files=text so a term embedded in a binary is reported with a
    # line number rather than silently skipped.
    matches=$(grep -Ein --binary-files=text -- "$pattern" "$file" 2>/dev/null || true)
    if [[ -z "$matches" ]]; then
        continue
    fi
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        if printf '%s' "$line" | grep -qF "disclosure-allow:"; then
            continue
        fi
        echo "VIOLATION: ${file}:${line}"
        annotate error "forbidden term in ${file}: ${line}"
        violations=$((violations + 1))
    done <<< "$matches"
done

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "disclosure-lint: FAILED with ${violations} violation(s) across ${scanned} scanned file(s)."
    summarize "### Disclosure lint: FAILED"
    summarize ""
    summarize "${violations} violation(s) across ${scanned} scanned file(s), ${term_count} active term(s)."
    summarize ""
    summarize "If a reference is intentional and cleared for public release, add a"
    summarize "trailing comment on the source line:"
    summarize ""
    summarize '    // disclosure-allow: <reason>'
    exit 1
fi

echo "disclosure-lint: clean. ${scanned} file(s) scanned against ${term_count} active term(s)."
summarize "### Disclosure lint: clean"
summarize ""
summarize "${scanned} file(s) scanned against ${term_count} active term(s)."
