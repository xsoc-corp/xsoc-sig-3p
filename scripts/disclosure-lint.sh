#!/usr/bin/env bash
# Disclosure-lint: scan tracked files for forbidden trade-secret terms.
#
# Configuration:
#   .disclosure-lint/forbidden.txt    one ERE pattern per line
#                                     # for comments, blank lines ignored
#
# Allowlist:
#   Add a trailing comment 'disclosure-allow: <reason>' on any source line
#   to permit an intentional reference. Reviewers should sanity-check these
#   during PR review.
#
# Exit codes:
#   0    clean (or empty term list)
#   1    one or more violations found

set -euo pipefail

terms_file=".disclosure-lint/forbidden.txt"

if [[ ! -f "$terms_file" ]]; then
    echo "disclosure-lint: no $terms_file; skipping."
    exit 0
fi

# Collect active (non-comment, non-blank) lines.
# || true so that grep returning 1 (no matches) does not trip pipefail.
active_lines=$(grep -Ev '^[[:space:]]*(#|$)' "$terms_file" || true)

if [[ -z "$active_lines" ]]; then
    echo "disclosure-lint: no active terms in $terms_file; skipping."
    exit 0
fi

# Build a single ERE pattern from the active lines.
pattern=$(printf '%s\n' "$active_lines" | paste -sd '|' -)
term_count=$(printf '%s\n' "$active_lines" | wc -l)
echo "disclosure-lint: scanning with $term_count term(s)."

# Scan tracked files except the lint config and script itself.
mapfile -t files < <(git ls-files | grep -Ev '^\.disclosure-lint/|^scripts/disclosure-lint')

violations=0
for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    # -E ERE, -i case-insensitive, -n line numbers.
    # 2>/dev/null suppresses binary-file warnings from grep.
    matches=$(grep -Ein "$pattern" "$file" 2>/dev/null || true)
    [[ -z "$matches" ]] && continue

    while IFS= read -r line; do
        # Skip lines with an explicit allowlist marker.
        if echo "$line" | grep -q "disclosure-allow:"; then
            continue
        fi
        echo "VIOLATION: ${file}:${line}"
        violations=$((violations + 1))
    done <<< "$matches"
done

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "disclosure-lint: failed with ${violations} violation(s)."
    echo "If a term is intentionally present, add a trailing comment:"
    echo "  // disclosure-allow: <reason>"
    exit 1
fi

echo "disclosure-lint: clean."
