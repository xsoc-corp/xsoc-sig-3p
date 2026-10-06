#!/usr/bin/env bash
# Self-test for scripts/disclosure-lint.sh.
#
# Exercises every exit path of the disclosure lint against scratch git trees,
# so the production check is known to work before anyone relies on it being
# green. This runs standalone and in CI, and depends on nothing in the XSOC
# control list: it is valid while .disclosure-lint/forbidden.txt is still
# empty, and it stays valid once that file is populated.
#
# Exit codes:
#   0    every case behaved as specified
#   1    at least one case did not

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lint="${here}/disclosure-lint.sh"

if [[ ! -f "$lint" ]]; then
    echo "selftest: cannot find ${lint}" >&2
    exit 1
fi

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

failures=0
case_num=0

# make_tree <terms-body> [path:::content ...]
# An empty terms body means no .disclosure-lint/forbidden.txt at all.
# Prints the new tree's path.
make_tree() {
    local terms="$1"
    shift
    local dir
    dir="$(mktemp -d "${root}/tree.XXXXXX")"
    git -C "$dir" init -q
    git -C "$dir" config user.email "selftest@example.invalid"
    git -C "$dir" config user.name "disclosure-lint selftest"
    if [[ -n "$terms" ]]; then
        mkdir -p "${dir}/.disclosure-lint"
        printf '%s\n' "$terms" > "${dir}/.disclosure-lint/forbidden.txt"
    fi
    mkdir -p "${dir}/scripts"
    cp "$lint" "${dir}/scripts/disclosure-lint.sh"
    local pair path content
    for pair in "$@"; do
        path="${pair%%:::*}"
        content="${pair#*:::}"
        mkdir -p "${dir}/$(dirname "$path")"
        printf '%s\n' "$content" > "${dir}/${path}"
    done
    git -C "$dir" add -A >/dev/null 2>&1
    printf '%s' "$dir"
}

# expect <want-exit> <description> <tree> [needle]
expect() {
    local want="$1" desc="$2" dir="$3" needle="${4:-}"
    local out rc=0
    case_num=$((case_num + 1))
    # Unset the CI variables so annotations stay plain and the real job
    # summary is never written to from here.
    out="$(cd "$dir" && env -u GITHUB_ACTIONS -u GITHUB_STEP_SUMMARY \
        bash scripts/disclosure-lint.sh 2>&1)" || rc=$?
    if [[ $rc -ne $want ]]; then
        echo "FAIL [${case_num}] ${desc}: expected exit ${want}, got ${rc}"
        printf '%s\n' "$out" | sed 's/^/           /'
        failures=$((failures + 1))
    elif [[ -n "$needle" ]] && ! printf '%s' "$out" | grep -qF -- "$needle"; then
        echo "FAIL [${case_num}] ${desc}: exit ${rc} correct, but output lacks '${needle}'"
        printf '%s\n' "$out" | sed 's/^/           /'
        failures=$((failures + 1))
    else
        echo "ok   [${case_num}] ${desc} (exit ${rc})"
    fi
}

echo "disclosure-lint selftest: ${lint}"
echo

# === Not configured: must never report clean. ===

expect 2 "no forbidden.txt at all" \
    "$(make_tree "" "src/lib.rs:::pub fn ok() {}")" \
    "not configured"

expect 2 "forbidden.txt with only comments and blanks" \
    "$(make_tree "$(printf '# header\n#\n\n   \n')" "src/lib.rs:::pub fn ok() {}")" \
    "no active terms"

expect 2 "forbidden.txt present but malformed ERE" \
    "$(make_tree "$(printf '[unclosed\n')" "src/lib.rs:::pub fn ok() {}")" \
    "invalid extended regex"

# === Clean: one active term, nothing matches. ===

expect 0 "active term, clean tree" \
    "$(make_tree "wave_round_constant_[0-9]+" "src/lib.rs:::pub fn ok() {}")" \
    "clean"

# === Violations: the scanner catches what it is given. ===

expect 1 "literal term present in a tracked file" \
    "$(make_tree "sp_versa_internal" "src/lib.rs:::let x = sp_versa_internal();")" \
    "VIOLATION"

expect 1 "term matches case-insensitively" \
    "$(make_tree "sp_versa_internal" "src/lib.rs:::let x = SP_VERSA_INTERNAL;")" \
    "VIOLATION"

expect 1 "regex term matches a generated name" \
    "$(make_tree "wave_round_constant_[0-9]+" "src/tbl.rs:::const wave_round_constant_7: u32 = 0;")" \
    "VIOLATION"

expect 1 "second term in the list matches (alternation is joined)" \
    "$(make_tree "$(printf 'never_appears_anywhere\nsp_versa_internal\n')" \
        "src/lib.rs:::let x = sp_versa_internal();")" \
    "VIOLATION"

expect 1 "term with surrounding whitespace is trimmed and still matches" \
    "$(make_tree "$(printf '   sp_versa_internal   \n')" \
        "src/lib.rs:::let x = sp_versa_internal();")" \
    "VIOLATION"

expect 1 "match in a file that is not Rust source" \
    "$(make_tree "sp_versa_internal" "docs/notes.md:::See sp_versa_internal for detail.")" \
    "VIOLATION"

# === Allowlist: an explicitly cleared reference passes. ===

expect 0 "disclosure-allow marker clears the line" \
    "$(make_tree "sp_versa_internal" \
        "src/lib.rs:::let x = sp_versa_internal(); // disclosure-allow: cleared for the public API doc")" \
    "clean"

expect 1 "allowlist on one line does not clear a second unmarked line" \
    "$(make_tree "sp_versa_internal" \
        "$(printf 'src/lib.rs:::let a = sp_versa_internal(); // disclosure-allow: cleared\nlet b = sp_versa_internal();')")" \
    "VIOLATION"

# === The lint never flags its own config or itself. ===

expect 0 "terms in forbidden.txt do not self-match" \
    "$(make_tree "sp_versa_internal" "src/lib.rs:::pub fn ok() {}")" \
    "clean"

echo
if [[ $failures -gt 0 ]]; then
    echo "disclosure-lint selftest: FAILED ${failures} of ${case_num} case(s)."
    exit 1
fi

echo "disclosure-lint selftest: all ${case_num} case(s) passed."
