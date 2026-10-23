#!/usr/bin/env bash
# Run one synthetic hook suite with an alternate guard and exact divergences.
set -euo pipefail
[[ $# == 3 ]] || { printf 'usage: go-hook.sh guard|codex BINARY claude|codex\n' >&2; exit 2; }
suite="$1" binary="$2" host="$3"
case "$suite:$host" in guard:claude | codex:codex) ;; *) exit 2 ;; esac
[[ "$binary" == /* && -x "$binary" ]] || { printf 'absolute executable required\n' >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Print the last 40 log lines for diagnosis. Suites use synthetic fixtures only, but
# lines carrying a synthetic- value pattern are redacted rather than printed.
log_tail() {
    printf '%s: last 40 lines of suite log (synthetic- lines redacted)\n' "$1" >&2
    tail -n 40 "$2" | sed -e 's/.*synthetic-.*/[redacted: line matches synthetic- value pattern]/' >&2
}
: >"$tmp/results"
: >"$tmp/inventory"
SECRET_GUARD="$binary hook $host" SECRET_TEST_RESULTS="$tmp/results" SECRET_TEST_INVENTORY="$tmp/inventory" \
    "${BASH_BIN:-bash}" "$root/tests/test-$suite.sh" >"$tmp/log" 2>&1 || true
if ! grep -Eq '^[0-9]+ passed, [0-9]+ failed' "$tmp/log"; then
    printf '%s: suite did not finish\n' "$suite" >&2
    log_tail "$suite" "$tmp/log"
    exit 1
fi
inventory="$root/testdata/inventory/$suite.tsv"
if [[ "$(uname -s)" == Darwin && -f "$root/testdata/inventory/$suite.darwin.tsv" ]]; then
    inventory="$root/testdata/inventory/$suite.darwin.tsv"
fi
rc=0
python3 -I "$root/tests/check-go-hook-divergence.py" "$suite" "$inventory" \
    "$tmp/results" "$root/testdata/inventory/go-hook-divergence.tsv" "$tmp/log" || rc=$?
if ((rc != 0)); then
    log_tail "$suite" "$tmp/log"
fi
exit "$rc"
