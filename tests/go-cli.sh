#!/usr/bin/env bash
# Run the original synthetic suite with an alternate CLI, then require exact failures.
set -euo pipefail
[[ $# == 2 ]] || { printf 'usage: go-cli.sh SUITE BINARY\n' >&2; exit 2; }
suite="$1" cli="$2"
case "$suite" in secret | backends | libsecret | keychain) ;; *) exit 2 ;; esac
[[ -x "$cli" && "$cli" == /* ]] || { printf 'absolute executable required\n' >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
: >"$tmp/results"
: >"$tmp/inventory"
SECRET_CLI="$cli" SECRET_TEST_RESULTS="$tmp/results" SECRET_TEST_INVENTORY="$tmp/inventory" \
    "${BASH_BIN:-bash}" "$root/tests/test-$suite.sh" >"$tmp/log" 2>&1 || true
# Incomplete suites must never be mistaken for known case divergences.
if ! grep -Eq '^[0-9]+ passed, [0-9]+ failed' "$tmp/log"; then
    printf '%s: suite did not finish\n' "$suite" >&2
    exit 1
fi
inventory="$root/testdata/inventory/$suite.tsv"
if [[ "$(uname -s)" == Darwin && -f "$root/testdata/inventory/$suite.darwin.tsv" ]]; then
    inventory="$root/testdata/inventory/$suite.darwin.tsv"
fi
python3 -I "$root/tests/check-go-divergence.py" "$suite" "$inventory" "$tmp/results" \
    "$root/testdata/inventory/go-expected-divergence.tsv"
