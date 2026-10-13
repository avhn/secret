#!/usr/bin/env bash
# Capture the exact synthetic shell case inventory without changing normal suite output.
# Usage: bash tests/inventory.sh --write|--check [--suite NAME]
# Provider inventories require isolated libsecret or macOS Keychain. When the
# keychain inventory is absent, CI uploads testdata/inventory/keychain.tsv as an
# artifact. Download and commit that artifact, then set SECRET_INVENTORY_STRICT=1
# in CI to require the committed file. Never run the Keychain suite on Linux.
# SECRET_INVENTORY_DIR overrides the write destination for read-only mounts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="" SUITE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --write | --check)
            [[ -z "$MODE" ]] || { printf 'choose one mode\n' >&2; exit 2; }
            MODE="$1"; shift ;;
        --suite)
            [[ $# -ge 2 ]] || { printf 'missing suite name\n' >&2; exit 2; }
            SUITE="$2"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ -n "$MODE" ]] || { printf 'choose --write or --check\n' >&2; exit 2; }
case "$SUITE" in
    '' | guard | secret | backends | codex | libsecret | keychain) ;;
    *) printf 'unknown suite: %s\n' "$SUITE" >&2; exit 2 ;;
esac
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILED=0
if [[ -n "$SUITE" ]]; then
    SUITES=("$SUITE")
else
    SUITES=(guard secret backends codex)
fi

for suite in "${SUITES[@]}"; do
    if [[ "$suite" == keychain && "$(uname -s)" != Darwin ]]; then
        printf 'keychain: macOS required\n' >&2
        exit 2
    fi
    raw="$TMP/$suite.raw"
    : >"$raw"
    # Explicitly require providers so a skipped suite cannot create an empty inventory.
    require_libsecret=0 require_keychain=0
    [[ "$suite" == libsecret ]] && require_libsecret=1
    [[ "$suite" == keychain ]] && require_keychain=1
    if ! env SECRET_TEST_INVENTORY="$raw" SECRET_REQUIRE_LIBSECRET="$require_libsecret" \
        SECRET_REQUIRE_KEYCHAIN="$require_keychain" "${BASH_BIN:-bash}" \
        "$ROOT/tests/test-$suite.sh" >"$TMP/$suite.log" 2>&1; then
        cat "$TMP/$suite.log" >&2
        printf '%s: suite failed\n' "$suite" >&2
        FAILED=1
        continue
    fi
    if [[ ! -s "$raw" ]]; then
        printf '%s: no cases recorded (suite may have skipped)\n' "$suite" >&2
        FAILED=1
        continue
    fi
    # Number repeated names in encounter order, before sorting. Repeated names
    # retain their original test identity even when their expectations differ.
    awk -F '\t' -v suite="$suite" '
        BEGIN { OFS="\t"; bad=0 }
        NF != 4 || $1 != suite || $2 == "" || $3 !~ /^(check|assert|decision)$/ ||
            ($3 == "decision" && $4 !~ /^(allow|deny)$/) ||
            ($3 != "decision" && $4 !~ /^[0-9]+$/) {
            print "invalid case: " $0 > "/dev/stderr"; bad=1; next
        }
        {
            name=$2
            count[name]++
            if (count[name] > 1) {
                $2=name "#" count[name]
            }
            if (seen[$2]++) {
                print suite ": duplicate inventory key " $2 > "/dev/stderr"
                bad=1
            }
            print
        }
        END {
            for (name in count) if (count[name] > 1)
                print suite ": duplicate " name " (" count[name] " occurrences)" > "/dev/stderr"
            if (bad) exit 1
        }
    ' "$raw" >"$TMP/$suite.numbered" || { FAILED=1; continue; }
    LC_ALL=C sort -t "$(printf '\t')" -k2,2 "$TMP/$suite.numbered" >"$TMP/$suite.tsv"
    dest="$ROOT/testdata/inventory/$suite.tsv"
    if [[ "$MODE" == --write ]]; then
        dest="${SECRET_INVENTORY_DIR:-$ROOT/testdata/inventory}/$suite.tsv"
        mkdir -p "$(dirname "$dest")"
        cp "$TMP/$suite.tsv" "$dest"
        printf '%s: wrote %s cases to %s\n' "$suite" "$(wc -l <"$dest" | tr -d ' ')" "$dest"
    elif [[ ! -f "$dest" ]]; then
        printf '%s: inventory missing, see artifact\n' "$suite" >&2
        if [[ "$suite" != keychain || "${SECRET_INVENTORY_STRICT:-}" == 1 ]]; then FAILED=1; fi
    elif ! diff -u "$dest" "$TMP/$suite.tsv"; then
        printf '%s: inventory differs (missing, changed or added cases); regenerate only after review\n' "$suite" >&2
        FAILED=1
    else
        printf '%s: %s cases match\n' "$suite" "$(wc -l <"$dest" | tr -d ' ')"
    fi
done
exit "$FAILED"
