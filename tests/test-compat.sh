#!/usr/bin/env bash
# Retained Bash identity and independence from the final Go launcher.
# BASH_BIN=/bin/bash forces stock Bash 3.2 on macOS, including the CLI child.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUNTIME="$(command -v "${BASH_BIN:-$BASH}")"
[[ "$RUNTIME" == /* && -x "$RUNTIME" ]]
# Last Bash bin/secret blob at 5309977, pinned without requiring full Git history.
EXPECTED=529a7dd7f2fa3d1bc8cfb69339baa6b1832f58a8
[[ -f "$ROOT/compat/secret" && ! -L "$ROOT/compat/secret" && -x "$ROOT/compat/secret" ]]
[[ "$(git -C "$ROOT" hash-object compat/secret)" == "$EXPECTED" ]]
[[ "$(git -C "$ROOT" ls-files --stage compat/secret)" == "100755 $EXPECTED "* ]]
TMP="$(mktemp -d)"
TMP="$(cd -P "$TMP" && pwd -P)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/checkout/compat" "$TMP/checkout/bin" "$TMP/checkout/tests" "$TMP/checkout/testdata/inventory" "$TMP/checkout/examples"
cp "$ROOT/examples/ripgreprc" "$TMP/checkout/examples/ripgreprc"
cp "$ROOT/compat/secret" "$TMP/checkout/compat/secret"
cp "$ROOT/bin/secret" "$TMP/checkout/bin/secret"
cp "$ROOT/tests/test-secret.sh" "$ROOT/tests/test-backends.sh" "$ROOT/tests/inventory.sh" "$TMP/checkout/tests/"
cp "$ROOT"/testdata/inventory/secret*.tsv "$ROOT"/testdata/inventory/backends*.tsv "$TMP/checkout/testdata/inventory/"
chmod +x "$TMP/checkout/compat/secret" "$TMP/checkout/bin/secret"
cmp "$ROOT/compat/secret" "$TMP/checkout/compat/secret"
ln -s "$TMP/checkout" "$TMP/checkout-link"
# Catch SECRET_CLI bypassing the forced interpreter, even if both Bash versions
# happen to produce identical results. Other synthetic helpers may use env bash.
mkdir "$TMP/tools"
cat >"$TMP/tools/bash" <<EOF
#!/bin/sh
if [ "\$1" = "$TMP/checkout/compat/secret" ]; then
    printf 'FAIL: compatibility CLI selected Bash through PATH\\n' >&2
    exit 98
fi
exec "$RUNTIME" "\$@"
EOF
chmod +x "$TMP/tools/bash"
export PATH="$TMP/tools:$PATH"
for phase in original broken; do
    if [[ "$phase" == broken ]]; then
        # A launcher that always fails must not change even one baseline case.
        printf '#!/bin/sh\nexit 70\n' >"$TMP/checkout/bin/secret"
    fi
    for suite in secret backends; do
        SECRET_CLI="$TMP/checkout-link/compat/secret" \
            SECRET_TEST_RESULTS="$TMP/$phase-$suite.results" \
            SECRET_TEST_INVENTORY="$TMP/$phase-$suite.inventory" \
            "$RUNTIME" "$TMP/checkout/tests/test-$suite.sh"
        BASH_BIN="$RUNTIME" "$RUNTIME" "$TMP/checkout/tests/inventory.sh" --check --suite "$suite"
        if [[ "$phase" == broken ]]; then
            cmp "$TMP/original-$suite.results" "$TMP/broken-$suite.results"
            cmp "$TMP/original-$suite.inventory" "$TMP/broken-$suite.inventory"
        fi
    done
done
printf 'PASS: Bash blob, executable identity, forced interpreter and broken-launcher isolation\n'
