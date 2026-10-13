#!/usr/bin/env bash
# Synthetic keystore dispatch regression suite; no host keystore is accessed.
# shellcheck disable=SC2016  # child fixture scripts contain literal dollars
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP/home" SECRETS_DIR="$TMP/home/.secrets" SECRETS_ENV="$TMP/home/.secrets.env"
export SECRET_BACKEND_STUB_DIR="$TMP/stub" CLIPBOARD="$TMP/clipboard" BASH_ENV='' ENV=''
mkdir -p "$HOME" "$SECRET_BACKEND_STUB_DIR" "$TMP/bin" "$TMP/cwd"
export PATH="$TMP/bin:$PATH"
cd "$TMP/cwd"
SECRET="$ROOT/bin/secret"
PASSED=0 FAILED=0

# check NAME STATUS CMD: run a bounded CLI invocation and compare its status.
check() {
    local name="$1" want="$2" got=0
    shift 2
    perl -e 'alarm 10; exec @ARGV' "$@" >"$TMP/out" 2>"$TMP/err" || got=$?
    if [[ "$got" == "$want" ]]; then PASSED=$((PASSED + 1)); else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: exit %s, expected %s\n' "$name" "$got" "$want"
        cat "$TMP/err"
    fi
}

# assert NAME CMD: count focused output and filesystem assertions.
assert() {
    local name="$1"
    shift
    if "$@"; then PASSED=$((PASSED + 1)); else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s\n' "$name"
    fi
}

# invoke ARGS: run the CLI under the selected Bash interpreter.
invoke() { "$BASH" "$SECRET" "$@"; }
printf 'synthetic-dev\n' >"$TMP/input"
check stash 0 "$BASH" "$SECRET" stash --env dev keychain:demo TOKEN <"$TMP/input"
manifest="$SECRETS_DIR/demo.keys"
assert manifest_mode test "$(perl -e 'printf "%04o", (stat $ARGV[0])[2] & 07777' "$manifest")" = 0600
assert manifest_header grep -q '^secret-manifest-v1$' "$manifest"
assert manifest_backend grep -q '^backend=keychain$' "$manifest"
assert manifest_format perl -e 'my @l=<>; exit !(@l==3 && $l[2]=~/^TOKEN\tenv=dev\t[0-9a-f]{32}\n$/)' "$manifest"
assert no_manifest_value bash -c '! grep -q synthetic "$1"' test "$manifest"
account="$(cut -f3 < <(tail -n 1 "$manifest"))"
assert backend_value grep -qx synthetic-dev "$SECRET_BACKEND_STUB_DIR/keychain/secret/demo/$account"
printf 'synthetic-new\n' >"$TMP/input"
check reuse 0 "$BASH" "$SECRET" stash --env dev keychain:demo TOKEN <"$TMP/input"
assert reused_id test "$(cut -f3 < <(tail -n 1 "$manifest"))" = "$account"
assert updated_backend grep -qx synthetic-new "$SECRET_BACKEND_STUB_DIR/keychain/secret/demo/$account"
check list 0 "$BASH" "$SECRET" list
assert list_ref grep -qx keychain:demo "$TMP/out"
: >"$SECRET_BACKEND_STUB_DIR/log"
check list_without_backend 0 "$BASH" "$SECRET" list
check show 0 "$BASH" "$SECRET" show keychain:demo
assert show_mask grep -Fq 'TOKEN [env=dev]=<stored>' "$TMP/out"
check selected_show 0 "$BASH" "$SECRET" show --env prod keychain:demo
assert show_unset grep -Fq 'TOKEN=<unset>' "$TMP/out"
assert no_backend_calls test ! -s "$SECRET_BACKEND_STUB_DIR/log"
printf 'synthetic-prod\n' >"$TMP/input"
check prod_stash 0 "$BASH" "$SECRET" stash --env prod keychain:demo TOKEN <"$TMP/input"
printf 'synthetic-base\n' >"$TMP/input"
check base_stash 0 "$BASH" "$SECRET" stash keychain:demo BASE <"$TMP/input"
: >"$SECRET_BACKEND_STUB_DIR/log"
check run_redacts_unselected 0 "$BASH" "$SECRET" run -f keychain:demo --env dev --key TOKEN -- "$BASH" -c 'printf "%s|synthetic-prod|%s" "$TOKEN" "${BASE-unset}"'
assert redaction grep -Fxq '<redacted>|<redacted>|unset' "$TMP/out"
assert loads_all test "$(grep -c '^get ' "$SECRET_BACKEND_STUB_DIR/log")" -ge 3
cat >"$TMP/bin/pbcopy" <<'EOF'
#!/usr/bin/env bash
cat >"$CLIPBOARD"
EOF
cat >"$TMP/bin/pbpaste" <<'EOF'
#!/usr/bin/env bash
cat "$CLIPBOARD"
EOF
chmod +x "$TMP/bin/pbcopy" "$TMP/bin/pbpaste"
: >"$SECRET_BACKEND_STUB_DIR/log"
check clip_stub 0 "$BASH" "$SECRET" clip --env prod keychain:demo TOKEN 2
assert clipboard_bytes grep -qx synthetic-prod "$CLIPBOARD"
assert clip_stub_single test "$(grep -c '^get ' "$SECRET_BACKEND_STUB_DIR/log")" -eq 1
if [[ "$OSTYPE" == darwin* ]]; then
    : >"$SECRET_BACKEND_STUB_DIR/log"
    check get_tty 0 script -q "$TMP/tty" "$BASH" "$SECRET" get --env dev keychain:demo TOKEN </dev/null
else
    : >"$SECRET_BACKEND_STUB_DIR/log"
    check get_tty 0 script -q -c "'$BASH' '$SECRET' get --env dev keychain:demo TOKEN" "$TMP/tty" </dev/null
fi
assert get_value grep -Fq synthetic-new "$TMP/tty"
assert get_single test "$(grep -c '^get ' "$SECRET_BACKEND_STUB_DIR/log")" -eq 1
: >"$SECRET_BACKEND_STUB_DIR/log"
check lookup_failure 1 env SECRET_BACKEND_STUB_GET_FAIL=1 "$BASH" "$SECRET" run -f keychain:demo -- touch "$TMP/child-ran"
assert no_child test ! -e "$TMP/child-ran"
assert failed_lookup grep -q 'backend lookup failed' "$TMP/err"
assert failed_lookup_logged grep -q '^get ' "$SECRET_BACKEND_STUB_DIR/log"
printf 'tampered\nbytes' >"$SECRET_BACKEND_STUB_DIR/keychain/secret/demo/$account"
check invalid_backend_bytes 1 "$BASH" "$SECRET" run -f keychain:demo -- touch "$TMP/child-ran"
assert invalid_no_child test ! -e "$TMP/child-ran"
assert invalid_lookup_message grep -q 'backend lookup failed' "$TMP/err"
printf 'synthetic-new' >"$SECRET_BACKEND_STUB_DIR/keychain/secret/demo/$account"
printf 'synthetic-failure\n' >"$TMP/input"
check put_failure 1 env SECRET_BACKEND_STUB_PUT_FAIL=1 "$BASH" "$SECRET" stash libsecret:other FAIL <"$TMP/input"
assert no_manifest test ! -e "$SECRETS_DIR/other.keys"
check manifest_failure 1 env SECRET_BACKEND_STUB_MANIFEST_FAIL=1 "$BASH" "$SECRET" stash libsecret:other FAIL <"$TMP/input"
assert no_published_record test ! -e "$SECRETS_DIR/other.keys"
assert orphan_exists test "$(find "$SECRET_BACKEND_STUB_DIR/libsecret/secret/other" -type f | wc -l)" -eq 1
check recovery 0 "$BASH" "$SECRET" stash libsecret:other FAIL <"$TMP/input"
assert backend_declaration grep -qx backend=libsecret < <(sed -n '2p' "$SECRETS_DIR/other.keys")
printf 'synthetic-orphan\n' >"$TMP/input"
check failed_publish_existing 1 env SECRET_BACKEND_STUB_MANIFEST_FAIL=1 "$BASH" "$SECRET" stash libsecret:other NEW <"$TMP/input"
assert prior_record_intact test "$(grep -c '^FAIL[[:space:]]' "$SECRETS_DIR/other.keys")" -eq 1
assert new_record_unpublished bash -c '! grep -q "^NEW[[:space:]]" "$1"' test "$SECRETS_DIR/other.keys"
assert orphan_after_existing test "$(find "$SECRET_BACKEND_STUB_DIR/libsecret/secret/other" -type f | wc -l)" -eq 3
check mismatch 1 "$BASH" "$SECRET" show keychain:other
assert mismatch_message grep -q 'mismatch' "$TMP/err"
check mismatch_run 1 "$BASH" "$SECRET" run -f keychain:other -- touch "$TMP/child-ran"
assert mismatch_no_child test ! -e "$TMP/child-ran"
printf 'FILEKEY=synthetic-file\n' >"$TMP/literal"
check file_escape 0 "$BASH" "$SECRET" show "file:$TMP/literal"
assert file_mask grep -q 'FILEKEY=<14 bytes>' "$TMP/out"
printf 'COLON=synthetic-colon\n' >"$TMP/cwd/keychain:literal"
check escaped_colon 0 "$BASH" "$SECRET" show file:keychain:literal
assert escaped_colon_mask grep -q 'COLON=<15 bytes>' "$TMP/out"
printf 'synthetic-escaped\n' >"$TMP/input"
check escaped_colon_stash 0 "$BASH" "$SECRET" stash file:keychain:literal COLON <"$TMP/input"
assert escaped_colon_file grep -q '^COLON=synthetic-escaped$' "$TMP/cwd/keychain:literal"
check invalid_backend_name 1 "$BASH" "$SECRET" show keychain:../outside
assert invalid_name_message grep -q 'invalid keystore name' "$TMP/err"
printf 'BARE=synthetic-bare\n' >"$SECRETS_DIR/plain.secret"
check bare_name 0 "$BASH" "$SECRET" show plain
assert bare_file_mask grep -q 'BARE=<14 bytes>' "$TMP/out"
check unsupported 1 env -u SECRET_BACKEND_STUB_DIR "$BASH" "$SECRET" run -f keychain:demo -- true
assert unsupported_message grep -q 'backend not yet supported' "$TMP/err"
printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
((FAILED == 0))
