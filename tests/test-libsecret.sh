#!/usr/bin/env bash
# Exercise real libsecret only against a temporary Secret Service session.
# shellcheck disable=SC2016  # child programs and synthetic dollars are intentionally literal
# The outer invocation owns the disposable HOME and D-Bus session; the inner
# invocation refuses to contact a provider unless those match its launch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" != --session ]]; then
    for tool in dbus-run-session gnome-keyring-daemon secret-tool perl script; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            if [[ "${SECRET_REQUIRE_LIBSECRET:-}" == 1 ]]; then
                printf 'FAIL: %s is required\n' "$tool" >&2
                exit 1
            fi
            printf 'SKIP: %s is not installed\n' "$tool"
            exit 0
        fi
    done
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    mkdir -p "$TMP/home" "$TMP/data" "$TMP/run" "$TMP/config"
    chmod 700 "$TMP/run"
    # Drop the inherited bus, keyring paths, and shell startup hooks.
    env -i PATH="$PATH" HOME="$TMP/home" XDG_DATA_HOME="$TMP/data" \
        XDG_RUNTIME_DIR="$TMP/run" XDG_CONFIG_HOME="$TMP/config" \
        SECRET_TEST_ROOT="$TMP" SECRET_TEST_INVENTORY="${SECRET_TEST_INVENTORY:-}" SECRET_TEST_RESULTS="${SECRET_TEST_RESULTS:-}" SECRET_CLI="${SECRET_CLI:-}" SECRET_REQUIRE_LIBSECRET="${SECRET_REQUIRE_LIBSECRET:-}" \
        dbus-run-session -- bash -c '
            [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] || exit 77
            export SECRET_TEST_BUS="$DBUS_SESSION_BUS_ADDRESS"
            exec bash "$1" --session
        ' test "$ROOT/tests/test-libsecret.sh"
    exit $?
fi

# The address token is set only by the child of the dbus-run-session above.
TMP="${SECRET_TEST_ROOT:-}"
if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" || -z "${SECRET_TEST_BUS:-}" || \
      "$DBUS_SESSION_BUS_ADDRESS" != "$SECRET_TEST_BUS" || -z "$TMP" || \
      "$HOME" != "$TMP/home" || "$XDG_DATA_HOME" != "$TMP/data" || \
      "$XDG_RUNTIME_DIR" != "$TMP/run" || "$XDG_CONFIG_HOME" != "$TMP/config" || \
      ! -d "$TMP/home" || -L "$TMP/home" ]]; then
    printf 'SKIP: isolated session and temporary HOME required\n' >&2
    exit 77
fi
export SECRETS_DIR="$HOME/.secrets" SECRETS_ENV="$HOME/.secrets.env" BASH_ENV='' ENV=''
unset SECRET_BACKEND_STUB_DIR TOKEN OTHER
# Unlock a freshly created, empty-password login keyring on this private bus.
printf '\n' | gnome-keyring-daemon --unlock --components=secrets >"$TMP/daemon-out" 2>"$TMP/daemon-err" || {
    printf 'FAIL: temporary keyring failed to start\n' >&2
    exit 1
}
SECRET="${SECRET_CLI:-$ROOT/bin/secret}"
PASSED=0 FAILED=0

# check NAME STATUS COMMAND: bound each synthetic operation and count its status.
check() {
    local name="$1" want="$2" got=0
    shift 2
    [[ -n "${SECRET_TEST_INVENTORY:-}" ]] && printf '%s\t%s\tcheck\t%s\n' libsecret "$name" "$want" >>"$SECRET_TEST_INVENTORY"
    perl -MPOSIX=setsid -e '$pid=fork(); defined($pid) or exit 124; if (!$pid) { setsid(); exec @ARGV; exit 127 } $SIG{ALRM}=sub { kill "TERM", -$pid; waitpid($pid,0); exit 124 }; alarm 15; waitpid($pid,0); exit($? & 127 ? 128+($? & 127) : $? >> 8)'  "$@" >"$TMP/out" 2>"$TMP/err" || got=$?
    if [[ -n "${SECRET_TEST_RESULTS:-}" ]]; then
        if [[ "$got" == "$want" ]]; then result=pass; else result=fail; fi
        printf '%s\t%s\t%s\n' libsecret "$name" "$result" >>"$SECRET_TEST_RESULTS"
    fi
    if [[ "$got" == "$want" ]]; then PASSED=$((PASSED + 1)); else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: exit %s, expected %s\n' "$name" "$got" "$want"
        if [[ -z "${SECRET_CLI:-}" ]]; then cat "$TMP/err"; fi
    fi
}

# assert NAME COMMAND: count file and output assertions without leaking values.
assert() {
    local name="$1"
    shift
    [[ -n "${SECRET_TEST_INVENTORY:-}" ]] && printf '%s\t%s\tassert\t0\n' libsecret "$name" >>"$SECRET_TEST_INVENTORY"
    if "$@"; then
        [[ -z "${SECRET_TEST_RESULTS:-}" ]] || printf '%s\t%s\tpass\n' libsecret "$name" >>"$SECRET_TEST_RESULTS"
        PASSED=$((PASSED + 1))
    else
        [[ -z "${SECRET_TEST_RESULTS:-}" ]] || printf '%s\t%s\tfail\n' libsecret "$name" >>"$SECRET_TEST_RESULTS"
        FAILED=$((FAILED + 1))
        printf 'FAIL %s\n' "$name"
    fi
}

printf 'synthetic-first\n' >"$TMP/input"
check stash 0 "$SECRET" stash --env dev libsecret:demo TOKEN <"$TMP/input"
account="$(cut -f3 < <(tail -n 1 "$SECRETS_DIR/demo.keys"))"
assert account_format bash -c '[[ "$1" =~ ^[0-9a-f]{32}$ ]]' test "$account"
check show 0 "$SECRET" show libsecret:demo
assert show_mask grep -Fq 'TOKEN [env=dev]=<stored>' "$TMP/out"
assert show_no_value bash -c '! grep -q synthetic "$1"' test "$TMP/out"
check get 0 script -q -e -c "'$SECRET' get --env dev libsecret:demo TOKEN" /dev/null </dev/null
printf 'synthetic-first' >"$TMP/expected"
assert get_bytes perl -e 'open my $a,"<",$ARGV[0] or die; open my $b,"<",$ARGV[1] or die; binmode $a; binmode $b; local $/; my $got=<$a>; my $want=<$b>; exit($got ne "$want\r\n")' "$TMP/out" "$TMP/expected"

# All accepted input forms normalize one optional terminal newline on stash.
for kind in unicode dollar slash equals hash large raw; do
    case "$kind" in
        unicode) printf 'synthetic-\303\251-\346\227\245' >"$TMP/expected" ;;
        dollar) printf '%s' 'synthetic-$TOKEN' >"$TMP/expected" ;;
        slash) printf '%s' 'synthetic-\path\tail' >"$TMP/expected" ;;
        equals) printf '%s' 'synthetic=a=b' >"$TMP/expected" ;;
        hash) printf '%s' 'synthetic#inside' >"$TMP/expected" ;;
        large) perl -e 'print "q" x 4096' >"$TMP/expected" ;;
        raw) printf '%s' 'synthetic-without-newline' >"$TMP/expected" ;;
    esac
    cp "$TMP/expected" "$TMP/input"
    if [[ "$kind" != raw ]]; then printf '\n' >>"$TMP/input"; fi
    check "stash_$kind" 0 "$SECRET" stash --env dev libsecret:demo TOKEN <"$TMP/input"
    assert "reused_$kind" test "$(cut -f3 < <(tail -n 1 "$SECRETS_DIR/demo.keys"))" = "$account"
    check "lookup_$kind" 0 secret-tool lookup service secret/demo account "$account"
    assert "lookup_bytes_$kind" cmp -s "$TMP/out" "$TMP/expected"
    check "run_$kind" 0 "$SECRET" run -f libsecret:demo --env dev --key TOKEN -- \
        bash -c 'printf %s "$TOKEN" >"$1"' test "$TMP/actual"
    assert "roundtrip_$kind" cmp -s "$TMP/expected" "$TMP/actual"
    check "get_$kind" 0 script -q -e -c "'$SECRET' get --env dev libsecret:demo TOKEN" /dev/null </dev/null
    assert "get_bytes_$kind" perl -e 'open my $a,"<",$ARGV[0] or die; open my $b,"<",$ARGV[1] or die; binmode $a; binmode $b; local $/; my $got=<$a>; my $want=<$b>; exit($got ne "$want\r\n")' "$TMP/out" "$TMP/expected"
done

for invalid in ' synthetic-space' 'synthetic-space ' '"synthetic-quote"' "'synthetic-quote'"; do
    printf '%s' "$invalid" >"$TMP/input"
    check rejected_value 1 "$SECRET" stash libsecret:demo INVALID <"$TMP/input"
    assert rejected_before_store bash -c '! grep -q "^INVALID[[:space:]]" "$1"' test "$SECRETS_DIR/demo.keys"
done

printf 'synthetic-prod-value' >"$TMP/input"
check prod_stash 0 "$SECRET" stash --env prod libsecret:demo TOKEN <"$TMP/input"
check labels 0 "$SECRET" run -f libsecret:demo --env dev --key TOKEN -- \
    bash -c 'printf "%s|synthetic-prod-value|%s" "$TOKEN" "${OTHER-unset}"'
assert redacts_unselected grep -Fxq '<redacted>|<redacted>|unset' "$TMP/out"
check selected_show 0 "$SECRET" show --env prod libsecret:demo
assert selected_mask grep -Fq 'TOKEN [env=prod]=<stored>' "$TMP/out"

# A different service with the same account must not satisfy this manifest.
check clear 0 secret-tool clear service secret/demo account "$account"
check deleted 1 "$SECRET" run -f libsecret:demo --env dev -- touch "$TMP/child-ran"
assert deleted_no_child test ! -e "$TMP/child-ran"
assert deleted_message grep -Fq 'backend lookup failed' "$TMP/err"
printf 'synthetic-wrong-service' >"$TMP/input"
check other_service 0 secret-tool store --label='synthetic other service' \
    service secret/other account "$account" <"$TMP/input"
check exact_service 1 "$SECRET" run -f libsecret:demo --env dev -- \
    touch "$TMP/child-ran"
assert no_child test ! -e "$TMP/child-ran"
assert lookup_failed grep -Fq 'backend lookup failed' "$TMP/err"
assert value_not_logged bash -c '! grep -q synthetic "$1"' test "$TMP/err"

printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
((FAILED == 0))
