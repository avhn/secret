#!/usr/bin/env bash
# Exercise macOS Keychain only against a disposable, explicitly selected keychain.
# shellcheck disable=SC2016  # child programs and synthetic dollars are intentionally literal
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    if [[ "${SECRET_REQUIRE_KEYCHAIN:-}" == 1 ]]; then
        printf 'FAIL: macOS is required for Keychain tests\n' >&2
        exit 1
    fi
    printf 'SKIP: macOS Keychain is unavailable\n'
    exit 0
fi
for tool in security perl script ps; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        if [[ "${SECRET_REQUIRE_KEYCHAIN:-}" == 1 ]]; then
            printf 'FAIL: %s is required\n' "$tool" >&2
            exit 1
        fi
        printf 'SKIP: %s is unavailable\n' "$tool"
        exit 0
    fi
done
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
SAMPLER=""
cleanup() {
    if [[ -n "$SAMPLER" ]]; then kill "$SAMPLER" 2>/dev/null || true; wait "$SAMPLER" 2>/dev/null || true; fi
    security delete-keychain "$SECRET_KEYCHAIN" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
export SECRET_KEYCHAIN="$TMP/disposable.keychain-db"
trap cleanup EXIT
# No search-list or default-keychain changes; every lookup and put names this file.
security create-keychain -p synthetic-test-pass "$SECRET_KEYCHAIN" >/dev/null 2>&1 || { printf 'FAIL: cannot create disposable keychain\n' >&2; exit 1; }
security unlock-keychain -p synthetic-test-pass "$SECRET_KEYCHAIN" >/dev/null 2>&1 || { printf 'FAIL: cannot unlock disposable keychain\n' >&2; exit 1; }
security set-keychain-settings "$SECRET_KEYCHAIN" >/dev/null 2>&1 || { printf 'FAIL: cannot disable disposable keychain timeout\n' >&2; exit 1; }
export HOME="$TMP/home" SECRETS_DIR="$TMP/home/.secrets" SECRETS_ENV="$TMP/home/.secrets.env" BASH_ENV='' ENV=''
unset SECRET_BACKEND_STUB_DIR TOKEN OTHER
mkdir -p "$HOME"
SECRET="${SECRET_CLI:-$ROOT/compat/secret}"
SECRET="$(cd -P "$(dirname "$SECRET")" && pwd -P)/${SECRET##*/}"
if [[ "$SECRET" -ef "$ROOT/compat/secret" ]]; then
    cat >"$TMP/secret-cli" <<EOF
#!$BASH
exec "$BASH" "$ROOT/compat/secret" "\$@"
EOF
    chmod +x "$TMP/secret-cli"
    SECRET="$TMP/secret-cli"
fi
PASSED=0 FAILED=0
check() {
    local name="$1" want="$2" got=0
    shift 2
    [[ -n "${SECRET_TEST_INVENTORY:-}" ]] && printf '%s\t%s\tcheck\t%s\n' keychain "$name" "$want" >>"$SECRET_TEST_INVENTORY"
    perl -MPOSIX=setsid -e '$pid=fork(); defined($pid) or exit 124; if (!$pid) { setsid(); exec @ARGV; exit 127 } $SIG{ALRM}=sub { kill "TERM", -$pid; waitpid($pid,0); exit 124 }; alarm 20; waitpid($pid,0); exit($? & 127 ? 128+($? & 127) : $? >> 8)'  "$@" >"$TMP/out" 2>"$TMP/err" || got=$?
    if [[ -n "${SECRET_TEST_RESULTS:-}" ]]; then
        if [[ "$got" == "$want" ]]; then result=pass; else result=fail; fi
        printf '%s\t%s\t%s\n' keychain "$name" "$result" >>"$SECRET_TEST_RESULTS"
    fi
    if [[ "$got" == "$want" ]]; then PASSED=$((PASSED + 1)); else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: exit %s, expected %s\n' "$name" "$got" "$want"
        # Provider errors are suppressed; diagnostics must never include a value.
        if [[ -z "${SECRET_CLI:-}" ]]; then cat "$TMP/err"; fi
    fi
}
assert() {
    local name="$1"
    shift
    [[ -n "${SECRET_TEST_INVENTORY:-}" ]] && printf '%s\t%s\tassert\t0\n' keychain "$name" >>"$SECRET_TEST_INVENTORY"
    if "$@"; then
        [[ -z "${SECRET_TEST_RESULTS:-}" ]] || printf '%s\t%s\tpass\n' keychain "$name" >>"$SECRET_TEST_RESULTS"
        PASSED=$((PASSED + 1))
    else
        [[ -z "${SECRET_TEST_RESULTS:-}" ]] || printf '%s\t%s\tfail\n' keychain "$name" >>"$SECRET_TEST_RESULTS"
        FAILED=$((FAILED + 1))
        printf 'FAIL %s\n' "$name"
    fi
}

printf 'synthetic-first\n' >"$TMP/input"
check stash 0 "$SECRET" stash --env dev keychain:demo TOKEN <"$TMP/input"
account="$(cut -f3 < <(tail -n 1 "$SECRETS_DIR/demo.keys"))"
assert account_format bash -c '[[ "$1" =~ ^[0-9a-f]{32}$ ]]' test "$account"
check show 0 "$SECRET" show keychain:demo
assert show_mask grep -Fq 'TOKEN [env=dev]=<stored>' "$TMP/out"
assert show_no_value bash -c '! grep -q synthetic "$1"' test "$TMP/out"
check list 0 "$SECRET" list
assert list_ref grep -Fxq keychain:demo "$TMP/out"

# -X over security -i must preserve every accepted byte, not just shell-safe text.
for kind in unicode dollar slash equals hash quote double_quote space large raw; do
    case "$kind" in
        unicode) printf 'synthetic-\303\251-\346\227\245' >"$TMP/expected" ;;
        dollar) printf '%s' 'synthetic-$TOKEN' >"$TMP/expected" ;;
        slash) printf '%s' 'synthetic-\path\tail' >"$TMP/expected" ;;
        equals) printf '%s' 'synthetic=a=b' >"$TMP/expected" ;;
        hash) printf '%s' 'synthetic#inside' >"$TMP/expected" ;;
        quote) printf '%s' "synthetic'quoted" >"$TMP/expected" ;;
        double_quote) printf '%s' 'synthetic"quoted' >"$TMP/expected" ;;
        space) printf '%s' 'synthetic space inside' >"$TMP/expected" ;;
        large) perl -e 'print "q" x 1700' >"$TMP/expected" ;;
        raw) printf '%s' 'synthetic-without-newline' >"$TMP/expected" ;;
    esac
    cp "$TMP/expected" "$TMP/input"
    if [[ "$kind" != raw ]]; then printf '\n' >>"$TMP/input"; fi
    check "stash_$kind" 0 "$SECRET" stash --env dev keychain:demo TOKEN <"$TMP/input"
    assert "reused_$kind" test "$(cut -f3 < <(tail -n 1 "$SECRETS_DIR/demo.keys"))" = "$account"
    # security -w prints non-ASCII passwords as bare hex; secret reads -g instead.
    check "lookup_$kind" 0 security find-generic-password -s secret/demo -a "$account" -w "$SECRET_KEYCHAIN"
    assert "lookup_bytes_$kind" perl -e 'open my $a,"<",$ARGV[0] or die; open my $b,"<",$ARGV[1] or die; binmode $a; binmode $b; local $/; my $got=<$a>; my $want=<$b>; if ($want =~ /[^\x20-\x7e]/) { $want = unpack("H*", $want); $got = lc $got } exit($got ne "$want\n")' "$TMP/out" "$TMP/expected"
    check "run_$kind" 0 "$SECRET" run -f keychain:demo --env dev --key TOKEN -- \
        bash -c 'printf %s "$TOKEN" >"$1"' test "$TMP/actual"
    assert "roundtrip_$kind" cmp -s "$TMP/expected" "$TMP/actual"
    check "get_$kind" 0 script -q "$TMP/tty" "$SECRET" get --env dev keychain:demo TOKEN </dev/null
    assert "get_bytes_$kind" perl -e 'open my $a,"<",$ARGV[0] or die; open my $b,"<",$ARGV[1] or die; binmode $a; binmode $b; local $/; my $got=<$a>; my $want=<$b>; exit(index($got,"$want\r\n") < 0)' "$TMP/tty" "$TMP/expected"
done

for invalid in ' synthetic-space' 'synthetic-space ' '"synthetic-quote"' "'synthetic-quote'"; do
    printf '%s' "$invalid" >"$TMP/input"
    check rejected_value 1 "$SECRET" stash keychain:demo INVALID <"$TMP/input"
    assert rejected_before_store bash -c '! grep -q "^INVALID[[:space:]]" "$1"' test "$SECRETS_DIR/demo.keys"
done
# The provider's text read API is not a byte transport for controls or malformed UTF-8.
printf 'synthetic\tinternal' >"$TMP/input"
check rejected_control 1 "$SECRET" stash keychain:demo INVALID <"$TMP/input"
assert control_not_published bash -c '! grep -q "^INVALID[[:space:]]" "$1"' test "$SECRETS_DIR/demo.keys"
printf '\377synthetic' >"$TMP/input"
check rejected_utf8 1 "$SECRET" stash keychain:demo INVALID <"$TMP/input"
assert utf8_not_published bash -c '! grep -q "^INVALID[[:space:]]" "$1"' test "$SECRETS_DIR/demo.keys"
printf 'synthetic\302\205internal' >"$TMP/input"
check rejected_unicode_control 1 "$SECRET" stash keychain:demo INVALID <"$TMP/input"
assert unicode_control_not_published bash -c '! grep -q "^INVALID[[:space:]]" "$1"' test "$SECRETS_DIR/demo.keys"
perl -e 'print "q" x 4096' >"$TMP/input"
check rejected_oversize 1 "$SECRET" stash keychain:demo INVALID <"$TMP/input"
assert oversize_message grep -q 'limited to about 1800 bytes' "$TMP/err"
assert oversize_not_published bash -c '! grep -q "^INVALID[[:space:]]" "$1"' test "$SECRETS_DIR/demo.keys"

# No secret appears in any process arguments, even while security -i is active.
perl -e 'print "synthetic-argv-", "A" x 96, "-END"' >"$TMP/expected"
cp "$TMP/expected" "$TMP/input"
: >"$TMP/ps"
( while :; do ps -axww -o args= >>"$TMP/ps"; done ) &
SAMPLER=$!
for iteration in 1 2 3 4 5 6 7 8; do
    check "argv_stash_$iteration" 0 "$SECRET" stash --env dev keychain:demo TOKEN <"$TMP/input"
done
# A fast CLI can finish between samples; keep stashing until the sampler sees security -i.
retry=0
while ! grep -Fq 'security -i' "$TMP/ps" && [ "$retry" -lt 40 ]; do
    "$SECRET" stash --env dev keychain:demo TOKEN <"$TMP/input" >/dev/null 2>&1 || true
    retry=$((retry + 1))
done
kill "$SAMPLER" 2>/dev/null || true
wait "$SAMPLER" 2>/dev/null || true
SAMPLER=""
assert sampled_processes grep -Fq 'security -i' "$TMP/ps"
assert value_absent_from_argv perl -e 'open my $a,"<",$ARGV[0] or die; open my $b,"<",$ARGV[1] or die; local $/; my $needle=<$a>; my $hay=<$b>; exit(index($hay,$needle)>=0)' "$TMP/expected" "$TMP/ps"

printf 'synthetic-prod-value' >"$TMP/input"
check prod_stash 0 "$SECRET" stash --env prod keychain:demo TOKEN <"$TMP/input"
check labels 0 "$SECRET" run -f keychain:demo --env dev --key TOKEN -- \
    bash -c 'printf "%s|synthetic-prod-value|%s" "$TOKEN" "${OTHER-unset}"'
assert redacts_unselected grep -Fxq '<redacted>|<redacted>|unset' "$TMP/out"
check selected_show 0 "$SECRET" show --env prod keychain:demo
assert selected_mask grep -Fq 'TOKEN [env=prod]=<stored>' "$TMP/out"

# Out-of-band deletion and a different service with the same account fail closed.
check clear 0 security delete-generic-password -s secret/demo -a "$account" "$SECRET_KEYCHAIN"
check deleted 1 "$SECRET" run -f keychain:demo --env dev -- touch "$TMP/child-ran"
assert deleted_no_child test ! -e "$TMP/child-ran"
assert deleted_message grep -Fq 'backend lookup failed' "$TMP/err"
printf 'synthetic-wrong-service' >"$TMP/input"
# The wrong-service item is created through the same stdin-only -X transport.
perl - "$TMP/input" "$account" "$SECRET_KEYCHAIN" <<'PERL' | security -i >"$TMP/provider-out" 2>"$TMP/provider-err"
use strict; use warnings;
open my $f, '<', $ARGV[0] or die; binmode $f; local $/; my $value=<$f>;
print 'add-generic-password -s secret/other -a ', $ARGV[1],
    ' -l synthetic-other -X ', unpack('H*', $value), ' ', $ARGV[2], "\n";
PERL
check other_service_lookup 0 security find-generic-password -s secret/other -a "$account" -w "$SECRET_KEYCHAIN"
assert other_service_bytes perl -e 'open my $a,"<",$ARGV[0] or die; open my $b,"<",$ARGV[1] or die; binmode $a; binmode $b; local $/; my $got=<$a>; my $want=<$b>; exit($got ne "$want\n")' "$TMP/out" "$TMP/input"
check exact_service 1 "$SECRET" run -f keychain:demo --env dev -- touch "$TMP/child-ran"
assert no_child test ! -e "$TMP/child-ran"
assert lookup_failed grep -Fq 'backend lookup failed' "$TMP/err"
assert value_not_logged bash -c '! grep -q synthetic "$1"' test "$TMP/err"
printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
((FAILED == 0))
