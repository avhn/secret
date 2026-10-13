#!/usr/bin/env bash
#
# Synthetic secret transport regression matrix. Never uses host stores or the
# real clipboard: disposable HOME, explicit stores, and stub clipboard tools.
# Usage: bash tests/test-secret.sh (also run with stock /bin/bash on macOS).
# shellcheck disable=SC2016  # fixtures and child programs deliberately contain literal dollars
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP/home" SECRETS_DIR="$TMP/home/.secrets" SECRETS_ENV="$TMP/home/.secrets.env"
export BASH_ENV='' ENV='' CLIPBOARD="$TMP/clipboard"
# Never let inherited host variables named like fixtures change a result.
unset KEY TOKEN SECOND ALPHA BETA OPTIONAL MISSING EMPTY ONE TWO SHORT THREE LONG META WORK KEYS key
mkdir -p "$HOME" "$TMP/bin" "$TMP/cwd"
export PATH="$TMP/bin:$PATH"
cd "$TMP/cwd"
SECRET="$ROOT/bin/secret"
PASSED=0 FAILED=0

# check NAME STATUS CMD: bound calls and retain synthetic diagnostics on failure.
check() {
    local name="$1" want="$2" got=0
    shift 2
    perl -e 'alarm 10; exec @ARGV' "$@" >"$TMP/out" 2>"$TMP/err" || got=$?
    if [[ "$got" == "$want" ]]; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: exit %s, expected %s\n' "$name" "$got" "$want"
        cat "$TMP/err"
    fi
}

# assert NAME CMD: record byte/content assertions without stopping the matrix.
assert() {
    local name="$1"
    shift
    if "$@"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s\n' "$name"
    fi
}

# invoke ARGS: always use the interpreter under test, not the script's shebang.
invoke() { "$BASH" "$SECRET" "$@"; }

cat >"$TMP/bin/pbcopy" <<'EOF'
#!/usr/bin/env bash
cat >"$CLIPBOARD"
EOF
cat >"$TMP/bin/pbpaste" <<'EOF'
#!/usr/bin/env bash
cat "$CLIPBOARD"
EOF
chmod +x "$TMP/bin/pbcopy" "$TMP/bin/pbpaste"

check empty_list 0 "$BASH" "$SECRET" list
assert empty_list_bytes test ! -s "$TMP/out"
check empty_show 0 "$BASH" "$SECRET" show
assert empty_message grep -q 'no secret stores' "$TMP/out"
check help 0 "$BASH" "$SECRET" --help
check missing 1 "$BASH" "$SECRET" show absent
check unknown 1 "$BASH" "$SECRET" invalid
check run_no_files 1 "$BASH" "$SECRET" run -- true
check run_no_separator 1 "$BASH" "$SECRET" run -f absent true

mkdir -p "$SECRETS_DIR/.directory.secret"
printf 'KEY=synthetic-bytes-[]$x\n' >"$SECRETS_DIR/.hidden.secret"
printf 'KEY=ignored-backup\n' >"$SECRETS_DIR/backup.secret~"
printf 'KEY=visible\n' >"$SECRETS_DIR/visible.secret"
printf 'TOKEN=synthetic-token\n' >"$SECRETS_ENV"
check discovery 0 "$BASH" "$SECRET" list
assert hidden_found grep -q '/.hidden.secret$' "$TMP/out"
assert backups_absent bash -c '! grep -q "backup\|directory" "$1"' test "$TMP/out"
check hidden_resolve 0 "$BASH" "$SECRET" show hidden
assert masked grep -q 'KEY=<20 bytes>' "$TMP/out"
assert values_absent bash -c '! grep -q "synthetic-bytes" "$1"' test "$TMP/out"

cat >"$TMP/legacy.store" <<'EOF'
# comment
export ALPHA="first-value"
if condition; then
ALPHA='last-value'
fi
export ALPHA
BROKEN="unterminated
BETA=legacy with spaces
EOF
check legacy_show 0 "$BASH" "$SECRET" show "$TMP/legacy.store"
assert duplicate_warning grep -q 'duplicate ALPHA (lines: 2,4)' "$TMP/err"
assert ignored_lines grep -q '4 non-assignment lines ignored (lines: 3,5,6,7)' "$TMP/err"
assert masked_legacy grep -q 'ALPHA=<10 bytes>' "$TMP/out"
check legacy_exec 0 "$BASH" "$SECRET" exec -f "$TMP/legacy.store" --key ALPHA -- "$BASH" -c '[[ "$ALPHA" == last-value && -z "${BETA+x}" ]]'

printf 'ALPHA=override-value\nOPTIONAL=optional-value\n' >"$TMP/override.store"
check later_wins 0 "$BASH" "$SECRET" exec -f "$TMP/legacy.store" -f "$TMP/override.store" --key ALPHA --optional-key MISSING -- "$BASH" -c '[[ "$ALPHA" == override-value && -z "${OPTIONAL+x}" && -z "${MISSING+x}" ]]'
check required_absent 1 "$BASH" "$SECRET" run -f "$TMP/override.store" --key MISSING -- true
printf 'EMPTY=\n' >"$TMP/empty.store"
check required_empty 1 "$BASH" "$SECRET" exec -f "$TMP/empty.store" --key EMPTY -- true
check optional_present 0 "$BASH" "$SECRET" exec -f "$TMP/override.store" --optional-key OPTIONAL -- "$BASH" -c '[[ "$OPTIONAL" == optional-value ]]'
export OPTIONAL=ambient-leak
check ambient_unselected 0 "$BASH" "$SECRET" exec -f "$TMP/override.store" --key ALPHA -- "$BASH" -c '[[ -z "${OPTIONAL+x}" ]]'
unset OPTIONAL
printf 'WORK=synthetic-work\nKEYS=synthetic-array\nkey=synthetic-lower\n' >"$TMP/internal-names.store"
check transport_name_collision 0 "$BASH" "$SECRET" exec -f "$TMP/internal-names.store" -- perl -e 'exit($ENV{WORK} eq "synthetic-work" && $ENV{KEYS} eq "synthetic-array" && $ENV{key} eq "synthetic-lower" ? 0 : 1)'

printf 'byte-safe-[]$x' >"$TMP/input"
check stash_eof 0 "$BASH" "$SECRET" stash "$TMP/bytes.store" KEY <"$TMP/input"
printf 'byte-safe-[]$x\n' >"$TMP/expected"
check exec_bytes 0 "$BASH" "$SECRET" exec -f "$TMP/bytes.store" -- "$BASH" -c 'printf "%s\n" "$KEY"'
assert exec_byte_equality cmp -s "$TMP/out" "$TMP/expected"
printf 'next-value\n' >"$TMP/input"
check stash_lf 0 "$BASH" "$SECRET" stash "$TMP/bytes.store" SECOND <"$TMP/input"
cp "$TMP/bytes.store" "$TMP/before"
for kind in empty leading trailing quotes singlequotes embedded nul cr doublelf; do
    case "$kind" in
        empty) : >"$TMP/input" ;;
        leading) printf ' leading' >"$TMP/input" ;;
        trailing) printf 'trailing ' >"$TMP/input" ;;
        quotes) printf '"quoted"' >"$TMP/input" ;;
        singlequotes) printf "'quoted'" >"$TMP/input" ;;
        embedded) printf 'one\ntwo' >"$TMP/input" ;;
        nul) printf 'one\000two' >"$TMP/input" ;;
        cr) printf 'one\r' >"$TMP/input" ;;
        doublelf) printf 'one\n\n' >"$TMP/input" ;;
    esac
    check "reject_$kind" 1 "$BASH" "$SECRET" stash "$TMP/bytes.store" KEY <"$TMP/input"
    assert "unchanged_$kind" cmp -s "$TMP/bytes.store" "$TMP/before"
done
MODE="$(stat -c %a "$TMP/bytes.store" 2>/dev/null || stat -f %Lp "$TMP/bytes.store")"
assert mode600 test "$MODE" = 600
MODE="$(stat -c %a "$SECRETS_DIR" 2>/dev/null || stat -f %Lp "$SECRETS_DIR")"
assert mode700 test "$MODE" = 700
ln -s "$TMP/bytes.store" "$TMP/link.store"
printf 'new-value' >"$TMP/input"
check symlink_refusal 1 "$BASH" "$SECRET" stash "$TMP/link.store" KEY <"$TMP/input"
assert symlink_unchanged cmp -s "$TMP/bytes.store" "$TMP/before"
check directory_refusal 1 "$BASH" "$SECRET" stash "$TMP/cwd" KEY <"$TMP/input"

# Parallel writers share one lock even for explicitly named external stores.
cat >"$TMP/tty-stash.py" <<'PYTTY'
"""Exercise hidden terminal entry with synthetic bytes and a bounded pseudo-terminal."""
import os
import pty
import select
import subprocess
import sys
import time
master, slave = pty.openpty()
process = subprocess.Popen(sys.argv[1:3] + ["stash", sys.argv[3], "KEY"], stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
output = b""
sent = False
deadline = time.monotonic() + 5
value = b"synthetic-hidden" if sys.argv[4] == "valid" else b"synthetic\0hidden"
try:
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.05)[0]:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            if not sent and b"KEY: " in output:
                os.write(master, value + b"\n")
                sent = True
        elif process.poll() is not None:
            break
    if process.poll() is None:
        process.kill()
    status = process.wait(timeout=2)
    expected = 0 if sys.argv[4] == "valid" else 1
    assert sent and status == expected and value not in output, "hidden terminal entry failed"
finally:
    os.close(master)
PYTTY
check hidden_stash 0 python3 -I "$TMP/tty-stash.py" "$BASH" "$SECRET" "$TMP/interactive.store" valid
check hidden_roundtrip 0 "$BASH" "$SECRET" exec -f "$TMP/interactive.store" -- perl -e 'exit($ENV{KEY} eq "synthetic-hidden" ? 0 : 1)'
check hidden_nul_rejected 0 python3 -I "$TMP/tty-stash.py" "$BASH" "$SECRET" "$TMP/invalid-interactive.store" invalid
assert hidden_nul_no_write test ! -e "$TMP/invalid-interactive.store"

invoke stash "$TMP/concurrent.store" ONE <"$TMP/input" >"$TMP/one.out" &
PID1=$!
invoke stash "$TMP/concurrent.store" TWO <"$TMP/input" >"$TMP/two.out" &
PID2=$!
wait "$PID1"
wait "$PID2"
check concurrent 0 "$BASH" "$SECRET" exec -f "$TMP/concurrent.store" -- "$BASH" -c '[[ "$ONE" == new-value && "$TWO" == new-value ]]'
mkdir "$SECRETS_DIR/.write-lock"
printf 'stale-owner\n' >"$SECRETS_DIR/.write-lock/token"
check stale_lock 1 "$BASH" "$SECRET" stash "$TMP/bytes.store" KEY <"$TMP/input"
assert stale_hint grep -q 'timed out after 3 s.*never auto-stolen' "$TMP/err"
assert stale_preserved test -d "$SECRETS_DIR/.write-lock"
assert stale_no_write cmp -s "$TMP/bytes.store" "$TMP/before"
rm -f "$SECRETS_DIR/.write-lock/token"
rmdir "$SECRETS_DIR/.write-lock"

cat >"$TMP/redact.store" <<'EOF'
SHORT=q
TWO=xy
THREE=abc
LONG=abcdef
META=[.*]$^
EOF
check redaction 0 "$BASH" "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s|%s|%s|%s|%s" "$SHORT" "$TWO" "$THREE" "$LONG" "$META"; printf "%s!" "$LONG" >&2'
printf '<redacted>|<redacted>|<redacted>|<redacted>|<redacted>' >"$TMP/expected"
assert stdout_exact cmp -s "$TMP/out" "$TMP/expected"
printf '<redacted>!' >"$TMP/expected"
assert stderr_exact cmp -s "$TMP/err" "$TMP/expected"
check child_status 37 "$BASH" "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s" "$LONG"; exit 37'
check chunk_split 0 "$BASH" "$SECRET" run -f "$TMP/redact.store" -- perl -e '$|=1; print "abc"; select undef,undef,undef,.03; print "def"; print STDERR "abc"; select undef,undef,undef,.03; print STDERR "def"'
printf '<redacted>' >"$TMP/expected"
assert chunk_stdout cmp -s "$TMP/out" "$TMP/expected"
assert chunk_stderr cmp -s "$TMP/err" "$TMP/expected"
check large_output 0 "$BASH" "$SECRET" run -f "$TMP/redact.store" -- perl -e 'print "abcdef" x 50000'
assert large_redaction perl -e 'local $/; $_=<>; exit($_ eq "<redacted>" x 50000 ? 0 : 1)' "$TMP/out"
check all_loaded_values 0 "$BASH" "$SECRET" run -f "$TMP/legacy.store" -f "$TMP/override.store" --key ALPHA -- "$BASH" -c 'printf "last-value|override-value|optional-value"'
assert old_and_unselected_redacted grep -q '^<redacted>|<redacted>|<redacted>$' "$TMP/out"

# Fail only filter invocation, not the store parser; child must not start.
REAL_PERL="$(command -v perl)"
cat >"$TMP/bin/perl" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == */values ]]; then exit 91; fi
exec "$REAL_PERL" "$@"
EOF
chmod +x "$TMP/bin/perl"
export REAL_PERL
check filter_start_failure 1 "$BASH" "$SECRET" run -f "$TMP/redact.store" -- touch "$TMP/child-started"
assert no_raw_output test ! -s "$TMP/out"
assert child_not_started test ! -e "$TMP/child-started"
cat >"$TMP/bin/perl" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == */values ]]; then
    exec 3<"$3"
    printf 'ready\n' >"$4"
    cat <&3 >/dev/null
    exit 91
fi
exec "$REAL_PERL" "$@"
EOF
check filter_drain_failure 1 "$BASH" "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s" "$LONG"; touch "$1"' test "$TMP/child-started"
assert filter_failure_no_raw test ! -s "$TMP/out"
assert filter_failure_started test -f "$TMP/child-started"
rm "$TMP/bin/perl"
mkdir "$TMP/no-perl-bin"
check missing_perl 1 env PATH="$TMP/no-perl-bin" "$BASH" "$SECRET" run -f "$TMP/redact.store" -- touch "$TMP/without-perl"
assert missing_perl_no_child test ! -e "$TMP/without-perl"

# Unfiltered exec preserves binary JSON-RPC framing and the process signal.
check exec_framing 0 "$BASH" "$SECRET" exec -f "$TMP/bytes.store" -- perl -e 'print "Content-Length: 2\r\n\r\n{}\0"'
printf 'Content-Length: 2\r\n\r\n{}\000' >"$TMP/expected"
assert framing_bytes cmp -s "$TMP/out" "$TMP/expected"
check exec_signal 143 "$BASH" "$SECRET" exec -f "$TMP/bytes.store" -- "$BASH" -c 'kill -TERM $$'
mkfifo "$TMP/unread.store"
check get_fifo 1 "$BASH" "$SECRET" get "$TMP/unread.store" KEY
assert get_early_hint grep -q 'human-terminal-only' "$TMP/err"
check get_pipe 1 "$BASH" -c 'set -o pipefail; "$1" "$2" get "$3" KEY | cat' test "$BASH" "$SECRET" "$TMP/unread.store"
check get_missing 1 "$BASH" "$SECRET" get "$TMP/missing.store" KEY
assert get_before_resolve grep -q 'human-terminal-only' "$TMP/err"
check get_substitution 0 "$BASH" -c 'if output=$("$1" "$2" get "$3" KEY); then exit 1; fi; [[ -z "$output" ]]' test "$BASH" "$SECRET" "$TMP/unread.store"
if [[ "$OSTYPE" == darwin* ]]; then
    check get_tty 0 script -q "$TMP/tty.out" "$BASH" "$SECRET" get "$TMP/bytes.store" KEY </dev/null
else
    check get_tty 0 script -q -c "'$BASH' '$SECRET' get '$TMP/bytes.store' KEY" "$TMP/tty.out" </dev/null
fi
assert tty_value grep -Fq 'byte-safe-[]$x' "$TMP/tty.out"
check clip 0 "$BASH" "$SECRET" clip "$TMP/bytes.store" KEY 1
printf 'byte-safe-[]$x' >"$TMP/expected"
assert clipboard_copy cmp -s "$CLIPBOARD" "$TMP/expected"
sleep 2
assert clipboard_cleared test ! -s "$CLIPBOARD"
check clip_preserve 0 "$BASH" "$SECRET" clip "$TMP/bytes.store" KEY 1
printf 'user-replaced' >"$CLIPBOARD"
sleep 1.2
assert clipboard_replacement grep -q '^user-replaced$' "$CLIPBOARD"
# Verify actual rg defaults against synthetic files, not real project stores.
mkdir "$TMP/rg-fixture"
for file in .env .env.example app.secret .netrc .git-credentials normal.ts; do printf 'SYNTHETIC_MATCH\n' >"$TMP/rg-fixture/$file"; done
check rg_default_exclusions 0 env RIPGREP_CONFIG_PATH="$ROOT/examples/ripgreprc" rg -l SYNTHETIC_MATCH "$TMP/rg-fixture"
assert rg_only_code grep -q '/normal.ts$' "$TMP/out"
assert rg_one_file test "$(wc -l <"$TMP/out" | tr -d ' ')" = 1
check rg_explicit_template 0 env RIPGREP_CONFIG_PATH="$ROOT/examples/ripgreprc" rg SYNTHETIC_MATCH "$TMP/rg-fixture/.env.example"

printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[[ "$FAILED" -eq 0 ]]
