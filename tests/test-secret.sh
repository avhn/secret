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
SECRET="${SECRET_CLI:-$ROOT/bin/secret}"
# The Bash CLI needs its interpreter; the Go CLI is an executable.
if [[ -z "${SECRET_CLI:-}" ]]; then
    cat >"$TMP/bin/secret-cli" <<EOF
#!$BASH
exec "$BASH" "$ROOT/bin/secret" "\$@"
EOF
    chmod +x "$TMP/bin/secret-cli"
    SECRET="$TMP/bin/secret-cli"
fi
PASSED=0 FAILED=0

# check NAME STATUS CMD: bound calls and retain synthetic diagnostics on failure.
check() {
    local name="$1" want="$2" got=0
    shift 2
    [[ -n "${SECRET_TEST_INVENTORY:-}" ]] && printf '%s\t%s\tcheck\t%s\n' secret "$name" "$want" >>"$SECRET_TEST_INVENTORY"
    perl -MPOSIX=setsid -e '$pid=fork(); defined($pid) or exit 124; if (!$pid) { setsid(); exec @ARGV; exit 127 } $SIG{ALRM}=sub { kill "TERM", -$pid; waitpid($pid,0); exit 124 }; alarm 10; waitpid($pid,0); exit($? & 127 ? 128+($? & 127) : $? >> 8)'  "$@" >"$TMP/out" 2>"$TMP/err" || got=$?
    if [[ -n "${SECRET_TEST_RESULTS:-}" ]]; then
        if [[ "$got" == "$want" ]]; then result=pass; else result=fail; fi
        printf '%s\t%s\t%s\n' secret "$name" "$result" >>"$SECRET_TEST_RESULTS"
    fi
    if [[ "$got" == "$want" ]]; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: exit %s, expected %s\n' "$name" "$got" "$want"
        if [[ -z "${SECRET_CLI:-}" ]]; then cat "$TMP/err"; fi
    fi
}

# assert NAME CMD: record byte/content assertions without stopping the matrix.
assert() {
    local name="$1"
    shift
    [[ -n "${SECRET_TEST_INVENTORY:-}" ]] && printf '%s\t%s\tassert\t0\n' secret "$name" >>"$SECRET_TEST_INVENTORY"
    if "$@"; then
        [[ -z "${SECRET_TEST_RESULTS:-}" ]] || printf '%s\t%s\tpass\n' secret "$name" >>"$SECRET_TEST_RESULTS"
        PASSED=$((PASSED + 1))
    else
        [[ -z "${SECRET_TEST_RESULTS:-}" ]] || printf '%s\t%s\tfail\n' secret "$name" >>"$SECRET_TEST_RESULTS"
        FAILED=$((FAILED + 1))
        printf 'FAIL %s\n' "$name"
    fi
}

# invoke ARGS: always use the interpreter under test, not the script's shebang.
invoke() { "$SECRET" "$@"; }

cat >"$TMP/bin/pbcopy" <<'EOF'
#!/usr/bin/env bash
cat >"$CLIPBOARD"
EOF
cat >"$TMP/bin/pbpaste" <<'EOF'
#!/usr/bin/env bash
cat "$CLIPBOARD"
EOF
chmod +x "$TMP/bin/pbcopy" "$TMP/bin/pbpaste"

check empty_list 0 "$SECRET" list
assert empty_list_bytes test ! -s "$TMP/out"
check empty_show 0 "$SECRET" show
assert empty_message grep -q 'no secret stores' "$TMP/out"
check help 0 "$SECRET" --help
check missing 1 "$SECRET" show absent
check unknown 1 "$SECRET" invalid
check run_no_files 1 "$SECRET" run -- true
check run_no_separator 1 "$SECRET" run -f absent true

mkdir -p "$SECRETS_DIR/.directory.secret"
printf 'KEY=synthetic-bytes-[]$x\n' >"$SECRETS_DIR/.hidden.secret"
printf 'KEY=ignored-backup\n' >"$SECRETS_DIR/backup.secret~"
printf 'KEY=visible\n' >"$SECRETS_DIR/visible.secret"
printf 'TOKEN=synthetic-token\n' >"$SECRETS_ENV"
check discovery 0 "$SECRET" list
assert hidden_found grep -q '/.hidden.secret$' "$TMP/out"
assert backups_absent bash -c '! grep -q "backup\|directory" "$1"' test "$TMP/out"
check hidden_resolve 0 "$SECRET" show hidden
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
check legacy_show 0 "$SECRET" show "$TMP/legacy.store"
assert duplicate_warning grep -q 'duplicate ALPHA (lines: 2,4)' "$TMP/err"
assert ignored_lines grep -q '4 non-assignment lines ignored (lines: 3,5,6,7)' "$TMP/err"
assert masked_legacy grep -q 'ALPHA=<10 bytes>' "$TMP/out"
check legacy_exec 0 "$SECRET" exec -f "$TMP/legacy.store" --key ALPHA -- "$BASH" -c '[[ "$ALPHA" == last-value && -z "${BETA+x}" ]]'

printf 'ALPHA=override-value\nOPTIONAL=optional-value\n' >"$TMP/override.store"
check later_wins 0 "$SECRET" exec -f "$TMP/legacy.store" -f "$TMP/override.store" --key ALPHA --optional-key MISSING -- "$BASH" -c '[[ "$ALPHA" == override-value && -z "${OPTIONAL+x}" && -z "${MISSING+x}" ]]'
check required_absent 1 "$SECRET" run -f "$TMP/override.store" --key MISSING -- true
printf 'EMPTY=\n' >"$TMP/empty.store"
check required_empty 1 "$SECRET" exec -f "$TMP/empty.store" --key EMPTY -- true
check optional_present 0 "$SECRET" exec -f "$TMP/override.store" --optional-key OPTIONAL -- "$BASH" -c '[[ "$OPTIONAL" == optional-value ]]'
export OPTIONAL=ambient-leak
check ambient_unselected 0 "$SECRET" exec -f "$TMP/override.store" --key ALPHA -- "$BASH" -c '[[ -z "${OPTIONAL+x}" ]]'
unset OPTIONAL
printf 'WORK=synthetic-work\nKEYS=synthetic-array\nkey=synthetic-lower\n' >"$TMP/internal-names.store"
check transport_name_collision 0 "$SECRET" exec -f "$TMP/internal-names.store" -- perl -e 'exit($ENV{WORK} eq "synthetic-work" && $ENV{KEYS} eq "synthetic-array" && $ENV{key} eq "synthetic-lower" ? 0 : 1)'

cat >"$TMP/labels.store" <<'EOF'
KEY=plain-synthetic
[env=dev,region=eu]
KEY=dev-eu-synthetic
ALPHA=dev-only-synthetic
[]
KEY=reset-synthetic
[env=dev]
KEY=dev-synthetic
[env=prod]
KEY=prod-synthetic
[]
[ env=dev]
BROKEN=legacy-synthetic
[env=dev,env=prod]
[env=dev ]
 [env=dev,region=eu]
[env=dev]
SECOND=dev-second-synthetic
[env=dev,env=prod]
THREE=still-dev-synthetic
EOF
check labels_no_selector 0 "$SECRET" exec -f "$TMP/labels.store" -- "$BASH" -c '[[ "$KEY" == reset-synthetic && -z "${ALPHA+x}" && -z "${SECOND+x}" && -z "${THREE+x}" && "$BROKEN" == legacy-synthetic ]]'
assert ignored_brackets grep -q 'non-assignment lines ignored (lines: 12,14,15,16,19)' "$TMP/err"
check labels_dev 0 "$SECRET" exec -f "$TMP/labels.store" --env dev -- "$BASH" -c '[[ "$KEY" == dev-synthetic && "$SECOND" == dev-second-synthetic && "$THREE" == still-dev-synthetic && -z "${env+x}" ]]'
check labels_specific 0 "$SECRET" exec -f "$TMP/labels.store" --env dev --label region=eu -- "$BASH" -c '[[ "$KEY" == dev-eu-synthetic && "$ALPHA" == dev-only-synthetic && "$BROKEN" == legacy-synthetic && -z "${region+x}" ]]'
check labels_prod 0 "$SECRET" exec -f "$TMP/labels.store" --label env=prod -- "$BASH" -c '[[ "$KEY" == prod-synthetic && -z "${ALPHA+x}" ]]'
check labels_and 0 "$SECRET" exec -f "$TMP/labels.store" --label env=dev --label region=us -- "$BASH" -c '[[ "$KEY" == dev-synthetic && -z "${ALPHA+x}" ]]'
check labels_repeated_same 0 "$SECRET" exec -f "$TMP/labels.store" --env dev --label env=dev -- "$BASH" -c '[[ "$KEY" == dev-synthetic ]]'
check labels_conflict 1 "$SECRET" exec -f "$TMP/labels.store" --env dev --env prod -- true
assert labels_conflict_message grep -q 'conflicting label selector for env' "$TMP/err"
check labels_invalid 1 "$SECRET" run -f "$TMP/labels.store" --label 'env=bad value' -- true
assert labels_invalid_message grep -q 'invalid label selector' "$TMP/err"
check labels_show 0 "$SECRET" show "$TMP/labels.store"
cat >"$TMP/expected" <<EOF
$TMP/labels.store
  KEY=<15 bytes>
  KEY [env=dev,region=eu]=<16 bytes>
  ALPHA [env=dev,region=eu]=<18 bytes>
  KEY=<15 bytes>
  KEY [env=dev]=<13 bytes>
  KEY [env=prod]=<14 bytes>
  BROKEN=<16 bytes>
  SECOND [env=dev]=<20 bytes>
  THREE [env=dev]=<19 bytes>
EOF
assert labels_show_bytes cmp -s "$TMP/out" "$TMP/expected"
check labels_show_selected 0 "$SECRET" show --env dev --label region=eu "$TMP/labels.store"
assert labels_show_selected_key grep -q '^  KEY \[env=dev,region=eu\]=<16 bytes>$' "$TMP/out"
assert labels_show_selected_unmatched bash -c '! grep -q "^  ALPHA=<unset>$" "$1"' test "$TMP/out"
check labels_show_unmatched 0 "$SECRET" show --env prod "$TMP/labels.store"
assert labels_show_unmatched_key grep -q '^  ALPHA=<unset>$' "$TMP/out"

cat >"$TMP/ambiguous.store" <<'EOF'
[env=dev]
KEY=first-synthetic
[region=eu]
KEY=second-synthetic
EOF
check labels_ambiguous 1 "$SECRET" exec -f "$TMP/ambiguous.store" --env dev --label region=eu -- true
assert labels_ambiguous_key grep -q 'ambiguous labels for KEY' "$TMP/err"
assert labels_ambiguous_no_value bash -c '! grep -E "first-synthetic|second-synthetic" "$1" "$2"' test "$TMP/out" "$TMP/err"
check labels_show_ambiguous 1 "$SECRET" show --env dev --label region=eu "$TMP/ambiguous.store"
assert labels_show_ambiguous_key grep -q 'ambiguous labels for KEY' "$TMP/err"
check labels_not_ambiguous 0 "$SECRET" exec -f "$TMP/ambiguous.store" --env dev -- "$BASH" -c '[[ "$KEY" == first-synthetic ]]'
cat >"$TMP/reordered.store" <<'EOF'
[env=dev,region=eu]
KEY=first-synthetic
[region=eu,env=dev]
KEY=second-synthetic
EOF
check labels_same_set_last_wins 0 "$SECRET" exec -f "$TMP/reordered.store" --env dev --label region=eu -- "$BASH" -c '[[ "$KEY" == second-synthetic ]]'
check labels_show_canonical 0 "$SECRET" show "$TMP/reordered.store"
assert labels_show_canonical_count test "$(grep -c '^  KEY \[env=dev,region=eu\]=' "$TMP/out")" -eq 2
cat >"$TMP/specificity.store" <<'EOF'
[env=dev]
KEY=first-synthetic
[region=eu]
KEY=second-synthetic
[env=dev,region=eu]
KEY=most-specific-synthetic
EOF
check labels_more_specific_resolves_tie 0 "$SECRET" exec -f "$TMP/specificity.store" --env dev --label region=eu -- "$BASH" -c '[[ "$KEY" == most-specific-synthetic ]]'
export NODE_ENV=dev
check labels_no_ambient_inference 0 "$SECRET" exec -f "$TMP/ambiguous.store" -- "$BASH" -c '[[ -z "${KEY+x}" ]]'
unset NODE_ENV
export ALPHA=ambient-synthetic
check labels_unmatched_ambient 0 "$SECRET" exec -f "$TMP/labels.store" --env prod -- "$BASH" -c '[[ -z "${ALPHA+x}" ]]'
check labels_unmatched_optional 0 "$SECRET" exec -f "$TMP/labels.store" --env prod --optional-key ALPHA -- "$BASH" -c '[[ -z "${ALPHA+x}" ]]'
check labels_unmatched_required 1 "$SECRET" exec -f "$TMP/labels.store" --env prod --key ALPHA -- true
unset ALPHA
check labels_later_selected 0 "$SECRET" exec -f "$TMP/labels.store" -f "$TMP/override.store" --env dev -- "$BASH" -c '[[ "$ALPHA" == override-value ]]'
check labels_later_unmatched 0 "$SECRET" exec -f "$TMP/override.store" -f "$TMP/labels.store" --env prod -- "$BASH" -c '[[ "$ALPHA" == override-value ]]'
check labels_later_scoped 0 "$SECRET" exec -f "$TMP/override.store" -f "$TMP/labels.store" --env dev --label region=eu -- "$BASH" -c '[[ "$ALPHA" == dev-only-synthetic ]]'
check labels_run_selection 0 "$SECRET" run -f "$TMP/labels.store" --env dev --label region=eu -- "$BASH" -c '[[ "$KEY" == dev-eu-synthetic && -z "${env+x}" ]]'
check labels_redact_unselected 0 "$SECRET" run -f "$TMP/labels.store" --env prod -- perl -e 'open my $f, "<", $ARGV[0] or die; while (<$f>) { if (/^ALPHA=(.*)/) { print $1; last } }' "$TMP/labels.store"
printf '<redacted>' >"$TMP/expected"
assert labels_redact_unselected_bytes cmp -s "$TMP/out" "$TMP/expected"
# The expected fixtures include comments, unusual line endings, and sibling
# sections so cmp catches any change outside the selected record.
printf 'new-synthetic' >"$TMP/input"
printf '# first\r\nKEY=old-synthetic\r\n[region=eu,env=dev]\r\n# sibling\r\nKEY=other-synthetic\r\nSECOND=kept-synthetic\r\n[]\r\nKEY=reset-synthetic\r\n' >"$TMP/edit.store"
printf '# first\r\nKEY=old-synthetic\r\n[region=eu,env=dev]\r\n# sibling\r\nSECOND=kept-synthetic\r\nKEY=new-synthetic\n[]\r\nKEY=reset-synthetic\r\n' >"$TMP/expected"
check labels_stash_existing 0 "$SECRET" stash --env dev --label region=eu "$TMP/edit.store" KEY <"$TMP/input"
assert labels_stash_existing_bytes cmp -s "$TMP/edit.store" "$TMP/expected"
check labels_stash_existing_selected 0 "$SECRET" exec -f "$TMP/edit.store" --env dev --label region=eu -- "$BASH" -c '[[ "$KEY" == new-synthetic ]]'
printf 'new-synthetic' >"$TMP/input"
printf '# first\r\nKEY=old-synthetic\r\n[region=eu,env=dev]\r\n# sibling\r\nSECOND=kept-synthetic\r\nKEY=new-synthetic\n[]\r\nKEY=reset-synthetic\r\n[env=prod,region=eu]\nKEY=new-synthetic\n' >"$TMP/expected"
check labels_stash_new 0 "$SECRET" stash --label region=eu --env=prod "$TMP/edit.store" KEY <"$TMP/input"
assert labels_stash_new_bytes cmp -s "$TMP/edit.store" "$TMP/expected"
check labels_stash_new_file 0 "$SECRET" stash --label region=eu --env prod "$TMP/brand-new.store" KEY <"$TMP/input"
printf '[env=prod,region=eu]\nKEY=new-synthetic\n' >"$TMP/expected-new"
assert labels_stash_new_file_bytes cmp -s "$TMP/brand-new.store" "$TMP/expected-new"
printf '# first\r\n[region=eu,env=dev]\r\n# sibling\r\nSECOND=kept-synthetic\r\nKEY=new-synthetic\n[]\r\n[env=prod,region=eu]\nKEY=new-synthetic\n[]\nKEY=plain-new-synthetic\n' >"$TMP/expected"
printf 'plain-new-synthetic' >"$TMP/input"
check labels_stash_plain 0 "$SECRET" stash "$TMP/edit.store" KEY <"$TMP/input"
assert labels_stash_plain_bytes cmp -s "$TMP/edit.store" "$TMP/expected"
printf '[env=dev]\n# keep\n' >"$TMP/end-labeled.store"
check labels_stash_reset 0 "$SECRET" stash "$TMP/end-labeled.store" KEY <"$TMP/input"
printf '[env=dev]\n# keep\n[]\nKEY=plain-new-synthetic\n' >"$TMP/expected"
assert labels_stash_reset_bytes cmp -s "$TMP/end-labeled.store" "$TMP/expected"
printf '# leading\nKEY=original-synthetic\n[env=dev]\nSECOND=kept-synthetic\n[]\n# reset\n' >"$TMP/leading.store"
printf '# leading\nKEY=plain-new-synthetic\n[env=dev]\nSECOND=kept-synthetic\n[]\n# reset\n' >"$TMP/expected"
check labels_stash_leading 0 "$SECRET" stash "$TMP/leading.store" KEY <"$TMP/input"
assert labels_stash_leading_bytes cmp -s "$TMP/leading.store" "$TMP/expected"
printf '[env=dev]\nSECOND=kept-synthetic\n[]\n# trailing\n' >"$TMP/reset-end.store"
printf '[env=dev]\nSECOND=kept-synthetic\n[]\n# trailing\nKEY=plain-new-synthetic\n' >"$TMP/expected"
check labels_stash_after_reset 0 "$SECRET" stash "$TMP/reset-end.store" KEY <"$TMP/input"
assert labels_stash_after_reset_bytes cmp -s "$TMP/reset-end.store" "$TMP/expected"
printf '"edge-synthetic' >"$TMP/input"
check labels_stash_quote 0 "$SECRET" stash --env dev "$TMP/reset-end.store" KEY <"$TMP/input"
check labels_stash_quote_roundtrip 0 "$SECRET" exec -f "$TMP/reset-end.store" --env dev -- perl -e 'exit($ENV{KEY} eq "\x22edge-synthetic" ? 0 : 1)'
cp "$TMP/edit.store" "$TMP/edit-before"
check labels_stash_invalid_selector 1 "$SECRET" stash --label 'env=bad value' "$TMP/edit.store" KEY <"$TMP/input"
assert labels_stash_invalid_unchanged cmp -s "$TMP/edit.store" "$TMP/edit-before"

printf 'byte-safe-[]$x' >"$TMP/input"
check stash_eof 0 "$SECRET" stash "$TMP/bytes.store" KEY <"$TMP/input"
printf 'byte-safe-[]$x\n' >"$TMP/expected"
check exec_bytes 0 "$SECRET" exec -f "$TMP/bytes.store" -- "$BASH" -c 'printf "%s\n" "$KEY"'
assert exec_byte_equality cmp -s "$TMP/out" "$TMP/expected"
printf 'next-value\n' >"$TMP/input"
check stash_lf 0 "$SECRET" stash "$TMP/bytes.store" SECOND <"$TMP/input"
printf '"abc' >"$TMP/input"
check stash_leading_quote 0 "$SECRET" stash "$TMP/quoted.store" KEY <"$TMP/input"
check stash_leading_quote_roundtrip 0 "$SECRET" exec -f "$TMP/quoted.store" -- perl -e 'exit($ENV{KEY} eq "\x22abc" ? 0 : 1)'
printf "abc'" >"$TMP/input"
check stash_trailing_quote 0 "$SECRET" stash "$TMP/quoted.store" KEY <"$TMP/input"
check stash_trailing_quote_roundtrip 0 "$SECRET" exec -f "$TMP/quoted.store" -- perl -e 'exit($ENV{KEY} eq "abc\x27" ? 0 : 1)'
printf "'ab\"" >"$TMP/input"
check stash_mixed_quote 0 "$SECRET" stash "$TMP/quoted.store" KEY <"$TMP/input"
check stash_mixed_quote_roundtrip 0 "$SECRET" exec -f "$TMP/quoted.store" -- perl -e 'exit($ENV{KEY} eq "\x27ab\x22" ? 0 : 1)'
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
    check "reject_$kind" 1 "$SECRET" stash "$TMP/bytes.store" KEY <"$TMP/input"
    assert "unchanged_$kind" cmp -s "$TMP/bytes.store" "$TMP/before"
done
MODE="$(stat -c %a "$TMP/bytes.store" 2>/dev/null || stat -f %Lp "$TMP/bytes.store")"
assert mode600 test "$MODE" = 600
MODE="$(stat -c %a "$SECRETS_DIR" 2>/dev/null || stat -f %Lp "$SECRETS_DIR")"
assert mode700 test "$MODE" = 700
ln -s "$TMP/bytes.store" "$TMP/link.store"
printf 'new-value' >"$TMP/input"
check symlink_refusal 1 "$SECRET" stash "$TMP/link.store" KEY <"$TMP/input"
assert symlink_unchanged cmp -s "$TMP/bytes.store" "$TMP/before"
check directory_refusal 1 "$SECRET" stash "$TMP/cwd" KEY <"$TMP/input"

# Observe a public parent throughout replacement, not just after the write.
PUBLIC_PARENT="$TMP/public-parent"
mkdir "$PUBLIC_PARENT"
chmod 755 "$PUBLIC_PARENT"
perl -e 'print "# padding\n" x 100000' >"$PUBLIC_PARENT/store"
chmod 600 "$PUBLIC_PARENT/store"
perl -e '
    use strict; use warnings;
    my ($dir, $ready, $done, $found) = @ARGV;
    open my $r, ">", $ready or die "watcher readiness failed\n"; close $r;
    for (1..3000) {
        opendir my $d, $dir or die "watcher directory failed\n";
        my @names = readdir $d; closedir $d;
        for my $name (@names) {
            next if $name eq "." || $name eq ".." || $name eq "store";
            if (-f "$dir/$name") {
                open my $f, ">", $found or die "watcher record failed\n"; close $f;
            }
        }
        last if -e $done;
        select undef, undef, undef, .001;
    }
' "$PUBLIC_PARENT" "$TMP/watcher-ready" "$TMP/watcher-done" "$TMP/watcher-found" &
WATCH_PID=$!
for ((i = 0; i < 100; i++)); do
    [[ ! -e "$TMP/watcher-ready" ]] || break
    sleep 0.01
done
assert stash_public_watcher_ready test -e "$TMP/watcher-ready"
check stash_public_parent 0 "$SECRET" stash "$PUBLIC_PARENT/store" KEY <"$TMP/input"
touch "$TMP/watcher-done"
assert stash_public_watcher wait "$WATCH_PID"
assert stash_public_no_regular_file test ! -e "$TMP/watcher-found"
assert stash_public_no_leftover bash -c 'shopt -s nullglob; dirs=("$1"/.secret-stash.*); ((${#dirs[@]} == 0))' test "$PUBLIC_PARENT"

mkdir "$TMP/failure-parent"
printf 'KEY=original-value\nSECOND=keep-value\n' >"$TMP/failure-parent/store"
cp "$TMP/failure-parent/store" "$TMP/failure-before"
REAL_PERL="$(command -v perl)"
export REAL_PERL
export STASH_FAIL_FILE="$TMP/failure-parent/store" STASH_FAIL_PARENT="$TMP/failure-parent" STASH_FAIL_MARKER="$TMP/failure-marker"
cat >"$TMP/bin/perl" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == "$STASH_FAIL_FILE" && "${3:-}" == KEY ]]; then
    shopt -s nullglob
    dirs=("$STASH_FAIL_PARENT"/.secret-stash.*)
    if ((${#dirs[@]})); then touch "$STASH_FAIL_MARKER"; fi
    exit 91
fi
exec "$REAL_PERL" "$@"
EOF
chmod +x "$TMP/bin/perl"
check stash_failure_cleanup 1 "$SECRET" stash "$STASH_FAIL_FILE" KEY <"$TMP/input"
assert stash_failure_reached_private_dir test -e "$STASH_FAIL_MARKER"
assert stash_failure_original cmp -s "$STASH_FAIL_FILE" "$TMP/failure-before"
assert stash_failure_no_leftover bash -c 'shopt -s nullglob; dirs=("$1"/.secret-stash.*); ((${#dirs[@]} == 0))' test "$STASH_FAIL_PARENT"
rm "$TMP/bin/perl"

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
process = subprocess.Popen([sys.argv[1], "stash", sys.argv[2], "KEY"], stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
output = b""
sent = False
deadline = time.monotonic() + 5
value = b"synthetic-hidden" if sys.argv[3] == "valid" else b"synthetic\0hidden"
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
    expected = 0 if sys.argv[3] == "valid" else 1
    assert sent and status == expected and value not in output, "hidden terminal entry failed"
finally:
    os.close(master)
PYTTY
check hidden_stash 0 python3 -I "$TMP/tty-stash.py" "$SECRET" "$TMP/interactive.store" valid
check hidden_roundtrip 0 "$SECRET" exec -f "$TMP/interactive.store" -- perl -e 'exit($ENV{KEY} eq "synthetic-hidden" ? 0 : 1)'
check hidden_nul_rejected 0 python3 -I "$TMP/tty-stash.py" "$SECRET" "$TMP/invalid-interactive.store" invalid
assert hidden_nul_no_write test ! -e "$TMP/invalid-interactive.store"

invoke stash "$TMP/concurrent.store" ONE <"$TMP/input" >"$TMP/one.out" &
PID1=$!
invoke stash "$TMP/concurrent.store" TWO <"$TMP/input" >"$TMP/two.out" &
PID2=$!
wait "$PID1"
wait "$PID2"
check concurrent 0 "$SECRET" exec -f "$TMP/concurrent.store" -- "$BASH" -c '[[ "$ONE" == new-value && "$TWO" == new-value ]]'
mkdir "$SECRETS_DIR/.write-lock"
printf 'stale-owner\n' >"$SECRETS_DIR/.write-lock/token"
check stale_lock 1 "$SECRET" stash "$TMP/bytes.store" KEY <"$TMP/input"
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
check redaction 0 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s|%s|%s|%s|%s" "$SHORT" "$TWO" "$THREE" "$LONG" "$META"; printf "%s!" "$LONG" >&2'
printf '<redacted>|<redacted>|<redacted>|<redacted>|<redacted>' >"$TMP/expected"
assert stdout_exact cmp -s "$TMP/out" "$TMP/expected"
printf '<redacted>!' >"$TMP/expected"
assert stderr_exact cmp -s "$TMP/err" "$TMP/expected"
check child_status 37 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s" "$LONG"; exit 37'
check chunk_split 0 "$SECRET" run -f "$TMP/redact.store" -- perl -e '$|=1; print "abc"; select undef,undef,undef,.03; print "def"; print STDERR "abc"; select undef,undef,undef,.03; print STDERR "def"'
printf '<redacted>' >"$TMP/expected"
assert chunk_stdout cmp -s "$TMP/out" "$TMP/expected"
assert chunk_stderr cmp -s "$TMP/err" "$TMP/expected"
check large_output 0 "$SECRET" run -f "$TMP/redact.store" -- perl -e 'print "abcdef" x 50000'
assert large_redaction perl -e 'local $/; $_=<>; exit($_ eq "<redacted>" x 50000 ? 0 : 1)' "$TMP/out"
check all_loaded_values 0 "$SECRET" run -f "$TMP/legacy.store" -f "$TMP/override.store" --key ALPHA -- "$BASH" -c 'printf "last-value|override-value|optional-value"'
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
check filter_start_failure 1 "$SECRET" run -f "$TMP/redact.store" -- touch "$TMP/child-started"
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
check filter_drain_failure 1 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s" "$LONG"; touch "$1"' test "$TMP/child-started"
assert filter_failure_no_raw test ! -s "$TMP/out"
assert filter_failure_started test -f "$TMP/child-started"
check filter_failure_child_nonzero 1 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s" "$LONG"; exit 37'
assert filter_failure_precedence grep -q '^secret: redaction filter failed$' "$TMP/err"
assert filter_failure_child_no_raw test ! -s "$TMP/out"

# Crash the stdout filter after one byte, while the child is still running.
# Neither a writing nor an idle child may postpone reporting the failure.
cat >"$TMP/bin/perl" <<'EOF'
#!/usr/bin/env bash
if [[ "${2:-}" == */values && "${3:-}" == */out ]]; then
    exec 3<"$3"
    printf 'ready\n' >"$4"
    dd bs=1 count=1 of=/dev/null <&3 2>/dev/null
    exit 91
fi
exec "$REAL_PERL" "$@"
EOF
check filter_dies_mid_run 1 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'while :; do printf "%s" "$LONG" || break; done; sleep 15'
assert filter_dies_message grep -q '^secret: redaction filter failed$' "$TMP/err"
assert filter_dies_no_raw test ! -s "$TMP/out"
# The stderr filter holds back the tail of child stderr when the stdout filter
# dies (CI runners ignore SIGPIPE, so children print write errors there); the
# message still starts on its own line, after the flushed child stderr.
check filter_dies_partial_stderr 1 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "child error line\n" >&2; sleep 0.3; printf "%s" "$LONG"; exec sleep 15'
assert partial_stderr_flushed grep -q "^child error line$" "$TMP/err"
assert partial_stderr_message grep -q '^secret: redaction filter failed$' "$TMP/err"
check child_idle_after_filter_death 1 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'printf "%s" "$LONG"; sleep 15'
assert idle_filter_message grep -q '^secret: redaction filter failed$' "$TMP/err"
assert idle_filter_no_raw test ! -s "$TMP/out"
rm "$TMP/bin/perl"

# Only the direct child is supervised; its descendant can hold a FIFO open.
check descendant_holds_stdout 1 "$SECRET" run -f "$TMP/redact.store" -- "$BASH" -c 'sleep 12 & printf "%s" "$LONG"'
assert descendant_filter_message grep -q '^secret: redaction filter failed$' "$TMP/err"
printf '<redacted>' >"$TMP/expected"
assert descendant_redacted cmp -s "$TMP/out" "$TMP/expected"
assert descendant_no_raw bash -c '! grep -Fq abcdef "$1" && ! grep -Fq abcdef "$2"' test "$TMP/out" "$TMP/err"
mkdir "$TMP/no-perl-bin"
check missing_perl 1 env PATH="$TMP/no-perl-bin" "$SECRET" run -f "$TMP/redact.store" -- touch "$TMP/without-perl"
assert missing_perl_no_child test ! -e "$TMP/without-perl"

# Unfiltered exec preserves binary JSON-RPC framing and the process signal.
check exec_framing 0 "$SECRET" exec -f "$TMP/bytes.store" -- perl -e 'print "Content-Length: 2\r\n\r\n{}\0"'
printf 'Content-Length: 2\r\n\r\n{}\000' >"$TMP/expected"
assert framing_bytes cmp -s "$TMP/out" "$TMP/expected"
check exec_signal 143 "$SECRET" exec -f "$TMP/bytes.store" -- "$BASH" -c 'kill -TERM $$'
mkfifo "$TMP/unread.store"
check get_fifo 1 "$SECRET" get "$TMP/unread.store" KEY
assert get_early_hint grep -q 'human-terminal-only' "$TMP/err"
check get_pipe 1 "$BASH" -c 'set -o pipefail; "$1" get "$2" KEY | cat' test "$SECRET" "$TMP/unread.store"
check get_missing 1 "$SECRET" get "$TMP/missing.store" KEY
assert get_before_resolve grep -q 'human-terminal-only' "$TMP/err"
check get_substitution 0 "$BASH" -c 'if output=$("$1" get "$2" KEY); then exit 1; fi; [[ -z "$output" ]]' test "$SECRET" "$TMP/unread.store"
if [[ "$OSTYPE" == darwin* ]]; then
    check get_tty 0 script -q "$TMP/tty.out" "$SECRET" get "$TMP/bytes.store" KEY </dev/null
else
    check get_tty 0 script -q -c "'$SECRET' get '$TMP/bytes.store' KEY" "$TMP/tty.out" </dev/null
fi
assert tty_value grep -Fq 'byte-safe-[]$x' "$TMP/tty.out"
if [[ "$OSTYPE" == darwin* ]]; then
    # BSD script returns the child's status; util-linux script without -e does not.
    check labels_get_tty 0 script -q "$TMP/tty.out" "$SECRET" get --env=dev --label region=eu "$TMP/labels.store" KEY </dev/null
    cp "$TMP/tty.out" "$TMP/selected-tty"
    check labels_get_ambiguous 1 script -q "$TMP/tty.out" "$SECRET" get --env dev --label region=eu "$TMP/ambiguous.store" KEY </dev/null
else
    check labels_get_tty 0 script -q -c "'$SECRET' get --env=dev --label region=eu '$TMP/labels.store' KEY" "$TMP/tty.out" </dev/null
    cp "$TMP/tty.out" "$TMP/selected-tty"
    check labels_get_ambiguous 0 script -q -c "'$SECRET' get --env dev --label region=eu '$TMP/ambiguous.store' KEY" "$TMP/tty.out" </dev/null
fi
assert labels_get_selected grep -Fq dev-eu-synthetic "$TMP/selected-tty"
assert labels_get_ambiguous_hint grep -q 'ambiguous labels for KEY' "$TMP/tty.out"
if [[ "$OSTYPE" == darwin* ]]; then
    check labels_get_unmatched 1 script -q "$TMP/tty.out" "$SECRET" get --env prod "$TMP/labels.store" ALPHA </dev/null
else
    check labels_get_unmatched 0 script -q -c "'$SECRET' get --env prod '$TMP/labels.store' ALPHA" "$TMP/tty.out" </dev/null
fi
assert labels_get_unmatched_hint grep -q 'key is not set' "$TMP/tty.out"
check labels_clip_selected 0 "$SECRET" clip --env=dev --label region=eu "$TMP/labels.store" KEY 2
printf 'dev-eu-synthetic' >"$TMP/expected"
assert labels_clip_selected_bytes cmp -s "$CLIPBOARD" "$TMP/expected"
check labels_clip_ambiguous 1 "$SECRET" clip --env dev --label region=eu "$TMP/ambiguous.store" KEY
assert labels_clip_ambiguous_hint grep -q 'ambiguous labels for KEY' "$TMP/err"
check labels_clip_unmatched 1 "$SECRET" clip --env prod "$TMP/labels.store" ALPHA
assert labels_clip_unmatched_hint grep -q 'key is not set' "$TMP/err"
check clip 0 "$SECRET" clip "$TMP/bytes.store" KEY 1
printf 'byte-safe-[]$x' >"$TMP/expected"
assert clipboard_copy cmp -s "$CLIPBOARD" "$TMP/expected"
sleep 2
assert clipboard_cleared test ! -s "$CLIPBOARD"
check clip_preserve 0 "$SECRET" clip "$TMP/bytes.store" KEY 1
printf 'user-replaced' >"$CLIPBOARD"
sleep 1.2
assert clipboard_replacement grep -q '^user-replaced$' "$CLIPBOARD"
# Verify actual rg defaults against synthetic files, not real project stores.
mkdir "$TMP/rg-fixture"
mkdir -p "$TMP/rg-fixture/.aws" "$TMP/rg-fixture/.ssh" "$TMP/rg-fixture/.config/gh"
# Distinct uppercase names: a case-insensitive macOS filesystem folds .ENV onto .env.
for file in .env .env.example app.secret prod.ENV UPPER.SECRET .netrc .git-credentials .npmrc .aws/credentials .ssh/id_ed25519 .config/gh/hosts.yml normal.ts; do printf 'SYNTHETIC_MATCH\n' >"$TMP/rg-fixture/$file"; done
check rg_default_exclusions 0 env RIPGREP_CONFIG_PATH="$ROOT/examples/ripgreprc" rg -l SYNTHETIC_MATCH "$TMP/rg-fixture"
assert rg_only_code grep -q '/normal.ts$' "$TMP/out"
assert rg_one_file test "$(wc -l <"$TMP/out" | tr -d ' ')" = 1
check rg_explicit_template 0 env RIPGREP_CONFIG_PATH="$ROOT/examples/ripgreprc" rg SYNTHETIC_MATCH "$TMP/rg-fixture/.env.example"

printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[[ "$FAILED" -eq 0 ]]
