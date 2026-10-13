#!/usr/bin/env bash
# Regenerate synthetic Bash CLI goldens into the specified directory only.
# LC_ALL=C makes show and the child report byte lengths on every host.
# shellcheck disable=SC2016 # The Perl child deliberately receives literal variable names.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# == 1 ]] || { printf 'usage: gen.sh OUTPUT_DIR\n' >&2; exit 2; }
[[ -f "$ROOT/testdata/store/cases.txt" ]] || { printf 'store case catalog is missing\n' >&2; exit 2; }
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/home" "$TMP/private"
cd "$ROOT/testdata/store/fixtures"
for catalog in "$ROOT/testdata/store/cases.txt" "$ROOT/testdata/store/cases-extended.txt"; do
    [[ -f "$catalog" ]] || continue
while IFS='|' read -r name mode options files keys; do
    [[ -n "$name" && "${name:0:1}" != '#' ]] || continue
    args=() file_args=() names=()
    read -r -a args <<<"$options"
    read -r -a file_args <<<"$files"
    read -r -a names <<<"$keys"
    rc=0
    if [[ "$mode" == show ]]; then
        env -i HOME="$TMP/home" SECRETS_DIR="$TMP/private" SECRETS_ENV="$TMP/fallback.store" LC_ALL=C PATH="$PATH" BASH_ENV='' ENV='' \
            bash "$ROOT/bin/secret" show ${args[@]+"${args[@]}"} ${file_args[@]+"${file_args[@]}"} >"$OUT/$name.stdout" 2>"$OUT/$name.stderr" || rc=$?
    elif [[ "$mode" == run ]]; then
        for file in ${file_args[@]+"${file_args[@]}"}; do args+=(-f "$file"); done
        env -i HOME="$TMP/home" SECRETS_DIR="$TMP/private" SECRETS_ENV="$TMP/fallback.store" LC_ALL=C PATH="$PATH" BASH_ENV='' ENV='' \
            KEY=ambient TOKEN=ambient SECOND=ambient ONLY=ambient OTHER=ambient \
            bash "$ROOT/bin/secret" run ${args[@]+"${args[@]}"} -- perl -e '
                for my $name (@ARGV) {
                    print "$name=", (exists $ENV{$name} ? length($ENV{$name}) : "<unset>"), "\n";
                }
            ' ${names[@]+"${names[@]}"} >"$OUT/$name.stdout" 2>"$OUT/$name.stderr" || rc=$?
    else
        printf 'unknown case mode: %s\n' "$mode" >&2
        exit 2
    fi
    printf '%s\n' "$rc" >"$OUT/$name.status"
done <"$catalog"
done
# Run the actual Bash stash against disposable copies, never against fixtures.
while IFS='|' read -r name fixture key labels value; do
    [[ -n "$name" && "${name:0:1}" != '#' ]] || continue
    cp "$ROOT/testdata/store/fixtures/$fixture" "$TMP/private/$name.store"
    args=()
    if [[ -n "$labels" ]]; then
        IFS=',' read -r -a pairs <<<"$labels"
        for pair in ${pairs[@]+"${pairs[@]}"}; do args+=(--label "$pair"); done
    fi
    printf '%b' "$value" | env -i HOME="$TMP/home" SECRETS_DIR="$TMP/private" LC_ALL=C PATH="$PATH" BASH_ENV='' ENV='' \
        bash "$ROOT/bin/secret" stash ${args[@]+"${args[@]}"} "$TMP/private/$name.store" "$key" > /dev/null
    cp "$TMP/private/$name.store" "$OUT/stash-$name.store"
done <"$ROOT/testdata/store/stash-cases.txt"
