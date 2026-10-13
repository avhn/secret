#!/usr/bin/env bash
# Generate CLI goldens against the real Bash command in isolated synthetic stores.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[[ $# == 1 ]] || { printf 'usage: gen.sh OUTPUT_DIR\n' >&2; exit 2; }
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/home" "$TMP/stores" "$TMP/work"
cp "$ROOT"/testdata/store/fixtures/*.store "$TMP/work/"
cd "$TMP/work"
while IFS='|' read -r name inventory arguments; do
    [[ -n "$name" && "${name:0:1}" != '#' ]] || continue
    [[ -n "$inventory" ]] || { printf 'missing inventory mapping\n' >&2; exit 2; }
    args=()
    read -r -a args <<<"$arguments"
    for i in "${!args[@]}"; do
        [[ "${args[i]}" != @child ]] || args[i]="$ROOT/testdata/cli/child.pl"
    done
    rc=0
    if [[ "$name" == stash_valid ]]; then
        printf 'synthetic\n' | env -i HOME="$TMP/home" SECRETS_DIR="$TMP/stores" SECRETS_ENV="$TMP/home/fallback.store" PATH="$PATH" LC_ALL=C BASH_ENV='' ENV='' \
            bash "$ROOT/bin/secret" ${args[@]+"${args[@]}"} >"$OUT/$name.stdout" 2>"$OUT/$name.stderr" || rc=$?
    else
        env -i HOME="$TMP/home" SECRETS_DIR="$TMP/stores" SECRETS_ENV="$TMP/home/fallback.store" PATH="$PATH" LC_ALL=C BASH_ENV='' ENV='' \
            bash "$ROOT/bin/secret" ${args[@]+"${args[@]}"} >"$OUT/$name.stdout" 2>"$OUT/$name.stderr" </dev/null || rc=$?
    fi
    printf '%s\n' "$rc" >"$OUT/$name.status"
done <"$ROOT/testdata/cli/cases.txt"
