#!/usr/bin/env bash
# Exercise the shared Git-path anchor cache with synthetic resolver results.
# Only repository function definitions are sourced, never candidate commands.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
sed -n '/^git_write_context() {/,/^}/p' "$ROOT/hooks/guard-secrets" >"$TMP/functions"
# shellcheck disable=SC1091  # Extracted repository function, not a credential store.
source "$TMP/functions"
export HOME="$TMP/home" XDG_CONFIG_HOME="$TMP/xdg"
# shellcheck disable=SC2034  # US is read by the sourced git_write_context.
CWD="$TMP/work" US=$'\037' BUDGET=1 RESOLVE_FAIL=0
: >"$TMP/calls"
within_budget() { [[ "$BUDGET" == 1 ]]; }
canonical_target() {
    printf '%s\n' "$1" >>"$TMP/calls"
    [[ "$RESOLVE_FAIL" == 0 ]] || return 1
    printf '%s' "$1"
}
expect_calls() {
    local count
    count="$(wc -l <"$TMP/calls" | tr -d " ")"
    [[ "$count" == "$1" ]] || { printf 'expected %s resolver calls, got %s\n' "$1" "$count" >&2; exit 1; }
}
git_write_context
expect_calls 3
[[ "$GIT_WRITE_HOME_CONFIG" == "$HOME/.gitconfig" && "$GIT_WRITE_XDG" == "$XDG_CONFIG_HOME/git" && "$GIT_WRITE_CWD" == "$CWD" ]]
git_write_context
expect_calls 3
CWD="$TMP/other"
git_write_context
expect_calls 6
[[ "$GIT_WRITE_CWD" == "$CWD" ]]
HOME="$TMP/other-home"
git_write_context
expect_calls 9
[[ "$GIT_WRITE_HOME_CONFIG" == "$HOME/.gitconfig" ]]
XDG_CONFIG_HOME="$TMP/other-xdg"
git_write_context
expect_calls 12
[[ "$GIT_WRITE_XDG" == "$XDG_CONFIG_HOME/git" ]]
# Cached success cannot bypass the shared deadline.
BUDGET=0
if git_write_context; then printf 'expired cache lookup allowed\n' >&2; exit 1; fi
expect_calls 12
BUDGET=1 RESOLVE_FAIL=1 CWD="$TMP/failing"
if git_write_context; then printf 'resolver failure allowed\n' >&2; exit 1; fi
expect_calls 13
# A failed refresh must not become a cache hit or discard later resolver errors.
if git_write_context; then printf 'resolver failure cached as success\n' >&2; exit 1; fi
expect_calls 14
RESOLVE_FAIL=0
git_write_context
expect_calls 17
printf '10 cache, scope, failure and deadline controls passed\n'
