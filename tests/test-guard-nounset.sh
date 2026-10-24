#!/usr/bin/env bash
# Empty-array controls for the owner-approved Bash 3.2 compatibility exception.
# Commands stay synthetic JSON data; no candidate command is ever executed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP/home" XDG_CONFIG_HOME="$TMP/xdg" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$TMP/work"
PASSED=0
check() {
    local name="$1" want="$2" command_text="$3" got=allow
    jq -cn --arg c "$command_text" --arg w "$TMP/work" \
        '{cwd:$w,tool_name:"Bash",tool_input:{command:$c}}' >"$TMP/envelope"
    if ! "$BASH" "$ROOT/hooks/guard-secrets" \
        <"$TMP/envelope" >"$TMP/output" 2>"$TMP/error"; then
        printf 'FAIL %s: guard exited unsuccessfully\n' "$name" >&2
        cat "$TMP/output" "$TMP/error" >&2
        exit 1
    fi
    if [[ -s "$TMP/output" ]]; then
        jq -se 'length == 1 and .[0].hookSpecificOutput.permissionDecision == "deny"' \
            "$TMP/output" >/dev/null || { cat "$TMP/output" >&2; exit 1; }
        got=deny
    fi
    if [[ -s "$TMP/error" || "$got" != "$want" ]]; then
        printf 'FAIL %s: got %s, expected %s without stderr\n' "$name" "$got" "$want" >&2
        cat "$TMP/output" "$TMP/error" >&2
        exit 1
    fi
    PASSED=$((PASSED + 1))
}
# Empty stdin does not need jq in the guard's fallback PATH on macOS.
if ! PATH=$'\n/usr/bin' "$BASH" "$ROOT/hooks/guard-secrets" </dev/null \
    >"$TMP/output" 2>"$TMP/error" || [[ -s "$TMP/output" || -s "$TMP/error" ]]; then
    printf 'FAIL empty_path_parts: expected successful empty output without stderr\n' >&2
    cat "$TMP/output" "$TMP/error" >&2
    exit 1
fi
PASSED=$((PASSED + 1))
check empty_selector allow "find . -name ''"
# shellcheck disable=SC2016  # candidate substitutions remain JSON data
check empty_literal_output allow 'cat "$()"'
check empty_fd_child allow 'fd -x'
check empty_git_args deny 'git submodule'
check empty_tar_inputs allow 'tar -cf public.tar'
check empty_kubectl_resources allow 'kubectl get ""'
printf '%s\n' 'TOKEN=synthetic-only' >"$TMP/work/.env"
check protected_selector deny 'find . -name .env -exec cat {} +'
check protected_tar_input deny 'tar -cf public.tar .env'
check protected_kubectl_resource deny 'kubectl get secrets -o yaml'
printf '%s empty-array and protected controls passed (%s)\n' "$PASSED" "$BASH_VERSION"
