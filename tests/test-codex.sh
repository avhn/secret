#!/usr/bin/env bash
#
# Synthetic Codex PreToolUse payloads. The wire envelope comes from
# codex-rs/hooks/src/events/pre_tool_use.rs and its generated input schema;
# shell and patch tool_input builders live in
# codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs and
# codex-rs/core/src/tools/handlers/apply_patch.rs (openai/codex 044e74f).
# Array and workdir cases exercise compatibility with other shell adapters;
# current Codex serializes a string command and omits workdir in hook input.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASSED=0 FAILED=0
mkdir -p "$TMP/work" "$TMP/elsewhere"
printf '%s\n' 'synthetic-only' >"$TMP/work/.env"
ln -s .env "$TMP/work/alias.txt"

# manifest_case NAME COMMAND [ARGS]: record a manifest assertion.
manifest_case() {
    local name="$1"
    shift
    if "$@" >/dev/null; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s\n' "$name"
    fi
}

# file_case NAME KIND PATH: check a referenced file, executable, or directory.
file_case() {
    local name="$1" kind="$2" path="$3"
    if [[ "$kind" == file && -f "$path" ]] ||
        [[ "$kind" == exec && -x "$path" ]] ||
        [[ "$kind" == dir && -d "$path" ]]; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: missing %s %s\n' "$name" "$kind" "$path"
    fi
}

CLAUDE_PLUGIN="$ROOT/.claude-plugin/plugin.json"
CLAUDE_MARKET="$ROOT/.claude-plugin/marketplace.json"
CODEX_PLUGIN="$ROOT/.codex-plugin/plugin.json"
CODEX_MARKET="$ROOT/.agents/plugins/marketplace.json"
manifest_case json jq -e -s 'length == 5' "$CLAUDE_PLUGIN" "$CLAUDE_MARKET" "$CODEX_PLUGIN" "$CODEX_MARKET" "$ROOT/.codex-plugin/hooks.json"
# jq variables are literal filter arguments, not shell expansions.
# shellcheck disable=SC2016
manifest_case versions jq -e -n --slurpfile cp "$CLAUDE_PLUGIN" --slurpfile cm "$CLAUDE_MARKET" --slurpfile xp "$CODEX_PLUGIN" --slurpfile xm "$CODEX_MARKET" '$cp[0].version == $cm[0].plugins[0].version and $cp[0].version == $xp[0].version and $xp[0].version == $xm[0].plugins[0].version and $xp[0].name == "secret" and $xm[0].name == "secret" and $xm[0].plugins[0].name == "secret" and $xm[0].plugins[0].source == "./"'
manifest_case references jq -e '.skills == "./skills" and .hooks == "./.codex-plugin/hooks.json"' "$CODEX_PLUGIN"
skills="$(jq -r '.skills' "$CODEX_PLUGIN")"
hooks="$(jq -r '.hooks' "$CODEX_PLUGIN")"
file_case skills dir "$ROOT/${skills#./}"
file_case skill_definition file "$ROOT/${skills#./}/secrets/SKILL.md"
file_case plugin_hooks file "$ROOT/${hooks#./}"
# The PLUGIN_ROOT placeholder must remain literal in the jq assertion.
# shellcheck disable=SC2016
manifest_case hook_config jq -e '.hooks.PreToolUse | length == 1 and .[0].matcher == "Bash|apply_patch" and (.[0].hooks | length == 1 and .[0].type == "command" and .[0].timeout == 5 and .[0].command == "\"${PLUGIN_ROOT}/hooks/guard-secrets\"")' "$ROOT/${hooks#./}"
hook_command="$(jq -r '.hooks.PreToolUse[0].hooks[0].command' "$ROOT/${hooks#./}")"
resolved_command="$(jq -nr --arg root "$ROOT" --arg command "$hook_command" '$command | gsub("\\$\\{PLUGIN_ROOT\\}"; $root) | ltrimstr("\"") | rtrimstr("\"")')"
file_case guard exec "$resolved_command"
# jq variables are literal filter arguments, not shell expansions.
# shellcheck disable=SC2016
manifest_case guard_path jq -e -n --arg path "$resolved_command" --arg expected "$ROOT/hooks/guard-secrets" '$path == $expected'
file_case manual_fallback file "$ROOT/codex/hooks.json"

# check NAME EXPECTED TOOL COMMAND [WORKDIR] [GUARD]: feed recorded-shaped hook JSON.
check() {
    local name="$1" expected="$2" tool="$3" command="$4" workdir="${5:-}" guard="${6:-$ROOT/hooks/guard-secrets}" got
    got="$(jq -cn --arg t "$tool" --argjson c "$command" --arg w "$TMP/work" --arg d "$workdir" \
        '{hook_event_name:"PreToolUse",session_id:"synthetic",turn_id:"synthetic",model:"synthetic",permission_mode:"default",tool_use_id:"synthetic",transcript_path:null,cwd:$w,tool_name:$t,tool_input:({command:$c} + (if $d == "" then {} else {workdir:$d} end))}' |
        perl -e 'alarm 5; exec @ARGV' "$BASH" "$guard" | jq -sr 'if length == 0 then "allow" else .[0].hookSpecificOutput.permissionDecision // "allow" end')" || got=crash
    if [[ "$got" == "$expected" ]]; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL %s: got %s, expected %s\n' "$name" "$got" "$expected"
    fi
}
# shell NAME DECISION COMMAND_JSON [WORKDIR].
shell_case() { check "$1" "$2" Bash "$3" "${4:-}"; }
# patch NAME DECISION HEADER: only metadata and synthetic patch lines are used.
patch_case() {
    local name="$1" expected="$2" text="$3"
    check "$name" "$expected" apply_patch "$(jq -cn --arg p "$text" '$p')"
}
check plugin_guard deny Bash '"cat .env"' '' "$resolved_command"
shell_case string deny '"cat .env"'
shell_case bash_lc deny '["bash","-lc","cat .env"]'
shell_case sh_c deny '["sh","-c","cat .env"]'
shell_case direct deny '["cat",".env"]'
# An inherited CMD variable must not stand in for the argv analysis.
CMD=true shell_case direct_inherited_cmd deny '["cat",".env"]'
shell_case direct_literal allow '["printf","%s","cat .env"]'
shell_case cwd_safe allow '"cat .env"' "$TMP/elsewhere"
shell_case workdir deny '"cat .env"' "$TMP/work"
shell_case workdir_relative deny '"cat .env"' .
shell_case argv_workdir deny '["cat",".env"]' "$TMP/work"
shell_case ordinary allow '"cat src/app.ts"'
for op in 'Add File' 'Update File' 'Delete File' 'Move to'; do
    patch_case "${op// /_}_env" deny "*** Begin Patch
*** $op: .env
+synthetic-only
*** End Patch"
    patch_case "${op// /_}_aws" deny "*** Begin Patch
*** $op: ~/.aws/credentials
*** End Patch"
    patch_case "${op// /_}_alias" deny "*** Begin Patch
*** $op: alias.txt
*** End Patch"
done
patch_case move_from deny '*** Begin Patch
*** Update File: .env
*** Move to: src/safe.ts
*** End Patch'
patch_case template allow '*** Begin Patch
*** Add File: .env.example
+TOKEN=sample
*** End Patch'
patch_case ordinary_patch allow '*** Begin Patch
*** Update File: src/app.ts
+test
*** End Patch'
patch_case malformed_named deny '*** Add File: .env'
patch_case malformed_safe allow '*** Add File: src/app.ts'
patch_case oversized_named deny "$(printf 'x%.0s' {1..9000})
*** Delete File: .env"
patch_case oversized_safe allow "$(printf 'x%.0s' {1..9000})
*** Update File: src/app.ts"
printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[[ "$FAILED" -eq 0 ]]
