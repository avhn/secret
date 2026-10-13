#!/usr/bin/env bash
#
# Guard regression matrix. Feeds hooks/guard-secrets synthetic tool calls the
# way Claude Code would and checks each permission decision (deny or allow).
# Fixtures live in a disposable directory; no host store is ever read. Run it
# with the bash under test, e.g. `/bin/bash tests/test-guard.sh` on macOS to
# cover stock bash 3.2. jq is required; missing it fails the matrix.
#
# Usage:
#   tests/test-guard.sh [-v|--verbose]
#
# Exit status: 0 when every case matches its expectation, 1 otherwise.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASSED=0 FAILED=0

VERBOSE=0
case "${1:-}" in
    -v | --verbose) VERBOSE=1 ;;
    -h | --help)
        sed -n '2,12p' "$0"
        exit 0
        ;;
    "") ;;
    *)
        echo "unknown option: $1" >&2
        exit 1
        ;;
esac

command -v jq >/dev/null 2>&1 || {
    printf '%s\n' 'jq not installed; required for the guard test matrix' >&2
    exit 1
}

# secrets NAME DECISION TOOL VALUE: run guard-secrets on a TOOL call whose
# command (Bash), file_path (Read/Edit/Write), or path (Grep) is VALUE.
SECRETS_GUARD="$REPO_ROOT/hooks/guard-secrets"
# Existing plain-rg cases model the installed defaults, independent of CI env.
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"
mkdir -p "$TMP/descendant-only/sub" "$TMP/search/sub" "$TMP/search/web" "$TMP/empty-search" "$TMP/search/src"
printf '%s\n' 'TOKEN=synthetic-only' >"$TMP/search/.env"
printf '%s\n' 'KEY=synthetic-only' >"$TMP/search/one.secret"
printf '%s\n' 'TOKEN=synthetic-only' >"$TMP/search/sub/.env"
printf '%s\n' 'TOKEN=synthetic-descendant' >"$TMP/descendant-only/sub/.env"
printf '%s\n' 'TOKEN=synthetic-only' >"$TMP/search/web/.env"
printf '%s\n' 'code' >"$TMP/search/src/a.ts"
# Uppercase fixtures also exercise case folding on case-sensitive CI hosts.
[[ -e "$TMP/search/.ENV" ]] || printf '%s\n' 'TOKEN=synthetic-upper' >"$TMP/search/.ENV"
printf '%s\n' 'KEY=synthetic-upper' >"$TMP/search/X.SECRET"
DEEP="$TMP/deep-search/a/b/c/d/e/f/g/h/i/j"
mkdir -p "$DEEP" "$TMP/upper-search" "$TMP/template-search" "$TMP/upper-private/.Secrets"
printf '%s\n' 'TOKEN=synthetic-deep' >"$DEEP/.ENV"
printf '%s\n' 'KEY=synthetic-upper' >"$TMP/upper-search/X.SECRET"
printf '%s\n' 'KEY=synthetic-private' >"$TMP/upper-private/.Secrets/file.txt"
printf '%s\n' 'TOKEN=template-only' >"$TMP/template-search/.ENV.EXAMPLE"
secrets() {
    local name="$1" want="$2" tool="$3" value="$4" extra="${5:-}" got
    [[ -n "$extra" ]] || extra='{}'
    got="$(jq -cn --arg t "$tool" --arg v "$value" --arg w "$TMP/search" --argjson extra "$extra" \
        '{tool_name:$t,cwd:$w,tool_input:((if $t == "Bash" then {command:$v} elif $t == "Grep" then {pattern:"x",path:$v} else {file_path:$v} end) + $extra)}' |
        perl -e 'alarm 5; exec @ARGV' "$BASH" "$SECRETS_GUARD" 2>"$TMP/$name.err" |
        jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null)" || got="crash"
    got="${got:-allow}"
    if [[ "$got" == "$want" ]]; then
        PASSED=$((PASSED + 1))
        ((VERBOSE)) && printf 'ok    %-22s %s\n' "$name" "$got"
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL  %-22s got %s, expected %s: %s %s\n' "$name" "$got" "$want" "$tool" "$value"
        sed 's/^/      /' "$TMP/$name.err"
    fi
    return 0
}

if command -v jq >/dev/null 2>&1; then
    # shellcheck disable=SC2016,SC2088  # literal home forms and expansions are the cases under test
    {
        # file tools
        secrets read_secret deny Read "$HOME/.secrets/svc.secret"
        secrets read_env deny Read /repo/web/.env.production
        secrets read_dotenv deny Read /repo/.env
        secrets read_example allow Read /repo/.env.example
        secrets read_code allow Read /repo/src/env.ts
        secrets edit_secrets_env deny Edit "$HOME/.secrets.env"
        secrets write_netrc deny Write "$HOME/.netrc"
        secrets grep_secrets allow Grep "$TMP/search" '{"output_mode":"files_with_matches"}'
        secrets grep_repo allow Grep /repo/src
        # Credential paths share literal, selector, reader, and tree protection.
        for entry in aws_credentials:.aws/credentials docker_config:.docker/config.json gh_hosts:.config/gh/hosts.yml npmrc:.npmrc pypirc:.pypirc ssh_rsa:.ssh/id_rsa ssh_ed25519:.ssh/id_ed25519 proc_self:proc/self/environ proc_thread:proc/thread-self/environ proc_pid:proc/123/environ proc_task:proc/123/task/456/environ 'proc_dollars:proc/$$/environ' 'proc_ppid:proc/$PPID/environ'; do
            name="${entry%%:*}" credential="${entry#*:}"
            for tool in Read Edit Write; do
                secrets "${tool}_${name}" deny "$tool" "/$credential"
            done
            secrets "grep_path_${name}" deny Grep "/$credential"
            secrets "grep_glob_${name}" deny Grep "$TMP/empty-search" "{\"glob\":\"$credential\",\"output_mode\":\"content\"}"
            secrets "cat_${name}" deny Bash "cat ~/$credential"
            secrets "redirect_${name}" deny Bash "wc < ~/$credential"
            secrets "xargs_${name}" deny Bash "echo ~/$credential | xargs cat"
            mkdir -p "$TMP/credential-$name"
            if [[ "$credential" == */* ]]; then mkdir -p "$TMP/credential-$name/${credential%/*}"; fi
            printf '%s\n' synthetic-only >"$TMP/credential-$name/$credential"
            secrets "grep_tree_${name}" deny Grep "$TMP/credential-$name" '{"output_mode":"content"}'
        done
        mkdir -p "$TMP/credential-safe/.ssh"
        printf '%s\n' synthetic-public >"$TMP/credential-safe/.ssh/id_ed25519.pub"
        printf '%s\n' template-only >"$TMP/credential-safe/.npmrc.example"
        printf '%s\n' ordinary >"$TMP/credential-safe/config.json"
        secrets credential_safe_tree allow Grep "$TMP/credential-safe" '{"output_mode":"content"}'
        secrets credential_component_lookalike allow Read /repo/xaws/credentials
        secrets credential_basename_lookalike allow Read /repo/xnpmrc
        secrets read_aws_credentials deny Read '~/.aws/credentials'
        secrets uppercase_credential deny Read '/repo/.AWS/CREDENTIALS'
        secrets uppercase_ssh_public allow Read '/repo/.SSH/ID_ED25519.PUB'
        secrets cat_proc_environ deny Bash 'cat /proc/self/environ'
        secrets redirect_proc_environ deny Bash 'wc < /proc/$$/environ'
        secrets read_ssh_other_private deny Read '~/.ssh/id_custom'
        secrets read_ssh_template_suffix deny Read '~/.ssh/id_custom.env.example'
        secrets read_ssh_space deny Read '~/.ssh/id_custom key'
        secrets cat_ssh_space deny Bash 'cat "~/.ssh/id_custom key"'
        secrets read_ssh_space_public allow Read '~/.ssh/id_custom key.pub'
        secrets credential_glob deny Bash 'cat ~/.docker/c*.json'
        secrets credential_selector_glob deny Grep "$TMP/empty-search" '{"glob":"**/.config/gh/*.yml","output_mode":"content"}'
        secrets ssh_private_glob deny Bash 'cat ~/.ssh/id_*'
        secrets ssh_public_glob allow Bash 'cat ~/.ssh/id_*.pub'
        safe_index=0
        for safe_path in '~/.ssh/config' '~/.ssh/known_hosts' '~/.ssh/id_ed25519.pub' /repo/config.json /repo/package.json /repo/.npmrc.example /repo/.npmrc.sample /repo/.npmrc.template /repo/.pypirc.example /proc/self/status /proc/cpuinfo; do
            secrets "read_safe_$safe_index" allow Read "$safe_path"
            secrets "cat_safe_$safe_index" allow Bash "cat $safe_path"
            secrets "glob_safe_$safe_index" allow Grep "$TMP/empty-search" "{\"glob\":\"$safe_path\",\"output_mode\":\"content\"}"
            safe_index=$((safe_index + 1))
        done
        # readers
        secrets cat_secret deny Bash 'cat ~/.secrets/svc.secret'
        secrets cat_home_var deny Bash 'cat "$HOME/.secrets/x.secret"'
        secrets grep_env deny Bash 'grep TOKEN web/.env.development'
        secrets sed_chain deny Bash 'cd web && sed -n 1p .env'
        secrets source_env deny Bash 'source ~/.secrets.env'
        secrets redirect deny Bash 'while read l; do :; done < .env'
        secrets redirect_tight deny Bash 'wc -l <.env'
        secrets sudo_cat deny Bash 'sudo cat /etc/app/.env'
        secrets cat_example allow Bash 'cat .env.example'
        secrets ls_secrets allow Bash 'ls -l ~/.secrets'
        secrets chmod_secret allow Bash 'chmod 600 ~/.secrets/x.secret'
        secrets env_file_flag allow Bash 'docker run --env-file=.env app'
        secrets quoted_prose allow Bash 'git commit -m "never cat .env again"'
        # the sanctioned path
        secrets secret_show allow Bash 'secret show svc'
        secrets secret_run allow Bash 'secret run -f ~/.secrets/svc.secret -- curl -H "Authorization: token $API_TOKEN" https://x'
        secrets secret_stash allow Bash 'gh auth token | secret stash github TOKEN'
        # environment dumps and credential printers
        secrets bare_env deny Bash 'env'
        secrets env_wraps allow Bash 'env FOO=1 make test'
        secrets env_grep deny Bash 'env | grep -c PATH'
        secrets printenv deny Bash 'printenv API_TOKEN'
        secrets export_p deny Bash 'export -p'
        secrets declare_x deny Bash 'declare -x'
        secrets bare_set deny Bash 'set'
        secrets set_opts allow Bash 'set -euo pipefail'
        secrets echo_token deny Bash 'echo $API_TOKEN'
        secrets echo_braced deny Bash 'printf "%s" "${DB_PASSWORD}"'
        secrets echo_home allow Bash 'echo $HOME'
        secrets keychain_w deny Bash 'security find-generic-password -s foo -w'
        secrets keychain_piped allow Bash 'security find-generic-password -s foo -w | secret stash foo KEY'
        secrets gh_token deny Bash 'gh auth token'
        secrets gh_status allow Bash 'gh auth status'
        PRINTER_CASES=('gcloud_token:gcloud auth print-access-token' 'gcloud_identity:gcloud auth print-identity-token' 'gcloud_default:gcloud auth application-default print-access-token' 'aws_get_secret:aws configure get aws_secret_access_key' 'aws_get_id:aws configure get aws_access_key_id' 'aws_get_session:aws configure get aws_session_token' 'aws_export:aws configure export-credentials' 'op_read:op read op://vault/item/password' 'op_reveal:op item get item --reveal' 'op_fields:op item get item --fields password' 'pass_show:pass show mail' 'pass_bare:pass mail' 'secret_tool_lookup:secret-tool lookup service mail' 'kwallet_read:kwallet-query -r mail wallet' 'ps_e:ps e' 'ps_eww:ps eww' 'ps_mac_environment:ps -E' 'declare_bare:declare' 'typeset_bare:typeset' 'jq_environment:jq -n env' 'jq_ENV:jq -n "$ENV"')
        for entry in "${PRINTER_CASES[@]}"; do
            name="${entry%%:*}" operation="${entry#*:}"
            secrets "$name" deny Bash "$operation"
            secrets "${name}_wrapped" deny Bash "timeout 5 $operation"
            secrets "${name}_nested" deny Bash "bash -c '${operation//\'/\'\\\'\'}'"
            secrets "${name}_to_stash" allow Bash "$operation | secret stash svc KEY"
            secrets "${name}_indirect_stash" deny Bash "$operation | cat | secret stash svc KEY"
        done
        secrets aws_profile_before deny Bash 'aws --profile work configure get AWS_SECRET_ACCESS_KEY'
        secrets aws_profile_after deny Bash 'aws configure get aws_session_token --profile work'
        secrets aws_profile_get deny Bash 'aws configure get --profile work aws_access_key_id'
        secrets aws_profile_equals deny Bash 'aws --profile=work configure export-credentials'
        secrets aws_mixed_key deny Bash 'aws configure get AwS_SeCrEt_AcCeSs_KeY'
        secrets op_fields_equals deny Bash 'op item get item --fields=password'
        secrets op_fields_title deny Bash 'op item get item --fields title'
        secrets secret_tool_search deny Bash 'secret-tool search service mail'
        secrets secret_tool_search_to_stash deny Bash 'secret-tool search service mail | secret stash svc KEY'
        secrets secret_tool_search_wrapped deny Bash 'nice -n 5 secret-tool search service mail'
        secrets secret_tool_search_nested deny Bash 'bash -c "secret-tool search service mail"'
        secrets ps_combined_environment deny Bash 'ps auxeww'
        secrets ps_environment_after_options deny Bash 'ps -p 1 eww'
        secrets jq_env_filter deny Bash 'jq "env | .TOKEN" input.json'
        secrets jq_env_literal deny Bash "jq -n '\$ENV'"
        secrets jq_env_arg deny Bash 'jq --arg label safe -n env'
        secrets echo_lower_token deny Bash 'echo $token'
        secrets echo_mixed_password deny Bash 'printf "%s" "${db_PassWord}"'
        safe_index=0
        for operation in 'ps aux' 'ps -ef' 'ps -e' 'ps -o user,pid' 'ps -C server' 'aws sts get-caller-identity' 'aws configure list' 'aws configure get region' 'gcloud auth list' 'op whoami' 'pass ls' 'pass insert x' 'secret-tool store service mail' "jq -n '1'" "jq -n '\"env\"'" 'jq --arg label env -n .label' 'declare -f name' 'typeset -i x=1'; do
            secrets "printer_safe_$safe_index" allow Bash "$operation"
            safe_index=$((safe_index + 1))
        done
        secrets git_cred deny Bash 'git credential fill'
        secrets pbpaste deny Bash 'pbpaste'
        secrets pbpaste_piped allow Bash 'pbpaste | secret stash vault KEY'
        secrets other_tool allow Glob '**/.env'
        secrets jq_filter allow Bash 'jq -r ".env.NODE_ENV" config/settings.json'
        secrets jq_env deny Bash 'jq . .env'
        secrets no_file allow Bash "cd $TMP/empty-search && cat .env"
        secrets cd_file deny Bash 'cd sub && cat .env'
        secrets path_reader deny Bash '/bin/cat .env'
        secrets command_reader deny Bash 'command cat .env'
        secrets nested_shell deny Bash 'bash -c "cat .env"'
        secrets run_reader deny Bash 'secret run -f svc -- cat .env'
        secrets run_nested deny Bash "secret run -f svc -- bash -c 'cat ~/.secrets/x.secret'"
        secrets get deny Bash 'secret get svc TOKEN'
        secrets exec deny Bash 'secret exec -f svc -- true'
        secrets abs_get deny Bash '/abs/path/secret get svc TOKEN'
        secrets unknown deny Bash 'secret typo'
        secrets env_cat deny Bash 'env | cat'
        secrets gh_tee deny Bash 'gh auth token | tee f'
        secrets pb_cat deny Bash 'pbpaste | cat'
        secrets git_stash allow Bash 'git credential fill | secret stash git PASSWORD'
        secrets keychain_g_stash deny Bash 'security find-generic-password -g | secret stash svc KEY'
        secrets internet_w_stash allow Bash 'security find-internet-password -w | secret stash svc KEY'
        secrets internet_g_stash deny Bash 'security find-internet-password -g | secret stash svc KEY'
        secrets keychain_tee deny Bash 'security find-generic-password -w | tee f'
        secrets direct_only deny Bash 'gh auth token | cat | secret stash svc KEY'
        secrets grep_recursive deny Bash 'grep -R TOKEN dir'
        secrets grep_long deny Bash 'grep --recursive TOKEN dir'
        secrets rg_uu deny Bash 'rg -uu TOKEN dir'
        secrets rg_noignore deny Bash 'rg --no-ignore TOKEN dir'
        secrets rg_noconfig deny Bash 'rg --no-config TOKEN dir'
        secrets rg_plain allow Bash 'rg TOKEN dir'
        secrets pattern_file deny Bash 'grep -f .env src/a.ts'
        secrets regexp_equals deny Bash 'grep --regexp=TOKEN .env'
        secrets pattern_file_equals deny Bash 'grep --file=.env src/a.ts'
        secrets jq_arg_role allow Bash "jq --arg file .env '.value' src/a.ts"
        secrets header_transport allow Bash "secret run -f svc -- bash -c 'printf \"Authorization: Bearer %s\\n\" \"\$TOKEN\" | curl -H @- https://example.test'"
        secrets rg_iglob deny Bash "rg --iglob='.env*' TOKEN dir"
        secrets rg_hidden allow Bash 'rg --hidden TOKEN dir'
        secrets rg_exclude allow Bash "rg --glob='!.env' TOKEN dir"
        secrets rg_reinclude deny Bash "rg --glob='.env*' TOKEN dir"
        secrets cat_glob deny Bash 'cat .env*'
        secrets head_glob deny Bash 'head *.secret'
        secrets cat_star deny Bash 'cat *'
        # heredoc bodies are data, except unquoted ones with substitutions
        secrets heredoc_commit allow Bash $'git commit -F - <<\'EOF\'\nfeat: secret exec and cat .env are prose\nEOF'
        secrets heredoc_plain allow Bash $'cat <<EOF\ncat ~/.secrets/x.secret\nEOF'
        secrets heredoc_dash allow Bash $'cat <<-EOF\n\tsecret exec x\n\tEOF'
        secrets heredoc_subst deny Bash $'cat <<EOF\n$(cat ~/.secrets/x.secret)\nEOF'
        secrets heredoc_after deny Bash $'cat <<\'EOF\'\nhi\nEOF\ncat ~/.secrets/x.secret'
        secrets heredoc_unclosed deny Bash $'cat <<EOF\n$(cat ~/.secrets/x.secret)'
        secrets herestring_subst deny Bash 'cat <<< "$(cat ~/.secrets/x.secret)"'
        secrets pattern_role allow Bash "grep 'env.*' src/a.ts"
        secrets ls_glob allow Bash 'ls *.secret'
        secrets redirect_glob deny Bash 'wc < .env*'
        secrets grep_glob deny Grep "$TMP/search" '{"glob":"*.secret","output_mode":"content"}'
        secrets grep_content deny Grep "$TMP/search" '{"output_mode":"content"}'
        secrets grep_count deny Grep "$TMP/search" '{"output_mode":"count"}'
        secrets grep_nopath deny Grep '' '{"output_mode":"content"}'
        secrets grep_empty allow Grep "$TMP/empty-search" '{"output_mode":"content"}'
        secrets secret_template deny Read "$HOME/.secrets/.env.example"
        secrets template_sample allow Read /repo/.env.sample
        secrets template_template allow Read /repo/.env.template

        # Positive search selectors must not depend on a same-named cwd file.
        secrets rg_descendant_glob deny Bash "cd $TMP/descendant-only && rg --glob=.env TOKEN sub"
        secrets rg_descendant_glob_split deny Bash "cd $TMP/descendant-only && rg --glob .env TOKEN sub"
        secrets rg_descendant_g deny Bash "cd $TMP/descendant-only && rg -g.env TOKEN sub"
        secrets rg_descendant_g_split deny Bash "cd $TMP/descendant-only && rg -g .env TOKEN sub"
        secrets rg_descendant_iglob deny Bash "cd $TMP/descendant-only && rg --iglob=.env TOKEN sub"
        secrets rg_descendant_iglob_upper deny Bash "cd $TMP/descendant-only && rg --iglob=.ENV TOKEN sub"
        secrets rg_descendant_iglob_upper_split deny Bash "cd $TMP/descendant-only && rg --iglob .ENV TOKEN sub"
        secrets rg_descendant_iglob_split deny Bash "cd $TMP/descendant-only && rg --iglob .env TOKEN sub"
        secrets rg_descendant_exclusion allow Bash "cd $TMP/descendant-only && rg --glob='!.env' TOKEN sub"
        secrets rg_descendant_negative_g allow Bash "cd $TMP/descendant-only && rg -g '!.env' TOKEN sub"
        secrets rg_descendant_negative_i allow Bash "cd $TMP/descendant-only && rg --iglob='!.env' TOKEN sub"
        secrets rg_safe_glob allow Bash 'rg --glob="**/environment*.ts" TOKEN src'
        secrets rg_safe_secret_glob allow Bash 'rg -g "**/secret*.ts" TOKEN src'
        secrets rg_private_glob deny Bash 'rg --glob="**/.secrets/*.ts" TOKEN sub'
        secrets rg_narrow_env deny Bash 'rg --glob="service?.env" TOKEN sub'
        secrets rg_narrow_secret deny Bash 'rg --glob="service?.secret" TOKEN sub'
        secrets rg_netrc_selector deny Bash 'rg --glob=.netrc TOKEN sub'
        secrets rg_gitcredential_selector deny Bash 'rg --glob=.git-credentials TOKEN sub'
        secrets rg_secretsenv_selector deny Bash 'rg --glob=.secrets.env TOKEN sub'
        secrets rg_envsuffix_selector deny Bash 'rg --glob="*.env" TOKEN sub'
        secrets rg_envprefix_selector deny Bash 'rg --glob=".env.*" TOKEN sub'
        secrets rg_type_with_glob deny Bash 'rg --type-add custom:.env -t custom --glob=.env TOKEN sub'
        # Compound prefixes, adjacent grouping, and substitutions preserve analysis.
        secrets conditional_reader deny Bash 'if test -f .env; then cat .env; fi'
        secrets elif_reader deny Bash 'if false; then :; elif cat .env; then :; fi'
        secrets else_reader deny Bash 'if false; then :; else cat .env; fi'
        secrets while_reader deny Bash 'while true; do cat .env; done'
        secrets until_reader deny Bash 'until true; do cat .env; done'
        secrets for_reader deny Bash 'for name in one; do cat .env; done'
        secrets case_reader deny Bash 'case name in name) cat .env;; esac'
        secrets grouped_reader deny Bash '{ cat .env; }'
        secrets subshell_reader deny Bash '(cat .env)'
        secrets negated_reader deny Bash '! cat .env'
        secrets timed_reader deny Bash 'time -p cat .env'
        secrets conditional_printer deny Bash 'if true; then env; fi'
        secrets loop_printer deny Bash 'while true; do printenv TOKEN; done'
        secrets grouped_printer deny Bash '{ gh auth token; }'
        secrets subshell_printer deny Bash '(pbpaste)'
        secrets substitution_reader deny Bash 'echo $(cat .env)'
        secrets substitution_printer deny Bash 'echo $(gh auth token)'
        secrets quoted_substitution_reader deny Bash 'printf "%s" "$(cat .env)"'
        secrets quoted_substitution_printer deny Bash 'printf "%s" "$(printenv TOKEN)"'
        secrets backtick_reader deny Bash 'echo `cat .env`'
        secrets backtick_printer deny Bash 'echo `pbpaste`'
        secrets nested_substitution deny Bash 'echo "$(printf "%s" "$(cat .env)")"'
        secrets safe_conditional allow Bash 'if test -f src/a.ts; then cat src/a.ts; fi'
        secrets safe_loop allow Bash 'for name in one; do cat src/a.ts; done'
        secrets safe_subshell allow Bash '(cat src/a.ts)'
        secrets substitution_cd_reader deny Bash "cd $TMP/descendant-only && cd sub && echo \$(cat .env)"
        secrets quoted_substitution_cd deny Bash "cd $TMP/descendant-only && cd sub && echo \"\$(cat .env)\""
        secrets backtick_cd_reader deny Bash "cd $TMP/descendant-only && cd sub && echo \`cat .env\`"
        secrets safe_substitution allow Bash 'echo "$(cat src/a.ts)"'
        secrets literal_substitution allow Bash "echo '\$(cat .env)'"
        secrets literal_backticks allow Bash "echo '\`cat .env\`'"
        secrets literal_group allow Bash "echo '(cat .env)'"
        secrets grep_environment_names allow Grep "$TMP/search" '{"glob":"**/environment*.ts","output_mode":"files_with_matches"}'
        secrets grep_secret_code_names allow Grep "$TMP/search" '{"glob":"**/secret*.ts","output_mode":"files_with_matches"}'
        secrets grep_ts_names allow Grep "$TMP/search" '{"glob":"*.ts","output_mode":"files_with_matches"}'
        secrets grep_env_content deny Grep "$TMP/empty-search" '{"glob":".env*","output_mode":"content"}'
        secrets grep_wildcard_names allow Grep "$TMP/search" '{"glob":"*.secret","output_mode":"files_with_matches"}'
        secrets grep_exact_store_names deny Grep "$TMP/empty-search" '{"glob":".env","output_mode":"files_with_matches"}'
        secrets grep_safe_content_selector allow Grep "$TMP/empty-search" '{"glob":"**/environment*.ts","output_mode":"content"}'
        secrets grep_safe_secret_content allow Grep "$TMP/empty-search" '{"glob":"**/secret*.ts","output_mode":"content"}'
        secrets grep_safe_ts_content allow Grep "$TMP/empty-search" '{"glob":"*.ts","output_mode":"content"}'

        # Comments are syntax only at an unquoted word boundary.
        secrets comment_reader deny Bash "cat .env # don't"
        secrets comment_printer deny Bash "printenv TOKEN # don't"
        secrets comment_safe allow Bash "cat src/a.ts # don't"
        secrets comment_stash_pipe allow Bash $'gh auth token | # don\'t\nsecret stash svc TOKEN'
        secrets comment_substitution_literal allow Bash 'echo ok # $(cat .env)'
        secrets comment_next_line deny Bash $'echo ok # don\'t\ncat .env'
        secrets quoted_hash allow Bash "echo \"# don't\""
        secrets embedded_hash allow Bash 'echo file#suffix'
        secrets escaped_hash allow Bash 'echo \#literal'
        # Failed analysis is denied only when raw command text names a risk.
        secrets unclosed_risk deny Bash "cat .env '"
        secrets unclosed_risk_case deny Bash "cat .ENV '"
        secrets unclosed_safe allow Bash "echo hello '"
        secrets unclosed_printenv deny Bash "printenv TOKEN '"
        secrets unclosed_keychain deny Bash "security find-generic-password '"
        secrets unclosed_auth deny Bash "gh auth token '"
        secrets unclosed_credential deny Bash "git credential fill '"
        secrets unclosed_clipboard deny Bash "pbpaste '"
        secrets unclosed_get deny Bash "secret get svc TOKEN '"
        secrets unclosed_exec deny Bash "secret exec -f svc -- true '"
        DEEP_CMD="cat .env" SAFE_DEEP_CMD="echo safe"
        for ((depth = 0; depth < 6; depth++)); do
            DEEP_CMD="bash -c '${DEEP_CMD//\'/\'\\\'\'}'"
            SAFE_DEEP_CMD="bash -c '${SAFE_DEEP_CMD//\'/\'\\\'\'}'"
        done
        secrets deep_risk deny Bash "$DEEP_CMD"
        secrets deep_safe allow Bash "$SAFE_DEEP_CMD"
        LONG_TEXT="$(printf 'a%.0s' $(seq 1 33000))"
        secrets long_safe allow Bash "echo $LONG_TEXT"
        secrets long_risk deny Bash "echo $LONG_TEXT .env"
        MEDIUM_TEXT="$(printf 'a%.0s' $(seq 1 8200))"
        secrets bounded_length_safe allow Bash "echo $MEDIUM_TEXT"
        secrets bounded_length_risk deny Bash "echo $MEDIUM_TEXT .ENV"
        MANY_TOKENS="$(printf 'word %.0s' $(seq 1 130))"
        secrets bounded_tokens_safe allow Bash "echo $MANY_TOKENS"
        secrets bounded_tokens_risk deny Bash "echo $MANY_TOKENS .ENV"
        # Path/selector/tree matching is case-insensitive on every platform.
        secrets uppercase_reader deny Bash 'cat .ENV'
        secrets uppercase_secret deny Bash 'head X.SECRET'
        secrets uppercase_private deny Bash 'cat ~/.Secrets/x'
        secrets uppercase_tool deny Read /repo/.ENV.PRODUCTION
        secrets uppercase_template allow Read /repo/.ENV.EXAMPLE
        secrets uppercase_private_template deny Read '~/.Secrets/.ENV.EXAMPLE'
        secrets uppercase_glob deny Bash 'cat *.SECRET'
        secrets uppercase_selector deny Bash 'rg --glob=.ENV TOKEN sub'
        secrets uppercase_grep_selector deny Grep "$TMP/empty-search" '{"glob":".ENV*","output_mode":"content"}'
        secrets uppercase_private_tree deny Grep "$TMP/upper-private" '{"output_mode":"content"}'
        secrets uppercase_tree deny Grep "$TMP/upper-search" '{"output_mode":"content"}'
        secrets uppercase_tree_template allow Grep "$TMP/template-search" '{"output_mode":"content"}'
        secrets deep_tree deny Grep "$TMP/deep-search" '{"output_mode":"content"}'
        # Wrapper-owned options/operands cannot hide readers or printers.
        secrets timeout_reader deny Bash 'timeout 5 cat .env'
        secrets timeout_attached_options deny Bash 'timeout --signal=TERM --kill-after=1s 5s cat .env'
        secrets timeout_options deny Bash 'timeout --signal TERM --kill-after 1s 5s cat .env'
        secrets nice_reader deny Bash 'nice -n 5 cat .env'
        secrets nohup_reader deny Bash 'nohup cat .env'
        secrets exec_reader deny Bash 'exec cat .env'
        secrets exec_named_reader deny Bash 'exec -a safe-name cat .env'
        secrets stdbuf_reader deny Bash 'stdbuf -oL cat .env'
        secrets stdbuf_long_options deny Bash 'stdbuf --output=L --input=0 cat .env'
        secrets stdbuf_options deny Bash 'stdbuf -i 0 -o L -e 0 cat .env'
        secrets caffeinate_reader deny Bash 'caffeinate -di -t 5 cat .env'
        secrets chained_wrappers deny Bash 'nohup timeout -s TERM 5 nice -n 5 stdbuf -oL cat .env'
        secrets timeout_printer deny Bash 'timeout 5 printenv TOKEN'
        secrets nice_printer deny Bash 'nice -n 5 gh auth token'
        secrets safe_timeout allow Bash 'timeout 5 cat src/a.ts'
        secrets safe_nice allow Bash 'nice -n 5 cat src/a.ts'
        secrets safe_stdbuf allow Bash 'stdbuf -oL cat src/a.ts'
        secrets safe_caffeinate allow Bash 'caffeinate -t 5 cat src/a.ts'
        secrets xargs_ls deny Bash 'ls .env | xargs cat'
        secrets xargs_find deny Bash "find . -name '.env' | xargs cat"
        secrets xargs_echo deny Bash 'echo .env | xargs cat'
        secrets xargs_find_descendant deny Bash "cd $TMP/descendant-only && find sub -name '.env' | xargs cat"
        secrets xargs_replace deny Bash 'echo .env | xargs -I {} cat {}'
        secrets xargs_options deny Bash 'ls .env | xargs -0 -n 1 -P 2 cat'
        secrets xargs_chain deny Bash "find . -name '.env' | sort | xargs cat"
        secrets xargs_safe_reader allow Bash 'ls src/a.ts | xargs cat'
        secrets xargs_safe_listing allow Bash 'ls .env | xargs ls'
        secrets python_code deny Bash "python -c 'open(\".env\").read()'"
        secrets perl_code deny Bash "perl -e 'open F, \"<\", \".env\"'"
        secrets node_code deny Bash "node -e 'require(\"fs\").readFileSync(\".env\")'"
        secrets ruby_code deny Bash "ruby -e 'puts File.read(\".env\")'"
        secrets inline_python_cluster deny Bash "python3 -Ic 'open(\".env\").read()'"
        secrets inline_perl_cluster deny Bash "perl -ne 'open F, \"<\", \".env\"'"
        secrets inline_case deny Bash "python3 -c 'open(\".ENV\").read()'"
        secrets inline_attached deny Bash "perl -e'open F, \"<\", \".env\"'"
        secrets inline_long deny Bash "node --eval='require(\"fs\").readFileSync(\".env\")'"
        secrets inline_safe allow Bash "python3 -c 'print(1)'"

        # Empty quotes still start a word, so a following hash is not a comment.
        secrets empty_word_hash deny Bash 'cat ""#x .env'
        secrets empty_single_hash deny Bash "cat ''#x .env"
        secrets empty_pattern_reader deny Bash 'grep "" .env'
        secrets empty_then_comment allow Bash 'cat "" # $(cat .env)'
        secrets escaped_word_hash deny Bash 'cat \#x .env'
        # Over-cap classification covers printer words, variables, and globs.
        risk_index=0
        for operation in env 'printenv TOKEN' 'export -p' set 'declare -p' 'declare -x' typeset 'compgen -v' wl-paste xclip xsel pbpaste 'grep -r TOKEN' 'grep -R TOKEN' 'grep --color=always -R TOKEN' 'rg TOKEN' 'cat .en*' 'cat *.secret' 'cat .secret*' 'cat *' 'consumer < *'; do
            secrets "over_cap_operation_$risk_index" deny Bash "$operation # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        for expansion in 'echo $API_TOKEN' 'echo ${db_password}' 'printf "%s" "$API_KEY"' 'echo $token'; do
            secrets "over_cap_expansion_$risk_index" deny Bash "$expansion # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        for safe_word in environment settings exported declared typesetting xclipboard rgument; do
            secrets "over_cap_safe_$risk_index" allow Bash "echo $safe_word $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        for entry in "${PRINTER_CASES[@]}"; do
            name="${entry%%:*}" operation="${entry#*:}"
            secrets "over_cap_${name}" deny Bash "$operation # $LONG_TEXT"
        done
        for operation in 'secret-tool search service mail' 'aws --profile work configure get aws_secret_access_key' 'aws configure get aws_access_key_id --profile work' 'aws configure get --profile work aws_session_token' 'op item get item --fields=password'; do
            secrets "over_cap_printer_$risk_index" deny Bash "$operation # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        for credential in '~/.aws/credentials' '~/.docker/config.json' '~/.config/gh/hosts.yml' .npmrc .pypirc '~/.ssh/id_custom' /proc/self/environ /proc/thread-self/environ /proc/123/environ /proc/123/task/456/environ '/proc/$$/environ' '/proc/$PPID/environ'; do
            secrets "over_cap_path_$risk_index" deny Bash "cat $credential # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        for operation in 'ps aux' 'ps -ef' 'ps -e' 'gh auth status' 'aws sts get-caller-identity' 'aws configure list' 'gcloud auth list' 'op whoami' 'pass ls' 'pass insert x' 'secret-tool store service mail' "jq -n '1'" 'cat ~/.ssh/id_ed25519.pub' 'cat ~/.ssh/config' 'cat ~/.ssh/known_hosts' 'cat .npmrc.example' 'cat .pypirc.template' 'cat /proc/self/status' 'cat /proc/cpuinfo' 'cat config.json' 'cat package.json' 'echo gcloudish opportune passage psalm secret-tooling kwallet-querying'; do
            secrets "over_cap_safe_$risk_index" allow Bash "$operation # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        secrets over_cap_pass_after_safe deny Bash "pass ls; pass show mail # $LONG_TEXT"
        secrets over_cap_public_then_private deny Bash "cat ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa # $LONG_TEXT"
        secrets over_cap_escaped_dot deny Bash "cat \\.aws/credentials # $LONG_TEXT"
        secrets over_cap_escaped_ssh deny Bash "cat foo\\\\.ssh/id_rsa # $LONG_TEXT"
        secrets over_cap_escaped_suffix deny Bash "cat ~/.npmrc\\ x # $LONG_TEXT"
        secrets over_cap_case deny Bash "ENV # $LONG_TEXT"
        secrets failed_analysis_variable deny Bash "echo \$TOKEN '"
        secrets failed_analysis_env deny Bash "env '"
        secrets failed_analysis_glob deny Bash "cat .en* '"
        # Argument checks do not depend on interpreter option-cluster parsing.
        secrets node_print deny Bash "node -p 'process.env'"
        secrets node_long_print deny Bash "node --print 'process.env'"
        secrets perl_lne deny Bash "perl -lne 'open F, \"<\", \".env\"'"
        secrets ruby_requires deny Bash "ruby -rjson -e 'puts File.read(\".env\")'"
        secrets interpreter_script_operand deny Bash 'python3 consumer.py .env'
        # Printer words are ordinary operands to scripts and shell -c code.
        secrets interpreter_printer_operand deny Bash 'perl consumer.pl printenv'
        secrets interpreter_set_operand allow Bash 'perl consumer.pl set --verbose'
        secrets interpreter_ruby_env deny Bash "ruby -e 'p ENV'"
        secrets interpreter_perl_env deny Bash "perl -e 'print %ENV'"
        secrets interpreter_python_environ deny Bash 'python3 -c "import os; print(os.environ)"'
        secrets interpreter_python_getenv deny Bash 'python3 -c "import os; print(os.getenv(\"TOKEN\"))"'
        secrets interpreter_node_env deny Bash 'node -p "process.env"'
        secrets interpreter_export_operand allow Bash 'python3 manage.py export --format csv'
        secrets interpreter_python_pass allow Bash "python3 -c 'if 1: pass  # noop'"
        secrets interpreter_perl_pass_text allow Bash "perl -e 'print \"tests pass ok\"'"
        secrets shell_c_set_options allow Bash 'bash -c "set -euo pipefail; echo environment ready"'
        secrets shell_c_export_path allow Bash 'sh -c "export PATH=/usr/bin; make build"'
        secrets shell_c_printer_still_denied deny Bash 'bash -c "printenv"'
        secrets shell_c_reader_still_denied deny Bash 'bash -c "set -e; cat ~/.secrets.env"'
        secrets shell_code deny Bash "sh -c 'printenv TOKEN'"
        secrets shell_long_options deny Bash "bash --noprofile --norc -c 'cat .env'"
        secrets shell_operand deny Bash "secret run -f svc -- bash -c 'cat \"\$1\"' test .env"
        secrets shell_filtered_header allow Bash "secret run -f svc -- bash --noprofile --norc -c 'printf \"Authorization: Bearer %s\\n\" \"\$TOKEN\" | curl -H @- https://example.test'"
        # Wrapper arities are explicit; arg-file values are always file operands.
        secrets xargs_R_reader deny Bash 'ls .env | xargs -R 1 cat'
        secrets xargs_S_reader deny Bash 'ls .env | xargs -S 255 cat'
        secrets xargs_optional_replace deny Bash 'ls .env | xargs --replace cat'
        secrets xargs_optional_lines deny Bash 'ls .env | xargs --max-lines cat'
        secrets xargs_optional_eof deny Bash 'ls .env | xargs --eof cat'
        secrets xargs_optional_safe allow Bash 'ls src/a.ts | xargs --replace cat'
        secrets xargs_R_safe allow Bash 'ls src/a.ts | xargs -R 1 cat'
        secrets xargs_S_safe allow Bash 'ls src/a.ts | xargs -S 255 cat'
        secrets xargs_arg_file deny Bash 'xargs -a .env cat'
        secrets xargs_arg_file_attached deny Bash 'xargs -a.env cat'
        secrets xargs_arg_file_long deny Bash 'xargs --arg-file .env cat'
        secrets xargs_arg_file_equals deny Bash 'xargs --arg-file=.env cat'
        secrets xargs_arg_file_default deny Bash 'xargs -a .env'
        secrets xargs_arg_file_safe allow Bash 'xargs -a src/a.ts cat'
        secrets xargs_arg_file_template allow Bash 'xargs --arg-file=.env.example cat'
        for wrapper in timeout nice stdbuf caffeinate xargs exec; do
            secrets "unknown_${wrapper}_reader" deny Bash "$wrapper --unrecognised value cat .env"
            secrets "unknown_${wrapper}_printer" deny Bash "$wrapper --unrecognised value env"
            secrets "unknown_${wrapper}_safe" allow Bash "$wrapper --unrecognised value echo environment settings"
        done
        secrets missing_wrapper_value deny Bash 'exec -a .env --unrecognised'

        # Parser differentials and bounded name indirection, never evaluation.
        secrets env_split deny Bash "env -S 'cat .env'"
        secrets env_split_equals deny Bash "env --split-string='cat .env'"
        secrets env_split_attached deny Bash 'env -S"cat .env"'
        secrets env_split_long deny Bash "env --split-string 'cat .env'"
        secrets env_split_operand deny Bash "env -S cat .env"
        secrets env_split_end_options deny Bash "env -S '-- cat .env'"
        secrets env_split_empty deny Bash "env -S ''"
        secrets env_split_assignment deny Bash "env -S 'NAME=value'"
        secrets env_split_options deny Bash "env -S '-i cat .env'"
        secrets env_split_options_safe allow Bash "env -S '-u NAME cat src/a.ts'"
        secrets env_split_unknown deny Bash "env -S '--unknown echo .env'"
        secrets env_split_safe allow Bash "env -S 'cat src/a.ts'"
        secrets env_split_safe_quote allow Bash "env -S echo \"don't\""
        secrets env_split_nested deny Bash "env -S 'bash -c \"cat .env\"'"
        secrets env_split_budget deny Bash "env -S '$DEEP_CMD'"
        secrets env_split_tokens deny Bash "env -S 'echo $MANY_TOKENS .env'"
        secrets env_unset deny Bash 'env -u NAME cat .env'
        secrets env_unset_equals deny Bash 'env --unset=NAME cat .env'
        secrets env_unset_safe allow Bash 'env -u cat echo .env'
        secrets env_flags deny Bash 'env -i -0 -- cat .env'
        secrets env_flags_safe allow Bash 'env -i -0 -- cat src/a.ts'
        secrets env_chdir deny Bash "env -C '$TMP/descendant-only/sub' cat .env"
        secrets env_chdir_equals deny Bash "env --chdir='$TMP/descendant-only/sub' cat .env"
        secrets env_chdir_attached deny Bash "env -C'$TMP/descendant-only/sub' cat .env"
        secrets env_chdir_empty allow Bash "env -C '$TMP/empty-search' cat .env"
        secrets env_chdir_scoped deny Bash "env -C '$TMP/empty-search' true; cat .env"
        secrets env_chdir_split deny Bash "env -C '$TMP/descendant-only/sub' -S 'cat .env'"
        secrets env_unknown deny Bash 'env --unknown value cat .env'
        secrets env_missing deny Bash 'env -u'
        secrets env_missing_split deny Bash 'env -S'
        for option in -u -g -h -p -C -D -R -T -U; do
            secrets "sudo_value_${option#-}" deny Bash "sudo $option value cat .env"
            secrets "sudo_value_safe_${option#-}" allow Bash "sudo $option cat echo .env"
            secrets "sudo_missing_${option#-}" allow Bash "sudo $option"
        done
        secrets sudo_flags deny Bash 'sudo -n -E -H -- cat .env'
        secrets sudo_attached deny Bash 'sudo -uroot cat .env'
        secrets sudo_long deny Bash 'sudo --user=root cat .env'
        secrets sudo_shell deny Bash "sudo -s 'cat .env'"
        secrets sudo_login deny Bash "sudo -i 'cat .env'"
        secrets sudo_shell_safe allow Bash "sudo -s 'cat src/a.ts'"
        secrets sudo_unknown deny Bash 'sudo --unknown value cat .env'
        secrets sudo_unknown_safe allow Bash 'sudo --unknown value echo hello'
        secrets continuation_operand deny Bash $'cat \\\n.env'
        secrets continuation_command deny Bash $'ca\\\nt .env'
        secrets continuation_double deny Bash $'cat ".en\\\nv"'
        secrets continuation_safe allow Bash $'ca\\\nt src/a.ts'
        secrets continuation_single allow Bash $'echo \'hello\\\nworld\''
        secrets ansi_plain deny Bash "cat \$'.env'"
        secrets ansi_hex deny Bash "cat \$'\\x2eenv'"
        secrets ansi_octal deny Bash "cat \$'\\056env'"
        secrets ansi_join deny Bash "cat .e\$'n'v"
        secrets ansi_command deny Bash "\$'c\\x61t' .env"
        secrets ansi_newline allow Bash "echo \$'hello\\n'"
        secrets ansi_newline_reader deny Bash "cat \$'hello\\n' .env"
        secrets ansi_tab_reader deny Bash "cat \$'hello\\t' .env"
        secrets ansi_hex_short allow Bash "echo \$'\\x9hello'"
        secrets ansi_octal_short allow Bash "echo \$'\\7hello'"
        secrets ansi_quotes allow Bash "echo \$'\\\\\\\'\\\"'"
        secrets ansi_escapes allow Bash "echo \$'\\e\\a\\b\\f\\r\\v'"
        secrets ansi_escapes_analysed allow Bash "echo \$'\\e\\a\\b\\f\\r\\v' .env"
        secrets ansi_literal_substitution allow Bash "echo \$'\\'\$(cat .env)'"
        secrets ansi_nested_literal allow Bash "echo \"\$(echo \$'\\'\$(cat .env)')\""
        for escape in '.' '\U0000002e' '\cA' '\x' '\q' '\000' '\x1f' '\036'; do
            secrets "ansi_failure_$escape" deny Bash "cat .env \$'$escape'"
            secrets "ansi_failure_safe_$escape" allow Bash "echo \$'$escape'"
        done
        secrets locale_string deny Bash 'cat $".env"'
        secrets locale_safe allow Bash 'echo $"hello"'
        secrets control_separator deny Bash $'cat\x1f.env'
        secrets control_safe allow Bash $'echo hello\x1fworld'
        secrets control_carriage deny Bash $'cat .env\r'
        secrets control_del deny Bash $'cat .env\x7f'
        secrets unresolved_assignment deny Bash 'f=.env; cat $f'
        secrets unresolved_echo deny Bash 'cat $(echo .env)'
        secrets unresolved_printf deny Bash 'cat "$(printf .en; printf v)"'
        secrets unresolved_printf_args deny Bash 'cat "$(printf %s .en v)"'
        secrets unresolved_echo_args deny Bash 'cat "$(echo -n .en v)"'
        secrets unresolved_concat deny Bash 'cat .e$(printf n)v'
        secrets unresolved_backtick deny Bash 'cat `printf .en; printf v`'
        secrets unresolved_redirect deny Bash 'f=.env; wc < "$f"'
        secrets unresolved_redirect_literal deny Bash 'wc < "$(printf .en; printf v)"'
        secrets unresolved_xargs deny Bash 'f=.env; printf "%s" "$f" | xargs cat'
        secrets unresolved_xargs_literal deny Bash 'echo "$(printf .en; printf v)" | xargs cat'
        secrets unresolved_xargs_argfile deny Bash 'f=.env; xargs -a "$f" cat'
        secrets unresolved_file_safe allow Bash 'cat "$FILE"'
        secrets unresolved_positional_safe allow Bash 'cat "$1"'
        secrets unresolved_listing_safe allow Bash 'cat $(git ls-files | head -1)'
        secrets unresolved_wc_safe allow Bash 'wc -l $(ls src/*.ts)'
        secrets unresolved_redirect_safe allow Bash 'wc < "$FILE"'
        secrets unresolved_xargs_safe allow Bash 'printf "%s" "$FILE" | xargs cat'
        secrets unresolved_literal_safe allow Bash 'cat "$(printf src/; printf a.ts)"'
        secrets unresolved_no_eval allow Bash 'cat "$(touch should-not-exist; printf src/a.ts)"'
        secrets unresolved_quoted_parameter allow Bash "f=.env; cat '\$f'"
        secrets unresolved_escaped_parameter allow Bash 'f=.env; cat \$f'
        secrets unresolved_quoted_substitution allow Bash "cat '\$(echo .env)'"
        secrets unresolved_quoted_literal_name allow Bash "cat '\$(printf .en; printf v)'"
        secrets unresolved_pattern_file deny Bash 'f=.env; grep --file="$f" src/a.ts'
        secrets stash_stdout_file deny Bash 'gh auth token > f | secret stash a K'
        secrets stash_stdout_tight deny Bash 'gh auth token>f | secret stash a K'
        secrets stash_stdout_prefix deny Bash '>f gh auth token | secret stash a K'
        secrets stash_stdout_append deny Bash 'gh auth token >>f | secret stash a K'
        secrets stash_stdout_both deny Bash 'gh auth token &>f | secret stash a K'
        secrets stash_stdout_fd deny Bash 'gh auth token 1>f | secret stash a K'
        secrets stash_stdout_zero_fd deny Bash 'gh auth token 01>f | secret stash a K'
        secrets stash_stdout_dup deny Bash 'gh auth token >&2 | secret stash a K'
        secrets stash_stdout_quoted_fd deny Bash 'gh auth token "2">f | secret stash a K'
        secrets stash_stdout_escaped_fd deny Bash 'gh auth token \2>f | secret stash a K'
        secrets stash_quoted_operator allow Bash 'gh auth token ">" | secret stash a K'
        secrets stash_sink_output allow Bash 'gh auth token | secret stash a K > out'
        secrets stash_sink_output_tight allow Bash 'gh auth token | secret stash a K>>out'
        secrets stash_stderr_dup allow Bash 'gh auth token 2>&1 | secret stash a K'
        secrets stash_stderr_file allow Bash 'gh auth token 2>err | secret stash a K'
        secrets stash_tee deny Bash 'gh auth token | tee f | secret stash a K'
        secrets stash_extra deny Bash 'gh auth token | secret stash a K extra'
        secrets stash_wrapped deny Bash 'gh auth token | env secret stash a K'
        secrets stash_absolute allow Bash 'gh auth token | /usr/bin/secret stash a K'
        secrets stash_missing_redirect deny Bash 'gh auth token | secret stash a K >'
        for operation in 'xclip -o' 'xclip -selection clipboard -o' 'xsel -o' 'xsel -b -o' 'xsel --output'; do
            secrets "clipboard_$operation" deny Bash "$operation"
            secrets "clipboard_stash_$operation" allow Bash "$operation | secret stash a K"
            secrets "over_cap_clipboard_$operation" deny Bash "$operation # $LONG_TEXT"
        done
        secrets clipboard_write_xclip allow Bash 'xclip -i'
        secrets clipboard_write_xsel allow Bash 'xsel -i'
        for operation in 'kwallet-query --read-password mail wallet' 'kwallet-query --read-password=mail wallet' 'ps aEeww' 'security find-generic-password -w' 'gh auth token' 'git credential fill' declare 'jq -n env' 'wl-paste' pbpaste; do
            secrets "over_cap_parity_$risk_index" deny Bash "$operation # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done
        for safe_word in 'gcloudish auth print-access-token' 'awsome configure export-credentials' 'opportune read' 'passage show mail' 'secret-tooling lookup' 'kwallet-querying -r' 'psalm eww' 'declaration' 'typesetting' 'jqish environment' 'securityish find-password' 'ghastly auth token' 'git credentialed fill' 'xclipboard -o' 'xselection --output' 'wl-pasted' 'pbpasted'; do
            secrets "over_cap_safe_parity_$risk_index" allow Bash "echo $safe_word # $LONG_TEXT"
            risk_index=$((risk_index + 1))
        done

    }
else
    printf '%s\n' 'jq not installed; guard-secrets cases cannot run' >&2
    FAILED=$((FAILED + 1))
fi

# Covered scope scans preserve NUL-delimited names and fail closed beyond
# depth 12. Empty directories at the limit are still complete.
DEEP="$TMP/beyond-depth/a/b/c/d/e/f/g/h/i/j/k/l"
mkdir -p "$DEEP" "$TMP/newline-clean" "$TMP/newline-protected"
secrets depth_limit_empty allow Grep "$TMP/beyond-depth" '{"output_mode":"content"}'
mkdir "$DEEP/m"
printf '%s\n' synthetic >"$DEEP/m/private.secret"
secrets beyond_depth deny Grep "$TMP/beyond-depth" '{"output_mode":"content"}'
secrets beyond_depth_count deny Grep "$TMP/beyond-depth" '{"output_mode":"count"}'
secrets beyond_depth_names allow Grep "$TMP/beyond-depth" '{"output_mode":"files_with_matches"}'
printf '%s\n' synthetic >"$TMP/newline-clean/"$'.env\nordinary'
printf '%s\n' synthetic >"$TMP/newline-protected/"$'ordinary\nprivate.secret'
secrets newline_filename_clear allow Grep "$TMP/newline-clean" '{"output_mode":"content"}'
secrets newline_filename_protected deny Grep "$TMP/newline-protected" '{"output_mode":"content"}'
mkdir -p "$TMP/newline-ssh/.ssh"
printf '%s\n' synthetic >"$TMP/newline-ssh/.ssh/"$'id_demo.pub\n'
secrets newline_public_suffix deny Grep "$TMP/newline-ssh" '{"output_mode":"content"}'
# Hidden Git metadata and dependency trees are deliberately outside coverage;
# committed vendor trees remain covered regardless of ignore configuration.
for directory in node_modules .git vendor; do
    mkdir -p "$TMP/pruned-$directory/$directory/sub"
    secrets "pruned_clear_$directory" allow Grep "$TMP/pruned-$directory" '{"output_mode":"content"}'
    printf '%s\n' synthetic >"$TMP/pruned-$directory/$directory/sub/private.secret"
    expected=allow
    [[ "$directory" != vendor ]] || expected=deny
    secrets "pruned_protected_$directory" "$expected" Grep "$TMP/pruned-$directory" '{"output_mode":"content"}'
    secrets "pruned_names_$directory" allow Grep "$TMP/pruned-$directory" '{"output_mode":"files_with_matches"}'
done
for directory in node_modules .git; do
    mkdir -p "$TMP/pruned-deep-$directory/$directory/a/b/c/d/e/f/g/h/i/j/k/l/m"
    secrets "pruned_deep_$directory" allow Grep "$TMP/pruned-deep-$directory" '{"output_mode":"content"}'
    secrets "pruned_deep_count_$directory" allow Grep "$TMP/pruned-deep-$directory" '{"output_mode":"count"}'
done
if ((EUID != 0)); then
    mkdir -p "$TMP/find-error/unreadable"
    chmod 000 "$TMP/find-error/unreadable"
    secrets find_error deny Grep "$TMP/find-error" '{"output_mode":"content"}'
    secrets find_error_names allow Grep "$TMP/find-error" '{"output_mode":"files_with_matches"}'
    chmod 700 "$TMP/find-error/unreadable"
else
    printf '%s\n' 'SKIP find_error permissions: root can read mode-000 directories'
fi

# An absent, partial, unreadable or re-including config is not certification.
unset RIPGREP_CONFIG_PATH
secrets rg_without_config deny Bash 'rg TOKEN .'
secrets rg_without_config_default deny Bash 'rg TOKEN'
secrets rg_without_config_clean allow Bash 'rg TOKEN src'
secrets rg_without_config_file allow Bash 'rg TOKEN src/a.ts'
secrets rg_without_config_names allow Bash 'rg -l TOKEN .'
secrets rg_without_config_names_cluster allow Bash 'rg -nl TOKEN .'
secrets rg_without_config_names_long allow Bash 'rg --files-with-matches TOKEN .'
secrets rg_without_config_files allow Bash 'rg --files .'
secrets rg_without_config_count deny Bash 'rg -c TOKEN .'
secrets rg_without_config_count_long deny Bash 'rg --count TOKEN .'
secrets rg_without_config_count_cluster deny Bash 'rg -nc TOKEN .'
secrets rg_without_config_regexp deny Bash 'rg -e TOKEN .'
secrets rg_without_config_regexp_equals deny Bash 'rg --regexp=TOKEN .'
secrets rg_without_config_double_dash deny Bash 'rg TOKEN -- .'
secrets rg_without_config_multiple deny Bash 'rg TOKEN src sub'
secrets rg_without_config_cd allow Bash 'cd src && rg TOKEN'
secrets rg_without_config_glob deny Bash 'rg TOKEN s*'
secrets rg_without_config_unknown deny Bash 'rg --unknown src'
secrets rg_without_config_depth deny Bash "rg TOKEN '$TMP/beyond-depth'"
secrets rg_without_config_depth_names allow Bash "rg -l TOKEN '$TMP/beyond-depth'"
secrets rg_without_config_newline allow Bash "rg TOKEN '$TMP/newline-clean'"
secrets rg_without_config_pruned deny Bash "rg TOKEN '$TMP/pruned-vendor'"
for directory in node_modules .git; do
    secrets "rg_pruned_$directory" allow Bash "rg TOKEN '$TMP/pruned-$directory'"
    secrets "git_grep_pruned_$directory" allow Bash "git -C '$TMP/pruned-$directory' grep TOKEN"
    secrets "rg_pruned_deep_$directory" allow Bash "rg TOKEN '$TMP/pruned-deep-$directory'"
done
secrets git_grep deny Bash 'git grep TOKEN'
secrets git_grep_clean allow Bash 'git grep TOKEN -- src'
secrets git_grep_names allow Bash 'git grep -l TOKEN'
secrets git_grep_names_long allow Bash 'git grep --files-with-matches TOKEN'
secrets git_grep_count deny Bash 'git grep -c TOKEN'
secrets git_grep_file deny Bash 'git grep TOKEN -- .env'
secrets git_grep_regexp deny Bash 'git grep -e TOKEN'
secrets git_grep_pattern_file deny Bash 'git grep -f .env -- src'
secrets git_grep_global deny Bash 'git --no-pager grep TOKEN'
secrets git_grep_chdir allow Bash 'git -C src grep TOKEN'
secrets git_grep_chdir_protected deny Bash 'git -C sub grep TOKEN'
secrets git_grep_multiple_chdir allow Bash 'git -C sub -C ../src grep TOKEN'
secrets git_grep_config deny Bash 'git -c core.bare=false grep TOKEN'
secrets git_grep_revision deny Bash 'git grep TOKEN HEAD -- src'
secrets git_grep_over_cap deny Bash "git grep TOKEN # $LONG_TEXT"
secrets git_grep_global_over_cap deny Bash "git -C sub grep TOKEN # $LONG_TEXT"
secrets git_grep_unclosed deny Bash "git grep 'TOKEN"
export RIPGREP_CONFIG_PATH="$TMP/missing-rg-config"
secrets rg_missing_config deny Bash 'rg TOKEN .'
printf '%s\n' '--iglob=!.env' '--iglob=!*.secret' '--iglob=!.secrets/' >"$TMP/partial-rg-config"
export RIPGREP_CONFIG_PATH="$TMP/partial-rg-config"
secrets rg_partial_config deny Bash 'rg TOKEN .'
secrets rg_partial_config_clean allow Bash 'rg TOKEN src'
# Display and matching flags keep the scan fallback instead of denying outright.
printf '%s\n' '--iglob=!.env' '--smart-case' '--max-columns=200' '--max-columns-preview' >"$TMP/display-rg-config"
export RIPGREP_CONFIG_PATH="$TMP/display-rg-config"
secrets rg_display_config deny Bash 'rg TOKEN .'
secrets rg_display_config_clean allow Bash 'rg TOKEN src'
cat "$REPO_ROOT/examples/ripgreprc" >"$TMP/reinclude-rg-config"
printf '%s\n' '--iglob=.env' >>"$TMP/reinclude-rg-config"
export RIPGREP_CONFIG_PATH="$TMP/reinclude-rg-config"
secrets rg_reinclude_config deny Bash 'rg TOKEN .'
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"
secrets rg_with_config allow Bash 'rg TOKEN .'
secrets rg_with_config_count allow Bash 'rg -c TOKEN .'
secrets rg_with_config_explicit deny Bash 'rg TOKEN .env'
secrets rg_with_config_env_unset deny Bash 'env -u RIPGREP_CONFIG_PATH rg TOKEN .'
secrets rg_with_config_env_empty deny Bash 'env -i rg TOKEN .'
secrets rg_with_config_env_tab deny Bash $'env\t-i rg TOKEN .'
secrets rg_with_config_env_quoted deny Bash "'env' -i rg TOKEN ."
secrets rg_with_config_nested_env deny Bash "env -i bash -c 'rg TOKEN .'"
secrets rg_with_config_env_sibling allow Bash 'env -i true; rg TOKEN .'
secrets rg_with_config_exec deny Bash 'exec -lc rg TOKEN .'
secrets rg_with_config_sudo deny Bash 'sudo rg TOKEN .'
secrets rg_with_config_unset_nested deny Bash "unset RIPGREP_CONFIG_PATH; bash -c 'rg TOKEN .'"
secrets rg_with_config_env_override deny Bash 'RIPGREP_CONFIG_PATH=other rg TOKEN .'
secrets git_grep_ignores_rg_config deny Bash 'git grep TOKEN'
cat "$REPO_ROOT/examples/ripgreprc" >"$TMP/search/rg-config"
export RIPGREP_CONFIG_PATH=rg-config
secrets rg_relative_config allow Bash 'rg TOKEN .'
secrets rg_relative_config_chdir deny Bash 'cd sub && rg TOKEN .'
export RIPGREP_CONFIG_PATH="$TMP/empty-search"
secrets rg_directory_config deny Bash 'rg TOKEN .'
perl -e 'print "#", "x" x 9000' >"$TMP/large-rg-config"
export RIPGREP_CONFIG_PATH="$TMP/large-rg-config"
secrets rg_large_config deny Bash 'rg TOKEN .'
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"
printf '%s\n' synthetic >"$TMP/search/HEAD"
secrets git_grep_existing_revision deny Bash 'git grep TOKEN HEAD -- src'
perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$TMP/search" "$TMP/search-link"
secrets grep_root_symlink deny Grep "$TMP/search-link" '{"output_mode":"content"}'
unset RIPGREP_CONFIG_PATH
secrets rg_root_symlink deny Bash "rg TOKEN '$TMP/search-link'"
secrets rg_missing_path deny Bash "rg TOKEN '$TMP/no-such-search'"
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"

# Deterministic find failures cover root CI too, separately from permissions.
mkdir "$TMP/find-error-bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$TMP/find-error-bin/find"
chmod +x "$TMP/find-error-bin/find"
PATH="$TMP/find-error-bin:$PATH" secrets grep_find_exit deny Grep "$TMP/empty-search" '{"output_mode":"content"}'
PATH="$TMP/find-error-bin:$PATH" secrets grep_find_exit_count deny Grep "$TMP/empty-search" '{"output_mode":"count"}'
PATH="$TMP/find-error-bin:$PATH" secrets grep_find_exit_names allow Grep "$TMP/empty-search" '{"output_mode":"files_with_matches"}'
unset RIPGREP_CONFIG_PATH
PATH="$TMP/find-error-bin:$PATH" secrets rg_find_exit deny Bash 'rg TOKEN src'
PATH="$TMP/find-error-bin:$PATH" secrets rg_find_exit_names allow Bash 'rg -l TOKEN src'
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"

# A timeout in the names-only Grep fallback denies content but not filenames.
mkdir "$TMP/find-bin"
cat >"$TMP/find-bin/find" <<'EOF'
#!/usr/bin/env bash
exec sleep 1
EOF
chmod +x "$TMP/find-bin/find"
PATH="$TMP/find-bin:$PATH" secrets grep_timeout deny Grep "$TMP/empty-search" '{"output_mode":"content"}'
PATH="$TMP/find-bin:$PATH" secrets grep_timeout_names allow Grep "$TMP/empty-search" '{"output_mode":"files_with_matches"}'
PATH="$TMP/find-bin:$PATH" secrets grep_timeout_count deny Grep "$TMP/empty-search" '{"output_mode":"count"}'
unset RIPGREP_CONFIG_PATH
PATH="$TMP/find-bin:$PATH" secrets rg_timeout deny Bash 'rg TOKEN src'
PATH="$TMP/find-bin:$PATH" secrets rg_timeout_names allow Bash 'rg -l TOKEN src'
PATH="$TMP/find-bin:$PATH" secrets git_grep_timeout deny Bash 'git grep TOKEN -- src'
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"

# Audit regressions: certification must not hide command-line scope changes.
for flag in '--follow' '-L' '-u' '--search-zip' '--pre=cat' '--ignore-file=other' '--ignore-file-case-insensitive' '--no-ignore-vcs'; do
    secrets "rg_config_scope_$flag" deny Bash "rg $flag TOKEN src"
done
secrets rg_config_follow_names allow Bash 'rg --follow -l TOKEN src'
secrets rg_json_overrides_names deny Bash 'rg -l --json TOKEN .env'
mkdir "$TMP/search/.secrets"
printf '%s\n' 'TOKEN=synthetic-only' >"$TMP/search/.secrets/nested.ts"
secrets rg_glob_private_child deny Bash 'rg -g "*.ts" TOKEN .'
for flag in --no-index --untracked --cached; do
    secrets "git_scope_$flag" deny Bash "git grep $flag TOKEN -- src"
    secrets "git_scope_names_$flag" allow Bash "git grep $flag -l TOKEN -- src"
done
secrets git_revision_colon deny Bash 'git grep TOKEN HEAD:.env'

# Explicit pruned roots, including clean ones, are scanned rather than dropped.
unset RIPGREP_CONFIG_PATH
for directory in .git node_modules; do
    secrets "grep_explicit_$directory" deny Grep "$TMP/pruned-$directory/$directory" '{"output_mode":"content"}'
    secrets "grep_explicit_count_$directory" deny Grep "$TMP/pruned-$directory/$directory" '{"output_mode":"count"}'
    secrets "grep_explicit_names_$directory" allow Grep "$TMP/pruned-$directory/$directory"
    secrets "rg_explicit_$directory" deny Bash "rg --hidden TOKEN '$TMP/pruned-$directory/$directory'"
    secrets "rg_hidden_parent_$directory" deny Bash "rg --hidden TOKEN '$TMP/pruned-$directory'"
    mkdir -p "$TMP/clean-pruned/$directory"
    secrets "grep_explicit_clean_$directory" allow Grep "$TMP/clean-pruned/$directory" '{"output_mode":"content"}'
done

# Root aliases and aliases to individual files use resolved metadata, not data.
perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$TMP/search/.env" "$TMP/search/alias.txt"
perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$TMP/search/src/a.ts" "$TMP/search/code-link"
perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$TMP/upper-private/.Secrets" "$TMP/private-link"
secrets grep_alias deny Grep "$TMP/search/alias.txt" '{"output_mode":"content","glob":"*.txt","type":"txt","multiline":true,"-A":2,"head_limit":1}'
secrets grep_alias_count deny Grep alias.txt '{"output_mode":"count"}'
secrets grep_alias_names allow Grep alias.txt
secrets grep_code_alias allow Grep code-link '{"output_mode":"content"}'
secrets grep_missing_content deny Grep "$TMP/missing-input" '{"output_mode":"content"}'
secrets rg_alias_unconfigured deny Bash 'rg TOKEN alias.txt'
secrets git_pattern_alias deny Bash 'git grep -f alias.txt -- src'
secrets git_pattern_alias_attached deny Bash 'git grep -falias.txt -- src'
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"
secrets rg_alias_configured deny Bash 'rg TOKEN alias.txt'
secrets rg_code_alias allow Bash 'rg TOKEN code-link'
secrets rg_private_directory_alias deny Bash "rg TOKEN '$TMP/private-link'"
secrets rg_private_cwd_alias deny Bash "cd '$TMP/private-link' && rg TOKEN"
secrets rg_inline_config_clean deny Bash 'RIPGREP_CONFIG_PATH=other rg TOKEN src'
secrets rg_wrapper_config_clean deny Bash 'env -u OTHER rg TOKEN src'
secrets rg_config_filesystem_root deny Bash 'rg TOKEN /'
if [[ -d /proc/self ]]; then
    secrets rg_config_proc_root deny Bash 'rg TOKEN /proc/self'
fi
secrets rg_pattern_alias deny Bash 'rg --file=alias.txt src'
secrets rg_pattern_alias_names deny Bash 'rg -l -f alias.txt src'

# Config bytes and flags must be certified in full, never before a NUL.
for suffix in nul trailing crlf follow pre ignore reinclude; do
    cat "$REPO_ROOT/examples/ripgreprc" >"$TMP/audit-config"
    case "$suffix" in
        nul) printf '\000\n--glob=.env\n' >>"$TMP/audit-config" ;;
        trailing) printf '%s\n' '--iglob=!.env ' >>"$TMP/audit-config" ;;
        crlf) printf '%s\r\n' '--no-ignore' >>"$TMP/audit-config" ;;
        follow) printf '%s\n' '--follow' >>"$TMP/audit-config" ;;
        pre) printf '%s\n' '--pre=cat' >>"$TMP/audit-config" ;;
        ignore) printf '%s\n' '--ignore-file=other' >>"$TMP/audit-config" ;;
        reinclude) printf '%s\n' '--glob=.env' >>"$TMP/audit-config" ;;
    esac
    export RIPGREP_CONFIG_PATH="$TMP/audit-config"
    # Extra negative globs with whitespace do not undo existing exclusions.
    expected=deny
    [[ "$suffix" != trailing ]] || expected=allow
    secrets "rg_config_bytes_$suffix" "$expected" Bash 'rg TOKEN .'
    if [[ "$suffix" != trailing ]]; then
        secrets "rg_config_clean_$suffix" deny Bash 'rg TOKEN src'
    fi
done
for format in crlf spaces; do
    perl -pe 'BEGIN { $format = shift } if ($format eq "crlf") { s/\n/\r\n/ } else { s/\n/ \n/ }' "$format" <"$REPO_ROOT/examples/ripgreprc" >"$TMP/formatted-config"
    export RIPGREP_CONFIG_PATH="$TMP/formatted-config"
    secrets "rg_formatted_config_$format" deny Bash 'rg TOKEN .'
done
if ((EUID != 0)); then
    chmod 000 "$TMP/audit-config"
    export RIPGREP_CONFIG_PATH="$TMP/audit-config"
    secrets rg_unreadable_config deny Bash 'rg TOKEN src'
    chmod 600 "$TMP/audit-config"
fi
perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$REPO_ROOT/examples/ripgreprc" "$TMP/config-link"
export RIPGREP_CONFIG_PATH="$TMP/config-link"
secrets rg_config_symlink allow Bash 'rg TOKEN .'
export RIPGREP_CONFIG_PATH="$TMP/search/alias.txt"
secrets rg_config_protected_alias deny Bash 'rg TOKEN src'
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"

# JSON controls are rejected before raw extraction can silently alter fields.
for field in path glob type output_mode; do
    secrets "grep_nul_$field" deny Grep "$TMP/empty-search" "{\"output_mode\":\"content\",\"$field\":\".env\\u0000x\"}"
done
secrets grep_nul_traversal deny Grep "$TMP/empty-search" '{"path":"src\u0000/../.env","output_mode":"content"}'
secrets grep_control_glob deny Grep "$TMP/empty-search" '{"glob":"*.ts\u001f","output_mode":"count"}'
secrets bash_nul_reader deny Bash '' '{"command":"cat .env\u0000x"}'
secrets bash_nul_search deny Bash '' '{"command":"rg TOKEN src\u0000/../.env"}'
for tool in Read Edit Write; do
    secrets "file_nul_$tool" deny "$tool" '' '{"file_path":".env\u0000x"}'
done

# Missing scan dependencies cannot establish a clean content search.
mkdir "$TMP/missing-scan-bin"
for executable in bash cat jq tr; do
    perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$(command -v "$executable")" "$TMP/missing-scan-bin/$executable"
done
# The harness needs Perl for its outer watchdog; this shim removes the scan
# tools only from the guard process, without changing the parent test runner.
printf '#!%s\nexport PATH=%q\nexec %q %q\n' "$BASH" "$TMP/missing-scan-bin" "$BASH" "$REPO_ROOT/hooks/guard-secrets" >"$TMP/missing-scan-guard"
SECRETS_GUARD="$TMP/missing-scan-guard"
secrets grep_missing_perl deny Grep "$TMP/empty-search" '{"output_mode":"content"}'
secrets grep_missing_perl_names allow Grep "$TMP/empty-search"
secrets rg_missing_perl_config deny Bash 'rg TOKEN src'
unset RIPGREP_CONFIG_PATH
secrets rg_missing_perl deny Bash 'rg TOKEN src'
perl -e 'symlink $ARGV[0], $ARGV[1] or die $!' "$(command -v perl)" "$TMP/missing-scan-bin/perl"
secrets grep_missing_find deny Grep "$TMP/empty-search" '{"output_mode":"content"}'
secrets rg_missing_find deny Bash 'rg TOKEN src'
SECRETS_GUARD="$REPO_ROOT/hooks/guard-secrets"
export RIPGREP_CONFIG_PATH="$REPO_ROOT/examples/ripgreprc"

mkdir "$TMP/missing-jq-bin"
printf '#!%s\nexport PATH=%q\nexec %q %q\n' "$BASH" "$TMP/missing-jq-bin" "$BASH" "$REPO_ROOT/hooks/guard-secrets" >"$TMP/missing-jq-guard"
SECRETS_GUARD="$TMP/missing-jq-guard"
secrets grep_missing_jq deny Grep "$TMP/empty-search" '{"output_mode":"content"}'
secrets rg_missing_jq deny Bash 'rg TOKEN src'
SECRETS_GUARD="$REPO_ROOT/hooks/guard-secrets"
FAILURE_OUTPUT="$(printf '%s' '{"tool_name":"Grep","cwd":"src\u0000/../.env","tool_input":{"output_mode":"content"}}' | "$BASH" "$SECRETS_GUARD")"
if printf '%s' "$FAILURE_OUTPUT" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null; then
    PASSED=$((PASSED + 1))
else
    FAILED=$((FAILED + 1))
    printf 'FAIL NUL in cwd must be denied before extraction\n'
fi

# Narrow analysis failures use an exact fixed reason, never command text.
FIXED_REASON='command too complex to analyse for secret access; split it or use secret run'
FAILURE_OUTPUT="$(jq -cn --arg c "cat .env '" --arg w "$TMP/search" '{tool_name:"Bash",cwd:$w,tool_input:{command:$c}}' | "$BASH" "$SECRETS_GUARD")"
if printf '%s' "$FAILURE_OUTPUT" | jq -e --arg reason "$FIXED_REASON" '.hookSpecificOutput.permissionDecision == "deny" and .hookSpecificOutput.permissionDecisionReason == $reason' >/dev/null; then
    PASSED=$((PASSED + 1))
else
    FAILED=$((FAILED + 1))
    printf 'FAIL fixed complexity reason\n'
fi

# Invalid control bytes must reach raw recovery, not change token boundaries.
for json_command in '"echo .env\u0000"' '"echo .env\u001f"' '"echo .env\u000b"' '"echo .env\u007f"'; do
    FAILURE_OUTPUT="$(jq -cn --argjson c "$json_command" '{tool_name:"Bash",tool_input:{command:$c}}' | "$BASH" "$SECRETS_GUARD")"
    if printf '%s' "$FAILURE_OUTPUT" | jq -e --arg reason "$FIXED_REASON" '.hookSpecificOutput.permissionDecision == "deny" and .hookSpecificOutput.permissionDecisionReason == $reason' >/dev/null; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL control byte must use raw recovery: %s\n' "$json_command"
    fi
done
if [[ ! -e "$TMP/search/should-not-exist" ]]; then
    PASSED=$((PASSED + 1))
else
    FAILED=$((FAILED + 1))
    printf 'FAIL command substitution was executed\n'
fi

# Malformed JSON and empty stdin still produce no decision.
if [[ -z "$(printf '%s' malformed | "$BASH" "$SECRETS_GUARD")" ]]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
if [[ -z "$(printf '%s' 'malformed cat .env' | "$BASH" "$SECRETS_GUARD")" ]]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
if [[ -z "$(PATH="$TMP/empty-search" "$BASH" "$SECRETS_GUARD" </dev/null)" ]]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi

printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[[ "$FAILED" -eq 0 ]]
