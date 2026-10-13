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

    }
else
    printf '%s\n' 'jq not installed; guard-secrets cases cannot run' >&2
    FAILED=$((FAILED + 1))
fi

# A timeout in the names-only Grep fallback denies content but not filenames.
mkdir "$TMP/find-bin"
cat >"$TMP/find-bin/find" <<'EOF'
#!/usr/bin/env bash
exec sleep 1
EOF
chmod +x "$TMP/find-bin/find"
PATH="$TMP/find-bin:$PATH" secrets grep_timeout deny Grep "$TMP/empty-search" '{"output_mode":"content"}'
PATH="$TMP/find-bin:$PATH" secrets grep_timeout_names allow Grep "$TMP/empty-search" '{"output_mode":"files_with_matches"}'

# Narrow analysis failures use an exact fixed reason, never command text.
FIXED_REASON='command too complex to analyse for secret access; split it or use secret run'
FAILURE_OUTPUT="$(jq -cn --arg c "cat .env '" --arg w "$TMP/search" '{tool_name:"Bash",cwd:$w,tool_input:{command:$c}}' | "$BASH" "$SECRETS_GUARD")"
if printf '%s' "$FAILURE_OUTPUT" | jq -e --arg reason "$FIXED_REASON" '.hookSpecificOutput.permissionDecision == "deny" and .hookSpecificOutput.permissionDecisionReason == $reason' >/dev/null; then
    PASSED=$((PASSED + 1))
else
    FAILED=$((FAILED + 1))
    printf 'FAIL fixed complexity reason\n'
fi

# Missing jq and malformed JSON are intentional fail-open boundaries.
if [[ -z "$(printf '%s' malformed | "$BASH" "$SECRETS_GUARD")" ]]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
if [[ -z "$(printf '%s' 'malformed cat .env' | "$BASH" "$SECRETS_GUARD")" ]]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi
if [[ -z "$(PATH="$TMP/empty-search" "$BASH" "$SECRETS_GUARD" </dev/null)" ]]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); fi

printf '%s passed, %s failed (%s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[[ "$FAILED" -eq 0 ]]
