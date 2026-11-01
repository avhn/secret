#!/bin/sh
# shellcheck disable=SC2015 # Every failed guard must fail the operation.
# HTTPS script execution is the bootstrap trust root. Review/download is stronger.
# Define everything before the final invocation to mitigate truncated pipe input.
secret_install() {
    set -f
    umask 077
    LC_ALL=C
    export LC_ALL
    fail() { printf 'secret: %s\n' "${1:-release installation failed}" >&2; exit 1; }
    version=${SECRET_VERSION-}
    directory=${INSTALL_DIR-}
    seen_version=no; seen_dir=no; show_help=no
    [ "${SECRET_RELEASE_COMMIT+x}" != x ] || fail 'commit pinning was removed; see docs/install.md for checkout verification'
    while [ "$#" -gt 0 ]; do
        case $1 in
            --commit) fail 'commit pinning was removed; see docs/install.md for checkout verification' ;;
            --help|-h) show_help=yes; shift ;;
            --version)
                [ "$#" -ge 2 ] && [ "$seen_version" = no ] || fail 'invalid arguments'
                [ -z "$version" ] || [ "${version#v}" = "${2#v}" ] || fail 'conflicting version pins'
                version=$2; seen_version=yes; [ -n "$version" ] || fail 'invalid version'; shift 2 ;;
            --dir)
                [ "$#" -ge 2 ] && [ "$seen_dir" = no ] && [ -n "$2" ] || fail 'invalid arguments'
                directory=$2; seen_dir=yes; shift 2 ;;
            *) fail 'invalid arguments (use --help)' ;;
        esac
    done
    if [ "$show_help" = yes ]; then
        printf '%s\n' 'Usage: sh install.sh [--version V] [--dir DIR]' \
            'Defaults to the latest release and ~/.local/bin. SECRET_VERSION and INSTALL_DIR are supported.' \
            'Requires curl and sha256sum or shasum. No PATH/profile or store changes.'
        exit 0
    fi
    valid_version() { printf '%s\n' "$1" | awk '/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/ {ok=1} END {exit !(NR==1 && ok)}'; }
    version=${version#v}
    if [ "${SECRET_VERSION+x}" = x ] || [ "$seen_version" = yes ]; then
        valid_version "$version" || fail 'invalid version'
    fi
    for tool in curl uname id stat awk wc cmp chmod mv rm rmdir mkdir mktemp sleep od tr cat; do
        command -v "$tool" >/dev/null 2>&1 || fail "missing dependency: $tool"
    done
    if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
    else fail 'sha256sum or shasum is required'; fi
    case $(uname -s) in Linux) os=linux ;; Darwin) os=darwin ;; *) fail 'unsupported platform' ;; esac
    case $(uname -m) in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'unsupported architecture' ;; esac
    uid=$(id -u) || fail
    attributes() {
        bsd=no
        attrs=$(stat -c '%u %a %h' "$1" 2>/dev/null) || { attrs=$(stat -f '%u %p %l' "$1" 2>/dev/null) && bsd=yes; } || return 1
        owner=${attrs%% *}; rest=${attrs#* }; mode=${rest%% *}; links=${rest#* }
        # BSD %Lp drops the sticky bit; %p carries the file type too. Keep the last four
        # octal digits and drop one leading zero so modes match GNU %a (755, 1777).
        if [ "$bsd" = yes ]; then mode=${mode#"${mode%????}"}; mode=${mode#0}; fi
        case $owner:$links in *[!0-9:]*|:*) return 1 ;; esac
        case $mode in *[!0-7]*|'') return 1 ;; esac
        [ "$owner" = "$uid" ] || [ "$owner" = 0 ]
    }
    safe_node() {
        [ ! -L "$1" ] && attributes "$1" || return 1
        if [ -f "$1" ]; then [ "$links" = 1 ] || return 1
        else [ -d "$1" ] || return 1; fi
        [ $((0$mode & 022)) -eq 0 ] && return 0
        [ -d "$1" ] && [ "$owner" = 0 ] && [ $((0$mode & 01000)) -ne 0 ]
    }
    safe_chain() {
        path=$1
        while :; do
            safe_node "$path" || return 1
            [ "$path" != / ] || break
            path=${path%/*}; [ -n "$path" ] || path=/
        done
    }
    make_chain() {
        [ ! -L "$1" ] || return 1
        if [ -e "$1" ]; then [ -d "$1" ] && safe_chain "$1"; return; fi
        ancestor=${1%/*}; [ -n "$ancestor" ] || ancestor=/
        make_chain "$ancestor" && { mkdir "$1" 2>/dev/null || [ -d "$1" ]; } && safe_chain "$1"
    }
    safe_directory() { [ -d "$directory" ] && safe_node "$directory" && [ "$owner" = "$uid" ] && [ $((0$mode & 022)) -eq 0 ]; }
    private_dir() { [ -d "$1" ] && safe_node "$1" && [ "$owner" = "$uid" ] && [ "$mode" = 700 ]; }
    private_file() { [ -f "$1" ] && safe_node "$1" && [ "$owner" = "$uid" ] && [ "$mode" = "$2" ]; }
    bounded_file() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(wc -c <"$1")" -le "$2" ]; }
    check_target() {
        [ ! -L "$target" ] || return 1
        if [ -e "$target" ]; then private_file "$target" 500 && bounded_file "$target" 67108864; fi
    }
    digest() {
        if [ "$hash_tool" = sha256sum ]; then sha256sum <"$1"; else shasum -a 256 <"$1"; fi | awk '{print $1}'
    }
    [ -n "$directory" ] || directory=${HOME:?HOME is required}/.local/bin
    case $directory in /*) ;; *) directory=$PWD/$directory ;; esac
    case $directory in */../*|*/./*|*/..|*/.) fail 'unsafe install directory' ;; esac
    [ "$(printf '%s' "$directory" | tr -d '[:cntrl:]')" = "$directory" ] || fail 'unsafe install directory'
    while [ "${directory%/}" != "$directory" ]; do directory=${directory%/}; done
    [ -n "$directory" ] || fail 'unsafe install directory'
    # Bind symlinked ancestors (macOS /var and /tmp) to their physical path once.
    # The install directory itself must never be a symlink.
    [ ! -L "$directory" ] || fail 'unsafe install directory; use a user-owned directory and chmod go-w DIR'
    existing=$directory; remainder=
    while [ ! -e "$existing" ] && [ ! -L "$existing" ]; do
        remainder=/${existing##*/}$remainder; existing=${existing%/*}; [ -n "$existing" ] || existing=/
    done
    physical=$(cd -P -- "$existing" 2>/dev/null && pwd -P) || fail 'unsafe install directory'
    directory=${physical%/}$remainder
    make_chain "$directory" && safe_directory || fail 'unsafe install directory; use a user-owned directory and chmod go-w DIR'
    target=$directory/secret
    check_target || fail 'unsafe destination'
    scratch=$(mktemp -d "$directory/.secret-install-XXXXXXXXXX") || fail
    lock=$directory/.secret.install-lock
    token=${scratch##*/}; locked=no; worker=; watchdog=
    # shellcheck disable=SC2329 # Called by traps.
    cleanup() {
        if [ -n "$worker" ]; then kill -KILL "$worker" 2>/dev/null || :; wait "$worker" 2>/dev/null || :; fi
        if [ -n "$watchdog" ]; then kill "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; fi
        if [ "$locked" = yes ] && private_dir "$lock" && private_file "$lock/owner" 600 &&
            printf 'pid=%s\ntoken=%s\n' "$$" "$token" | cmp -s - "$lock/owner"; then
            rm -f "$lock/owner"; rmdir "$lock" 2>/dev/null || :
        fi
        rm -rf "$scratch"
    }
    trap cleanup 0
    trap 'exit 1' HUP INT TERM
    tries=0
    until mkdir "$lock" 2>/dev/null; do
        private_dir "$lock" || fail 'unsafe installation lock'
        tries=$((tries + 1))
        [ "$tries" -lt 4 ] || fail 'installation lock timeout; verify and remove stale lock manually'
        sleep 1
    done
    locked=yes
    printf 'pid=%s\ntoken=%s\n' "$$" "$token" >"$lock/owner" || fail
    # Each response has a fresh body/header directory. No automatic redirects.
    request=0
    fetch() {
        request=$((request + 1))
        mkdir "$scratch/body-$request" "$scratch/header-$request" || fail
        body=$scratch/body-$request/asset; headers=$scratch/header-$request/response
        file_limit=$2; [ "$file_limit" -ge 65536 ] || file_limit=65536
        (ulimit -f "$(((file_limit + 511) / 512))" || exit 1; exec curl --silent --proto '=https' --proto-redir '=https' --max-redirs 0 \
            --connect-timeout 10 --max-time 60 --max-filesize "$2" \
            --dump-header "$headers" --output "$body" --write-out '%{http_code}' "$1" </dev/null >"$scratch/code" 2>/dev/null) &
        worker=$!
        (
            ticks=0
            while kill -0 "$worker" 2>/dev/null; do
                if [ "$ticks" -ge 65 ] ||
                    { [ -f "$headers" ] && ! bounded_file "$headers" 65536; } ||
                    { [ -f "$body" ] && ! bounded_file "$body" "$2"; }; then
                    kill -KILL "$worker" 2>/dev/null; exit
                fi
                sleep 1; ticks=$((ticks + 1))
            done
        ) </dev/null >/dev/null 2>&1 &
        watchdog=$!
        result=0; wait "$worker" || result=$?; worker=
        kill "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; watchdog=
        [ "$result" -eq 0 ] && bounded_file "$scratch/code" 3 || fail
        code=$(cat "$scratch/code")
        bounded_file "$body" "$2" && bounded_file "$headers" 65536 || fail 'oversized response'
    }
    location() {
        # Shell variables cannot preserve NUL bytes; reject them before extraction.
        [ "$(tr -d '\000' <"$headers" | wc -c)" -eq "$(wc -c <"$headers")" ] || fail 'invalid redirect'
        url=$(awk 'tolower(substr($0,1,9))=="location:" {sub(/\r$/, ""); sub(/^[^:]*:[ \t]*/, ""); print; n++} END {if(n!=1) exit 1}' "$headers") || fail 'invalid redirect'
        [ "$(printf '%s' "$url" | tr -d '[:cntrl:] ')" = "$url" ] || fail 'unsafe redirect'
        case $url in *\\*) fail 'unsafe redirect' ;; esac
    }
    if [ -z "$version" ]; then
        fetch https://github.com/avhn/secret/releases/latest 4096
        case $code in 301|302|303|307|308) ;; *) fail 'invalid latest redirect' ;; esac
        location
        case $url in https://github.com/avhn/secret/releases/tag/v*) version=${url#https://github.com/avhn/secret/releases/tag/v} ;; *) fail 'invalid latest redirect' ;; esac
        valid_version "$version" || fail 'invalid latest version'
    fi
    tag=v$version; asset=secret-$tag-$os-$arch
    download() {
        url=https://github.com/avhn/secret/releases/download/$tag/$1
        redirects=0
        while :; do
            fetch "$url" "$2"
            case $code in
                200) break ;;
                301|302|303|307|308)
                    [ "$redirects" -lt 3 ] || fail 'redirect limit'
                    location
                    case $url in https://github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*) ;; *) fail 'unsafe redirect' ;; esac
                    redirects=$((redirects + 1)) ;;
                *) fail 'release asset download failed' ;;
            esac
        done
    }
    download "checksums-$tag.txt" 4096
    manifest=$body
    [ "$(tr -d '\012\040-\176' <"$manifest" | wc -c)" -eq 0 ] || fail 'invalid checksum manifest'
    [ "$(wc -l <"$manifest")" -eq 8 ] || fail 'invalid checksum manifest'
    sha=$(awk -v tag="$tag" -v asset="$asset" '
        BEGIN {p="secret-" tag "-"; name[1]=p "darwin-amd64"; name[2]=p "darwin-arm64";
          name[3]=p "desktop.mcpb"; name[4]=p "linux-amd64"; name[5]=p "linux-arm64";
          name[6]=p "windows-amd64.exe"; name[7]=p "windows-arm64.exe"; name[8]="server.json"}
        {if (NR>8 || length(substr($0,1,64))!=64 || substr($0,1,64) ~ /[^0-9a-f]/ ||
             substr($0,65,2)!="  " || substr($0,67)!=name[NR]) bad=1;
         if(substr($0,67)==asset) {digest=substr($0,1,64); found++}}
        END {if(bad || NR!=8 || found!=1) exit 1; print digest}' "$manifest") || fail 'invalid checksum manifest'
    safe_chain "$directory" && safe_directory && check_target || fail 'unsafe destination'
    if [ -f "$target" ] && [ "$(digest "$target")" = "$sha" ]; then
        printf 'secret %s is already installed at %s\n' "$version" "$target"
        exit 0
    fi
    download "$asset" 67108864
    binary=$body
    [ "$(digest "$binary")" = "$sha" ] || fail 'checksum mismatch'
    header=$(od -An -tx1 -N20 "$binary" | tr -d ' \n') || fail
    case $os:$arch:$header in
        linux:amd64:7f454c460201????????????????????????3e00|linux:arm64:7f454c460201????????????????????????b700) ;;
        darwin:amd64:cffaedfe07000001*|darwin:arm64:cffaedfe0c000001*) ;;
        *) fail 'wrong executable format or architecture' ;;
    esac
    chmod 500 "$binary" || fail
    # Older releases expose only the version subcommand. Check only the new file.
    version_arg=--version
    case $version in 0.[0-4].*) version_arg=version ;; esac
    # Bound regular-file output and runtime; stdin is detached.
    (ulimit -f 2 || exit 1; exec "$binary" "$version_arg" </dev/null >"$scratch/version" 2>"$scratch/error") &
    worker=$!
    (sleep 10; kill -KILL "$worker" 2>/dev/null) </dev/null >/dev/null 2>&1 &
    watchdog=$!
    result=0; wait "$worker" || result=$?
    worker=
    kill "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; watchdog=
    [ "$result" -eq 0 ] && bounded_file "$scratch/version" 256 && bounded_file "$scratch/error" 1024 || fail 'invalid version output'
    printf 'secret %s (go)\n' "$version" | cmp -s - "$scratch/version" || fail 'wrong version'
    [ "$(digest "$binary")" = "$sha" ] || fail 'modified binary'
    safe_chain "$directory" && safe_directory && check_target && private_file "$binary" 500 || fail 'unsafe destination'
    mv -f "$binary" "$target" || fail
    printf 'Installed secret %s at %s\n' "$version" "$target"
}
secret_install "$@"
