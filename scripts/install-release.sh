#!/bin/sh
# shellcheck disable=SC2015 # Guard chains deliberately fail if any check fails.
# Explicit preinstallation from a trusted checkout. Launchers use only --offline.
set -f
umask 077
LC_ALL=C
export LC_ALL
version=0.3.3
tag=v0.3.3
scratch=
locked=no

fail() {
    case $1 in
        2) message='usage: scripts/install-release.sh [--from-dir DIR] [--offline]' ;;
        3) message='secret: installation lock timeout; verify and remove stale lock manually' ;;
        4) message='secret: unsupported platform or missing dependency' ;;
        *) message='secret: release installation failed' ;;
    esac
    printf '%s\n' "$message" >&2
    exit "$1"
}

for tool in dirname readlink uname; do
    command -v "$tool" >/dev/null 2>&1 || fail 4
done
# Resolve entrypoint links only. Manifest and cache links are never followed.
entry=$0
case $entry in /*) ;; *) entry=$PWD/$entry ;; esac
n=0
while :; do
    parent=$(CDPATH='' cd -P "$(dirname "$entry")" 2>/dev/null && pwd -P) || fail 1
    entry=$parent/${entry##*/}
    [ -L "$entry" ] || break
    n=$((n + 1))
    [ "$n" -le 32 ] || fail 1
    link=$(readlink "$entry" 2>/dev/null) || fail 1
    case $link in /*) entry=$link ;; *) entry=$parent/$link ;; esac
done
[ -f "$entry" ] || fail 1
root=$(CDPATH='' cd -P "$parent/.." 2>/dev/null && pwd -P) || fail 1

from=
offline=no
while [ "$#" -gt 0 ]; do
    case $1 in
        --offline) [ "$offline" = no ] || fail 2; offline=yes; shift ;;
        --from-dir)
            [ "$#" -ge 2 ] && [ -z "$from" ] && [ -n "$2" ] || fail 2
            case $2 in --*) fail 2 ;; esac
            from=$2; shift 2 ;;
        *) fail 2 ;;
    esac
done

for tool in id stat awk wc cmp chmod mv cp rm rmdir mkdir mktemp sleep git; do
    command -v "$tool" >/dev/null 2>&1 || fail 4
done
if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
else fail 4
fi
uid=$(id -u) || fail 4

# GNU and BSD stat both report lstat information by default.
attributes() {
    attrs=$(stat -c '%u %a %h' "$1" 2>/dev/null) ||
        attrs=$(stat -f '%u %Lp %l' "$1" 2>/dev/null) || return 1
    owner=${attrs%% *}
    rest=${attrs#* }; mode=${rest%% *}; links=${rest#* }
    case $owner:$links in *[!0-9:]*|:*) return 1 ;; esac
    case $mode in *[!0-7]*|'') return 1 ;; esac
    [ "$owner" = "$uid" ] || [ "$owner" = 0 ] || return 1
}
safe_node() {
    [ ! -L "$1" ] && attributes "$1" || return 1
    if [ -f "$1" ]; then [ "$links" = 1 ] || return 1; fi
    [ $((0$mode & 022)) -eq 0 ] && return 0
    # A root-owned sticky system temporary directory is not a writable checkout.
    [ -d "$1" ] && [ "$owner" = 0 ] && [ $((0$mode & 01000)) -ne 0 ]
}
safe_chain() {
    path=$1
    case $path in /*) ;; *) return 1 ;; esac
    case $path in *'
'*|*/../*|*/./*|*/..|*/.) return 1 ;; esac
    while :; do
        safe_node "$path" || return 1
        [ "$path" != / ] && [ "$path" != "${HOME-}" ] || break
        path=${path%/*}
        [ -n "$path" ] || path=/
    done
}
private_dir() {
    [ -d "$1" ] && safe_node "$1" && [ "$owner" = "$uid" ] && [ "$mode" = 700 ]
}
private_file() {
    [ -f "$1" ] && safe_node "$1" && [ "$owner" = "$uid" ] && [ "$mode" = "$2" ]
}
bounded_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(wc -c <"$1")" -le "$2" ]
}
digest() {
    if [ "$hash_tool" = sha256sum ]; then sha256sum <"$1"
    else shasum -a 256 <"$1"
    fi | awk '{print $1}'
}

safe_chain "$entry" && safe_chain "$root" || fail 1
manifest=$root/dist/checksums-v$version.txt
safe_chain "$manifest" && bounded_file "$manifest" 4096 || fail 1
# Historical genuine-provenance rehearsals substitute the compiled-in identity.
# There is no runtime override and a 0.3.3 manifest always requires all eight names.
case $version in
    0.2.0|0.2.1|0.2.2|0.2.3) records=4 ;;
    0.3.0|0.3.1|0.3.2|0.3.3) records=8 ;;
    *) fail 1 ;;
esac
# Check bytes as well as records: wc rejects a missing final LF.
[ "$(wc -l <"$manifest")" -eq "$records" ] || fail 1
awk -v version="$version" -v records="$records" '
BEGIN {
    prefix="secret-v" version "-"
    name[1]=prefix "darwin-amd64"; name[2]=prefix "darwin-arm64"
    if (records == 4) {
        name[3]=prefix "linux-amd64"; name[4]=prefix "linux-arm64"
    } else {
        name[3]=prefix "desktop.mcpb"
        name[4]=prefix "linux-amd64"; name[5]=prefix "linux-arm64"
        name[6]=prefix "windows-amd64.exe"; name[7]=prefix "windows-arm64.exe"
        name[8]="server.json"
    }
}
NR > records { exit 1 }
{ if (length(substr($0,1,64)) != 64 || substr($0,1,64) ~ /[^0-9a-f]/ ||
      substr($0,65,2) != "  " || substr($0,67) != name[NR]) exit 1 }
END { if (NR != records) exit 1 }
' "$manifest" || fail 1
case $(uname -s 2>/dev/null) in Linux) os=linux ;; Darwin) os=darwin ;; *) fail 4 ;; esac
case $(uname -m 2>/dev/null) in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 4 ;; esac
asset=secret-v$version-$os-$arch
sha=$(awk -v name="$asset" 'substr($0,67)==name {print substr($0,1,64)}' "$manifest")
[ "${#sha}" -eq 64 ] || fail 1

fixture=no
if [ -n "${SECRET_RELEASE_TEST_ROOT-}" ]; then
    private_file "$root/.secret-release-test-fixture" 600 || fail 1
    fixture=yes
    base=$SECRET_RELEASE_TEST_ROOT
    commit=fixture
else
    [ -n "${HOME-}" ] || fail 1
    base=${XDG_CACHE_HOME:-$HOME/.cache}
    # HEAD and the locally trusted tag are the pin, not a field committed at C.
    commit=$(git -C "$root" rev-parse --verify HEAD 2>/dev/null) || fail 1
    [ "$(git -C "$root" cat-file -t "refs/tags/$tag" 2>/dev/null)" = tag ] || fail 1
    tagged=$(git -C "$root" rev-parse --verify "refs/tags/$tag^{commit}" 2>/dev/null) || fail 1
    [ "$commit" = "$tagged" ] && [ "${#commit}" -eq 40 ] || fail 1
    git -C "$root" show "HEAD:dist/checksums-v$version.txt" 2>/dev/null |
        cmp -s - "$manifest" || fail 1
fi
case $base in /*) ;; *) fail 1 ;; esac
# Normalize trailing slashes, but never canonicalize away a cache symlink.
while [ "${base%/}" != "$base" ]; do base=${base%/}; done
[ -n "$base" ] || fail 1
cache=$base/secret/v$version

metadata() {
    printf 'version=%s\nasset=%s\nsha256=%s\ncommit=%s\ntag=%s\n' "$version" "$asset" "$sha" "$commit" "$tag"
}
current() {
    safe_chain "$cache" && private_dir "$cache" &&
        private_file "$cache/secret" 500 && bounded_file "$cache/secret" 67108864 &&
        private_file "$cache/verified" 600 && bounded_file "$cache/verified" 512 &&
        metadata | cmp -s - "$cache/verified" || return 1
    [ "$(digest "$cache/secret")" = "$sha" ]
}
if current 2>/dev/null; then exit 0; fi
# No cold network bootstrap, lock waiting or directory creation in the hook path.
[ "$offline" != yes ] || [ -n "$from" ] || fail 1
[ "$fixture" != yes ] || [ -n "$from" ] || fail 1
command -v python3 >/dev/null 2>&1 || fail 4
if [ "$fixture" = no ]; then
    command -v gh >/dev/null 2>&1 || fail 4
    if [ -z "$from" ]; then command -v curl >/dev/null 2>&1 || fail 4; fi
fi

# Create each missing component privately, and check existing ancestors first.
make_chain() {
    [ ! -L "$1" ] || return 1
    if [ -e "$1" ]; then [ -d "$1" ] && safe_chain "$1"; return; fi
    ancestor=${1%/*}
    [ -n "$ancestor" ] || ancestor=/
    make_chain "$ancestor" && { mkdir "$1" 2>/dev/null || [ -d "$1" ]; } && safe_chain "$1"
}
make_chain "$cache" && private_dir "$cache" || fail 1
lock=$cache.lock
lock_parent=${cache%/*}
scratch=$(mktemp -d "$lock_parent/.install.XXXXXXXXXX") || fail 1
token=${scratch##*.install.}
# shellcheck disable=SC2329 # Invoked by the exit trap.
cleanup() {
    if [ "$locked" = yes ] && [ ! -L "$lock" ] && private_file "$lock/owner" 600 &&
        printf 'pid=%s\ntoken=%s\n' "$$" "$token" | cmp -s - "$lock/owner"; then
        rm -f "$lock/owner"
        rmdir "$lock" 2>/dev/null || :
    fi
    [ -z "$scratch" ] || rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
tries=0
until mkdir "$lock" 2>/dev/null; do
    [ ! -L "$lock" ] && private_dir "$lock" || fail 1
    tries=$((tries + 1))
    [ "$tries" -lt 4 ] || fail 3
    sleep 1
done
locked=yes
printf 'pid=%s\ntoken=%s\n' "$$" "$token" >"$lock/owner" || fail 1
if current 2>/dev/null; then exit 0; fi
# Refuse aliased publication destinations, even when mv could replace a link.
for destination in secret verified attestation.jsonl trusted_root.jsonl; do
    target=$cache/$destination
    [ ! -L "$target" ] || fail 1
    if [ -e "$target" ]; then safe_node "$target" && [ -f "$target" ] || fail 1; fi
done
mkdir "$scratch/input" "$scratch/bundle" "$scratch/trust" "$scratch/output" || fail 1
if [ -n "$from" ]; then
    from=$(CDPATH='' cd -P "$from" 2>/dev/null && pwd -P) || fail 1
    bounded_file "$from/$asset" 67108864 || fail 1
    cp "$from/$asset" "$scratch/input/$asset" || fail 1
else
    # Follow only explicitly allowed HTTPS release hosts. Each response gets its
    # own empty directory; headers and bodies are never interpreted as code.
    url=https://github.com/avhn/secret/releases/download/$tag/$asset
    redirects=0
    while :; do
        body=$scratch/body-$redirects
        headers=$scratch/headers-$redirects
        mkdir "$body" "$headers" || fail 1
        code=$(curl --silent --proto '=https' --proto-redir '=https' --max-redirs 0 \
            --connect-timeout 10 --max-time 60 --max-filesize 67108864 \
            --dump-header "$headers/response" --output "$body/asset" \
            --write-out '%{http_code}' "$url" 2>/dev/null) || fail 1
        case $code in
            200) mv "$body/asset" "$scratch/input/$asset" || fail 1; break ;;
            301|302|303|307|308)
                [ "$redirects" -lt 3 ] && bounded_file "$headers/response" 65536 || fail 1
                url=$(awk 'tolower(substr($0,1,9))=="location:" {sub(/\r$/, ""); sub(/^[^:]*:[ \t]*/, ""); print}' "$headers/response")
                case $url in
                    https://release-assets.githubusercontent.com/*) ;;
                    *) fail 1 ;;
                esac
                case $url in *'
'*|*' '*|*\\*) fail 1 ;; esac
                redirects=$((redirects + 1)) ;;
            *) fail 1 ;;
        esac
    done
fi
binary=$scratch/input/$asset
bounded_file "$binary" 67108864 && [ "$(digest "$binary")" = "$sha" ] || fail 1

if [ "$fixture" = no ]; then
    bundle=$scratch/bundle/attestation.jsonl
    trust=$scratch/trust/trusted_root.jsonl
    if [ -n "$from" ]; then
        bounded_file "$from/sha256:$sha.jsonl" 1048576 || fail 1
        cp "$from/sha256:$sha.jsonl" "$bundle" || fail 1
    else
        # gh download writes only into this new empty directory.
        mkdir "$scratch/bundles" || fail 1
        (CDPATH='' cd -P "$scratch/bundles" && gh attestation download "$binary" --repo avhn/secret) >/dev/null 2>&1 || fail 1
        bounded_file "$scratch/bundles/sha256:$sha.jsonl" 1048576 || fail 1
        cp "$scratch/bundles/sha256:$sha.jsonl" "$bundle" || fail 1
    fi
    if [ "$offline" = yes ]; then
        # Bundles alone are not offline verification. Only reuse a trust root
        # previously obtained through gh's authenticated TUF bootstrap.
        private_file "$cache/trusted_root.jsonl" 600 && bounded_file "$cache/trusted_root.jsonl" 1048576 || fail 1
        cp "$cache/trusted_root.jsonl" "$trust" || fail 1
    else
        gh attestation trusted-root >"$trust" 2>/dev/null || fail 1
        bounded_file "$trust" 1048576 || fail 1
    fi
    GH_PROMPT_DISABLED=1 gh attestation verify "$binary" --repo avhn/secret \
        --source-digest "$commit" --signer-digest "$commit" --source-ref "refs/tags/$tag" \
        --cert-oidc-issuer https://token.actions.githubusercontent.com \
        --cert-identity "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/$tag" \
        --deny-self-hosted-runners \
        --bundle "$bundle" --custom-trusted-root "$trust" --format json \
        >"$scratch/output/result.json" 2>/dev/null || fail 1
    bounded_file "$scratch/output/result.json" 1048576 || fail 1
    python3 -I - "$scratch/output/result.json" "$asset" "$sha" <<'PY' >/dev/null 2>&1 || fail 1
import json
import sys
with open(sys.argv[1], 'rb') as stream:
    results = json.load(stream)
assert isinstance(results, list) and results
for result in results:
    statement = result['verificationResult']['statement']
    assert statement['predicateType'] == 'https://slsa.dev/provenance/v1'
    subjects = statement['subject']
    assert isinstance(subjects, list) and subjects
    matches = [subject for subject in subjects if subject.get('name') == sys.argv[2]]
    assert matches == [{'name': sys.argv[2], 'digest': {'sha256': sys.argv[3]}}]
PY
fi
# Check executable architecture without executing downloaded data. Version is
# checked only after digest and provenance verification, with stdin detached.
python3 -I - "$binary" "$os" "$arch" <<'PY' >/dev/null 2>&1 || fail 1
import struct
import sys
with open(sys.argv[1], 'rb') as stream:
    header = stream.read(32)
os_name, arch = sys.argv[2:]
if os_name == 'linux':
    assert header[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<H', header, 18)[0] == {'amd64': 62, 'arm64': 183}[arch]
else:
    assert header[:4] == b'\xcf\xfa\xed\xfe'
    assert struct.unpack_from('<I', header, 4)[0] == {'amd64': 0x1000007, 'arm64': 0x100000c}[arch]
PY
chmod 500 "$binary" || fail 1
[ "$("$binary" version </dev/null 2>/dev/null)" = "secret $version (go)" ] || fail 1
[ "$(digest "$binary")" = "$sha" ] || fail 1
metadata >"$scratch/output/verified" || fail 1
chmod 600 "$scratch/output/verified" || fail 1
if [ "$fixture" = no ]; then
    chmod 600 "$bundle" "$trust" || fail 1
    mv -f "$bundle" "$cache/attestation.jsonl" && mv -f "$trust" "$cache/trusted_root.jsonl" || fail 1
fi
# The binary is published in one rename. Metadata is published last, so an
# interrupted install never turns a partial binary into an executable cache.
mv -f "$binary" "$cache/secret" && mv -f "$scratch/output/verified" "$cache/verified" || fail 1
current 2>/dev/null || fail 1
exit 0
