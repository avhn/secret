#!/bin/sh
# CI-only optional provider fixture. Never install into the host or real HOME.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'pass fixture install requires GitHub Actions' >&2; exit 1; }
[ "$#" -eq 1 ] && [ ! -e "$1" ] || { echo 'new absolute prefix required' >&2; exit 1; }
case "$1" in /*) ;; *) exit 1 ;; esac
prefix=$1
root=$(mktemp -d "${RUNNER_TEMP:?}/secret-pass-build.XXXXXXXX")
trap 'rm -rf "$root"' EXIT HUP INT TERM
mkdir -m 700 "$root/home" "$root/download" "$root/source" "$root/work"
export HOME="$root/home"
revision=1078f2514d579178d5df7042c6a790e9c9b731ad
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
expected=$(awk '{print $1}' "$script_dir/../testdata/pass/upstream.sha256")
curl --fail --location --silent --show-error \
    "https://git.zx2c4.com/password-store/snapshot/password-store-$revision.tar.xz" \
    -o "$root/download/pass.tar.xz"
actual=$(shasum -a 256 "$root/download/pass.tar.xz" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo 'pass snapshot checksum mismatch' >&2; exit 1; }
tar -xf "$root/download/pass.tar.xz" -C "$root/source"
# The immutable upstream Makefile installs the platform file as well as pass.
make -C "$root/source/password-store-$revision" install PREFIX="$prefix" WITH_ALLCOMP=no
[ -x "$prefix/bin/pass" ]
if [ "$(uname -s)" = Darwin ]; then
    test -f "$prefix/lib/password-store/platform.sh"
    grep -F "source \"$prefix/lib/password-store/platform.sh\"" "$prefix/bin/pass" >/dev/null
fi
