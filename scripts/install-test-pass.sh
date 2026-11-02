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
name=password-store-$revision.tar.xz
archive=$root/download/pass.tar.xz
# Optional CI cache of the verified archive. The pinned digest always decides.
cache=${SECRET_PASS_CACHE:-}
case $cache in ''|/*) ;; *) echo 'SECRET_PASS_CACHE must be absolute' >&2; exit 1 ;; esac
fetch() {
    # The cgit snapshot endpoint intermittently answers runners with HTTP 502.
    curl --fail --location --silent --show-error --retry 6 --retry-delay 15 \
        --retry-all-errors --retry-max-time 360 \
        "https://git.zx2c4.com/password-store/snapshot/$name" -o "$archive"
}
digest() { shasum -a 256 "$archive" | awk '{print $1}'; }
cached=no
if [ -n "$cache" ] && [ -f "$cache/$name" ] && [ ! -L "$cache/$name" ]; then
    cp "$cache/$name" "$archive"
    cached=yes
else
    fetch
fi
actual=$(digest)
if [ "$actual" != "$expected" ] && [ "$cached" = yes ]; then
    # A damaged cache entry never wins over the pinned digest: refetch once.
    rm -f "$archive"
    fetch
    actual=$(digest)
    cached=no
fi
[ "$actual" = "$expected" ] || { echo 'pass snapshot checksum mismatch' >&2; exit 1; }
if [ -n "$cache" ] && [ "$cached" = no ]; then
    mkdir -p "$cache"
    chmod 700 "$cache"
    cp "$archive" "$cache/$name.tmp" && mv -f "$cache/$name.tmp" "$cache/$name"
fi
tar -xf "$root/download/pass.tar.xz" -C "$root/source"
# The immutable upstream Makefile installs the platform file as well as pass.
make -C "$root/source/password-store-$revision" install PREFIX="$prefix" WITH_ALLCOMP=no
[ -x "$prefix/bin/pass" ]
if [ "$(uname -s)" = Darwin ]; then
    test -f "$prefix/lib/password-store/platform.sh"
    grep -F "source \"$prefix/lib/password-store/platform.sh\"" "$prefix/bin/pass" >/dev/null
fi
