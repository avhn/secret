#!/bin/sh
# Assemble the full release: six raw binaries, MCPB, registry metadata, checksums.
# Full builds require macOS/native lipo and the locked Node/npm MCPB toolchain
# (packaging/mcpb). CI pins Python/Node/npm and runs two isolated macOS jobs.
set -eu
umask 077
if [ "$#" -ne 1 ]; then
    echo 'usage: build-release.sh OUTDIR' >&2
    exit 2
fi
root=$(CDPATH="" cd -P "$(dirname "$0")/.." && pwd -P)
case $1 in
    /*) out=$1 ;;
    *) out=$(pwd -P)/$1 ;;
esac
# Never mix an earlier build, a downloaded artifact or a stub with this build.
if [ -e "$out" ] || [ -L "$out" ]; then
    if [ ! -d "$out" ] || [ -L "$out" ] || [ -n "$(ls -A "$out")" ]; then
        echo 'secret: release output must be an empty real directory' >&2
        exit 1
    fi
else
    mkdir -p "$out"
fi
out=$(CDPATH="" cd -P "$out" && pwd -P)
cd "$root"
export CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOFLAGS="" GOTOOLCHAIN=local
# Ignore persistent per-user build settings and workspace overlays as well.
export GOENV=off GOWORK=off GOEXPERIMENT=""
if [ "$(go env GOVERSION)" != go1.26.10 ]; then
    echo 'secret: release builds require Go 1.26.10' >&2
    exit 1
fi
version=$(sh "$root/scripts/verify-release.sh" --version)
source=$(sh "$root/scripts/verify-release.sh" --source)
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$source")
export SOURCE_DATE_EPOCH
for tool in lipo node npm python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "secret: complete release builds require macOS lipo and locked packaging tools (missing $tool)" >&2
        exit 1
    fi
done
if [ "$(node --version)" != v26.10.0 ] || [ "$(npm --version)" != 11.19.1 ] ||
   [ "$(python3 --version)" != 'Python 3.14.8' ]; then
    echo 'secret: release packaging requires Node 26.10.0, npm 11.19.1 and Python 3.14.8' >&2
    exit 1
fi
# Installation is from the reviewed lock, never a floating npx download or script.
npm ci --ignore-scripts --prefix "$root/packaging/mcpb"
go mod download
go mod verify
for os in darwin linux windows; do
    for arch in amd64 arm64; do
        suffix=
        if [ "$os" = windows ]; then suffix=.exe; fi
        GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
            -ldflags="-buildid= -s -w -X main.version=$version" \
            -o "$out/secret-v$version-$os-$arch$suffix" ./cmd/secret
    done
done
# Frozen lane interfaces: metadata must describe the exact inspected MCPB bytes.
python3 -I "$root/scripts/package_mcpb.py" --version "$version" \
    --darwin-amd64 "$out/secret-v$version-darwin-amd64" \
    --darwin-arm64 "$out/secret-v$version-darwin-arm64" \
    --windows-amd64 "$out/secret-v$version-windows-amd64.exe" --out "$out"
python3 -I "$root/scripts/release_manifest.py" generate --version "$version" --assets "$out"
git diff --exit-code -- go.mod go.sum packaging/mcpb/package.json packaging/mcpb/package-lock.json
sh "$root/scripts/verify-release.sh" --checksums "$out"
# At C, reproduction must match the committed manifest, not merely itself.
if git cat-file -e "HEAD:dist/checksums-v$version.txt" 2>/dev/null; then
    git show "HEAD:dist/checksums-v$version.txt" | cmp - "$out/checksums-v$version.txt"
fi
