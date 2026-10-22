#!/bin/sh
# Build the four raw release executables with the frozen M4 inputs.
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
source=$(sh "$root/scripts/verify-release.sh" --source)
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$source")
export SOURCE_DATE_EPOCH
go mod download
go mod verify
for os in darwin linux; do
    for arch in amd64 arm64; do
        GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
            -ldflags='-buildid= -s -w -X main.version=0.2.2' \
            -o "$out/secret-v0.2.2-$os-$arch" ./cmd/secret
    done
done
git diff --exit-code -- go.mod go.sum
cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum secret-v0.2.2-darwin-amd64 secret-v0.2.2-darwin-arm64 \
        secret-v0.2.2-linux-amd64 secret-v0.2.2-linux-arm64 >checksums-v0.2.2.txt
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 secret-v0.2.2-darwin-amd64 secret-v0.2.2-darwin-arm64 \
        secret-v0.2.2-linux-amd64 secret-v0.2.2-linux-arm64 >checksums-v0.2.2.txt
else
    echo 'secret: missing SHA-256 utility' >&2
    exit 1
fi
sh "$root/scripts/verify-release.sh" --checksums "$out"
