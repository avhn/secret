#!/bin/sh
# Verify final-tag provenance, or validate candidate checksums/source inputs.
set -eu
root=$(CDPATH="" cd -P "$(dirname "$0")/.." && pwd -P)
exec python3 -I - "$root" "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(sys.argv[1])
VERSION = "0.2.2"
TAG = "v" + VERSION
REPO = "avhn/secret"
WORKFLOW = REPO + "/.github/workflows/release.yml"
MANIFEST = "checksums-" + TAG + ".txt"
MANIFEST_PATH = "dist/" + MANIFEST
NAMES = sorted("secret-" + TAG + "-" + osname + "-" + arch
               for osname in ("linux", "darwin") for arch in ("amd64", "arm64"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args],
                                   stderr=subprocess.DEVNULL)


def commit(value):
    require(re.fullmatch(r"[0-9a-f]{40}", value), "expected full commit SHA")
    require(git("rev-parse", "--verify", value + "^{commit}").decode().strip() == value,
            "invalid commit")
    return value


def fixture_absent(sha):
    require(not git("ls-tree", "--name-only", sha, "--", ".secret-release-test-fixture"),
            "test fixture marker must not ship")


def check_source(source, final):
    commit(source)
    commit(final)
    fixture_absent(source)
    fixture_absent(final)
    require(git("rev-list", "--parents", "-n", "1", final).decode().split() == [final, source],
            "checksum commit must have exactly source S as parent")
    require(git("diff-tree", "--no-commit-id", "--name-status", "-r", source, final).decode()
            == "A\t" + MANIFEST_PATH + "\n", "only the new checksum manifest may change S..C")


def source_commit():
    head = git("rev-parse", "HEAD").decode().strip()
    fixture_absent(head)
    if git("ls-tree", "--name-only", head, "--", MANIFEST_PATH):
        parents = git("rev-list", "--parents", "-n", "1", head).decode().split()
        require(len(parents) == 2, "invalid checksum commit parent")
        check_source(parents[1], head)
        return parents[1]
    return head


def read_file(path, limit):
    require(path.is_file() and not path.is_symlink(), "missing or symlinked release file")
    require(path.stat().st_size <= limit, "oversized release file")
    return path.read_bytes()


def checksum_records(path):
    data = read_file(path, 4096)
    lines = data.splitlines(keepends=True)
    require(len(lines) == 4, "invalid checksum manifest")
    records = {}
    for name, line in zip(NAMES, lines):
        match = re.fullmatch(rb"([0-9a-f]{64})  " + re.escape(name.encode()) + rb"\n", line)
        require(match is not None, "invalid checksum manifest")
        records[name] = match[1].decode()
    return data, records


def digest(path):
    require(path.is_file() and not path.is_symlink(), "missing or symlinked release asset")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checksums(directory, manifest):
    data, records = checksum_records(manifest)
    for name, expected in records.items():
        require(digest(directory / name) == expected, "release digest mismatch")
    return data, records


def verify(directory, final, bundle_dir):
    commit(final)
    require(git("rev-parse", "HEAD").decode().strip() == final, "checkout is not final commit C")
    require(git("cat-file", "-t", "refs/tags/" + TAG).strip() == b"tag",
            "release tag must be annotated")
    require(git("rev-parse", "refs/tags/" + TAG + "^{commit}").decode().strip() == final,
            "peeled tag does not equal C")
    source_commit()  # Enforce the exact S..C input boundary, not candidate provenance.
    committed = git("show", final + ":" + MANIFEST_PATH)
    data, records = checksums(directory, ROOT / MANIFEST_PATH)
    require(data == committed, "manifest is not committed at C")
    require(read_file(directory / MANIFEST, 4096) == committed, "checksum asset differs from C")
    records[MANIFEST] = digest(directory / MANIFEST)
    for name, expected in records.items():
        command = ["gh", "attestation", "verify", str(directory / name),
                   "--repo", REPO,
                   "--source-digest", final, "--signer-digest", final,
                   "--source-ref", "refs/tags/" + TAG,
                   "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
                   "--cert-identity", "https://github.com/" + WORKFLOW + "@refs/tags/" + TAG,
                   "--deny-self-hosted-runners", "--format", "json"]
        if bundle_dir is not None:
            bundle = bundle_dir / ("sha256:" + expected + ".jsonl")
            read_file(bundle, 16 * 1024 * 1024)
            command.extend(["--bundle", str(bundle)])
        # A local bundle does not make gh offline: it still uses its normal
        # authenticated trust-root policy. Never trust a root supplied beside
        # an untrusted downloaded bundle.
        try:
            # Only public release assets/attestations reach gh here. Its stderr
            # is safe to inherit and preserves the actual verification diagnosis.
            result = subprocess.check_output(command, timeout=120)
        except (OSError, subprocess.SubprocessError):
            print("secret: gh attestation verification failed for " + name, file=sys.stderr)
            raise
        verified = json.loads(result)
        require(isinstance(verified, list) and verified, "missing verified attestations")
        # gh validates the certificate identities and authenticated source fields.
        # Independently enforce each authenticated statement's exact subject, not
        # just the fact that a digest appeared somewhere in the bundle.
        for entry in verified:
            statement = entry["verificationResult"]["statement"]
            require(statement["predicateType"] == "https://slsa.dev/provenance/v1",
                    "unexpected provenance type")
            subjects = statement["subject"]
            require(isinstance(subjects, list) and subjects, "missing provenance subjects")
            require(all(isinstance(subject, dict) for subject in subjects), "invalid provenance subjects")
            matches = [subject for subject in subjects if subject.get("name") == name]
            require(len(matches) == 1 and matches[0].get("digest") == {"sha256": expected},
                    "provenance subject mismatch")
    print("secret: verified all four assets and checksum provenance at final tag C")


def main(args):
    if args == ["--source"]:
        print(source_commit())
    elif len(args) == 3 and args[0] == "--check-source":
        check_source(args[1], args[2])
    elif len(args) in (2, 3) and args[0] == "--checksums":
        directory = Path(args[1]).resolve()
        checksums(directory, Path(args[2]) if len(args) == 3 else directory / MANIFEST)
    else:
        require(len(args) >= 2, "usage: verify-release.sh ASSET_DIR COMMIT [--bundle-dir DIR]")
        directory, final = Path(args[0]).resolve(), args[1]
        bundle_dir = None
        options = args[2:]
        while options:
            option = options.pop(0)
            if option == "--bundle-dir" and options and bundle_dir is None:
                bundle_dir = Path(options.pop(0)).resolve()
            else:
                raise ValueError("invalid verification option")
        verify(directory, final, bundle_dir)


try:
    main(sys.argv[2:])
except (ValueError, OSError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
    print("secret: release verification failed", file=sys.stderr)
    sys.exit(1)
PY
