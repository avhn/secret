#!/usr/bin/env python3
"""Rebuild a dead release and exercise new logic against its public provenance.

Only disposable copies receive the 0.3.0 -> 0.2.2 identity substitution. Production
entry points have no tag override and the dead tag is never created or moved.
This is historical five-subject evidence, not Windows/MCPB issuance evidence.
Run with Python -I and TMPDIR set to a private scratch directory.
"""
import hashlib
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TAG = "v0.2.2"
FINAL = "68b2cf8c5e9196f4d79afc032ea95b535751971d"
MANIFEST = "checksums-" + TAG + ".txt"


def run(*args, env=None, cwd=None, deny=False, capture=False):
    command = [str(arg) for arg in args]
    print("+ " + shlex.join(command), flush=True)
    result = subprocess.run(command, env=env, cwd=cwd, capture_output=capture, text=True)
    if deny:
        if result.returncode == 0:
            raise RuntimeError("negative rehearsal unexpectedly succeeded")
        print("PASS: expected rejection (exit " + str(result.returncode) + ")", flush=True)
    else:
        result.check_returncode()
    return result.stdout.strip() if capture else result


def rehearse(scratch):
    worktree = scratch / "tag-checkout"
    assets = scratch / "assets"
    env = dict(os.environ)
    # Never use the operator's real gh configuration or HOME. Hosted runs use
    # only the read-only GITHUB_TOKEN supplied as GH_TOKEN, not stored credentials.
    env["GH_CONFIG_DIR"] = str(scratch / "gh-config")
    env.update(HOME=str(scratch), XDG_CACHE_HOME=str(scratch / "cache"),
               GOCACHE=str(scratch / "go-cache"), GOMODCACHE=str(scratch / "go-modules"),
               GOTOOLCHAIN="local", GH_PROMPT_DISABLED="1",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    env.pop("SECRET_RELEASE_TEST_ROOT", None)
    # Fetch the existing annotated object explicitly, not checkout's commit ref.
    run("git", "-C", ROOT, "fetch", "--no-tags", "--force", "origin",
        "refs/tags/" + TAG + ":refs/tags/" + TAG, env=env)
    assert run("git", "-C", ROOT, "cat-file", "-t", "refs/tags/" + TAG,
               capture=True, env=env) == "tag"
    assert run("git", "-C", ROOT, "rev-parse", "refs/tags/" + TAG + "^{commit}",
               capture=True, env=env) == FINAL
    run("git", "-C", ROOT, "worktree", "add", "--detach", worktree, FINAL, env=env)
    try:
        # Build BEFORE replacing scripts, using precisely the dead tag's inputs.
        run("sh", worktree / "scripts/build-release.sh", assets, env=env)
        assert (assets / MANIFEST).read_bytes() == (worktree / "dist" / MANIFEST).read_bytes()
        print("PASS: rebuilt all four assets match the committed v0.2.2 manifest", flush=True)
        for name in ("verify-release.sh", "install-release.sh"):
            source = (ROOT / "scripts" / name).read_text()
            assert "0.3.0" in source
            (worktree / "scripts" / name).write_text(source.replace("0.3.0", "0.2.2"))
        verify = worktree / "scripts/verify-release.sh"
        install = worktree / "scripts/install-release.sh"
        run("sh", verify, assets, FINAL, env=env)
        print("PASS: new verifier with genuine online provenance (five subjects)", flush=True)
        bundles = scratch / "bundles"
        bundles.mkdir()
        for asset in sorted(assets.iterdir()):
            # gh writes digest-named downloads only into a fresh empty directory.
            download = Path(tempfile.mkdtemp(prefix="download-", dir=scratch))
            run("gh", "attestation", "download", asset, "--repo", "avhn/secret",
                cwd=download, env=env)
            with asset.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            bundle = "sha256:" + digest + ".jsonl"
            shutil.copyfile(download / bundle, bundles / bundle)
        run("sh", verify, assets, FINAL, "--bundle-dir", bundles, env=env)
        print("PASS: new verifier with genuine downloaded bundles (five subjects)", flush=True)
        inputs = scratch / "installer-input"
        shutil.copytree(assets, inputs)
        for bundle in bundles.iterdir():
            shutil.copyfile(bundle, inputs / bundle.name)
        # Production mode: no fixture marker or bypass variable. The online
        # installer acquires its root with gh attestation trusted-root, exactly as
        # docs/install.md prescribes, and retains it for the offline replay.
        assert not (worktree / ".secret-release-test-fixture").exists()
        run("sh", install, "--from-dir", inputs, env=env)
        cache = scratch / "cache/secret" / TAG
        assert (cache / "trusted_root.jsonl").stat().st_mode & 0o777 == 0o600
        print("PASS: production installer with genuine bundle and authenticated TUF root", flush=True)
        for name in ("secret", "verified"):
            (cache / name).unlink()
        run("sh", install, "--offline", "--from-dir", inputs, env=env)
        print("PASS: cold production offline replay with retained trusted root", flush=True)

        system = {"Linux": "linux", "Darwin": "darwin"}[platform.system()]
        arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
        binary = "secret-" + TAG + "-" + system + "-" + arch
        corrupt = scratch / "corrupt-assets"
        shutil.copytree(inputs, corrupt)
        with (corrupt / binary).open("r+b") as stream:
            byte = stream.read(1)
            stream.seek(0)
            stream.write(bytes([byte[0] ^ 1]))
        run("sh", verify, corrupt, FINAL, "--bundle-dir", bundles, env=env, deny=True)
        # A new private cache ensures the installer cannot take its warm shortcut.
        bad_env = {**env, "XDG_CACHE_HOME": str(scratch / "negative-cache")}
        run("sh", install, "--from-dir", corrupt, env=bad_env, deny=True)
        print("PASS: byte-flipped binary rejected by verifier and production installer", flush=True)
        source = run("git", "-C", worktree, "rev-parse", FINAL + "^", capture=True, env=env)
        run("sh", verify, assets, source, env=env, deny=True)
        # Exercise gh's authenticated pins too, rather than only local git checks.
        command = ["gh", "attestation", "verify", str(assets / binary),
                   "--repo", "avhn/secret", "--source-digest", FINAL,
                   "--signer-digest", FINAL, "--source-ref", "refs/tags/" + TAG,
                   "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
                   "--cert-identity", "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/" + TAG,
                   "--deny-self-hosted-runners", "--format", "json"]
        for flag, value in (("--source-digest", source),
                            ("--source-ref", "refs/tags/v0.3.0")):
            wrong = command.copy()
            wrong[wrong.index(flag) + 1] = value
            run(*wrong, env=env, deny=True)
        print("PASS: wrong commit and tag ref rejected by genuine provenance", flush=True)
    finally:
        run("git", "-C", ROOT, "worktree", "remove", "--force", worktree, env=env)


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="secret-release-rehearsal-") as temporary:
        rehearse(Path(temporary).resolve())
    print("PASS: real-provenance release rehearsal complete", flush=True)
