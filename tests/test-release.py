#!/usr/bin/env python3
"""Synthetic release-boundary tests. No network, providers or real HOME use."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
TAG = "v" + VERSION
MANIFEST = "checksums-" + TAG + ".txt"
NAMES = sorted("secret-" + TAG + "-" + system + "-" + arch
               for system in ("linux", "darwin") for arch in ("amd64", "arm64"))

# This is a verifier boundary double, not cryptographic or hosted evidence.
GH = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["GH_CALLS"], "a") as log:
    log.write(json.dumps(args) + "\n")
if args[:2] == ["attestation", "download"]:
    import hashlib
    assert args[3:] == ["--repo", "avhn/secret"]
    digest = hashlib.sha256(pathlib.Path(args[2]).read_bytes()).hexdigest()
    pathlib.Path("sha256:" + digest + ".jsonl").write_text("synthetic bundle " + digest + "\n")
    sys.exit(0)
assert args[:2] == ["attestation", "verify"]
expected = {
    "--repo": "avhn/secret",
    "--signer-workflow": "avhn/secret/.github/workflows/release.yml",
    "--source-digest": os.environ["EXPECTED_COMMIT"],
    "--signer-digest": os.environ["EXPECTED_COMMIT"],
    "--source-ref": "refs/tags/v0.2.0",
    "--cert-identity": "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.2.0",
    "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
    "--format": "json",
}
for flag, value in expected.items():
    assert args[args.index(flag) + 1] == value
assert "--deny-self-hosted-runners" in args
mode = os.environ.get("GH_MODE", "valid")
# Emulate gh rejecting authenticated identities that do not match pinned flags.
if mode in ("repo", "workflow", "source", "ref", "issuer", "candidate"):
    print("synthetic verifier diagnostic must not escape", file=sys.stderr)
    sys.exit(1)
name = pathlib.Path(args[2]).name
import hashlib
digest = hashlib.sha256(pathlib.Path(args[2]).read_bytes()).hexdigest()
if "--bundle" in args:
    bundle = pathlib.Path(args[args.index("--bundle") + 1])
    assert bundle.name == "sha256:" + digest + ".jsonl"
    assert bundle.read_text() == "synthetic bundle " + digest + "\n"
subject = {"name": name, "digest": {"sha256": digest}}
if mode == "subject": subject["name"] = "wrong-subject"
if mode == "digest": subject["digest"]["sha256"] = "0" * 64
subjects = [subject, subject] if mode == "duplicate" else [subject]
if mode == "malformed-subject": subjects = ["not a subject object"]
statement = {"predicateType": "https://slsa.dev/provenance/v1", "subject": subjects}
if mode == "predicate": statement["predicateType"] = "wrong-predicate"
result = [{"verificationResult": {"statement": statement}}]
if mode == "empty": result = []
print("not-json" if mode == "json" else json.dumps(result))
'''

GO = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args == ["env", "GOVERSION"]:
    print(os.environ.get("FAKE_GO_VERSION", "go1.26.0"))
    sys.exit(0)
if args in (["mod", "download"], ["mod", "verify"]):
    sys.exit(0)
assert args[:3] == ["build", "-trimpath", "-buildvcs=false"]
assert args[3] == "-ldflags=-buildid= -s -w -X main.version=0.2.0"
assert args[4] == "-o" and args[6:] == ["./cmd/secret"]
if os.environ.get("GO_FAIL_BUILD") == "1": sys.exit(1)
expected = {"CGO_ENABLED": "0", "GOAMD64": "v1", "GOARM64": "v8.0",
            "GOFLAGS": "", "GOTOOLCHAIN": "local", "GOENV": "off",
            "GOWORK": "off", "GOEXPERIMENT": ""}
for key, value in expected.items(): assert os.environ[key] == value
with open(os.environ["GO_CALLS"], "a") as log:
    log.write(json.dumps({key: os.environ[key] for key in
                         ["GOOS", "GOARCH", "SOURCE_DATE_EPOCH"]}) + "\n")
pathlib.Path(args[5]).write_bytes((os.environ["GOOS"] + "/" + os.environ["GOARCH"]).encode())
'''


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="secret-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "trusted checkout"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        for name in ("build-release.sh", "verify-release.sh"):
            shutil.copyfile(ROOT / "scripts" / name, self.repo / "scripts" / name)
        self.tools = self.base / "tools"
        self.tools.mkdir()
        for name, content in (("gh", GH), ("go", GO)):
            path = self.tools / name
            path.write_text(content)
            path.chmod(0o700)
        home = self.base / "home"
        home.mkdir()
        self.env = {**os.environ, "HOME": str(home), "XDG_CACHE_HOME": str(home / "cache"),
                    "PATH": str(self.tools) + os.pathsep + os.environ["PATH"],
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "GH_CALLS": str(self.base / "gh-calls"),
                    "GO_CALLS": str(self.base / "go-calls")}
        # Do not forward authentication to even a synthetic verifier subprocess.
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
            self.env.pop(name, None)
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Release")
        self.git("config", "user.email", "release@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.repo / "go.mod").write_text("module synthetic.invalid/release\n\ngo 1.26.0\n")
        (self.repo / "go.sum").write_bytes(b"")
        self.env.update(GIT_AUTHOR_DATE="2001-01-01T00:00:00Z",
                        GIT_COMMITTER_DATE="2001-01-01T00:00:00Z")
        self.source = self.save("source S")
        self.assets = self.base / "assets"
        self.assets.mkdir()
        for name in NAMES:
            (self.assets / name).write_bytes(("synthetic " + name).encode())
        self.manifest = b"".join(hashlib.sha256((self.assets / name).read_bytes()).hexdigest().encode()
                                  + b"  " + name.encode() + b"\n" for name in NAMES)
        (self.assets / MANIFEST).write_bytes(self.manifest)
        (self.repo / "dist").mkdir()
        (self.repo / "dist" / MANIFEST).write_bytes(self.manifest)
        self.env.update(GIT_AUTHOR_DATE="2002-01-01T00:00:00Z",
                        GIT_COMMITTER_DATE="2002-01-01T00:00:00Z")
        self.final = self.save("checksum C")
        self.env["EXPECTED_COMMIT"] = self.final
        self.git("tag", "-a", TAG, "-m", "synthetic release")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], env=self.env,
                                       stderr=subprocess.PIPE).decode().strip()

    def save(self, message):
        self.git("add", ".")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def script(self, name, *args):
        return subprocess.run(["sh", str(self.repo / "scripts" / name), *map(str, args)],
                              env=self.env, cwd=self.base, capture_output=True, text=True)

    def verify(self, *options):
        return self.script("verify-release.sh", self.assets, self.final, *options)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def assert_denied(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("synthetic verifier diagnostic", result.stderr)

    def test_valid_final_and_all_five_pinned_verifications(self):
        self.assert_ok(self.verify())
        calls = [json.loads(line) for line in Path(self.env["GH_CALLS"]).read_text().splitlines()]
        self.assertEqual(sorted(Path(call[2]).name for call in calls), sorted(NAMES + [MANIFEST]))

    def test_changed_binary_denies_before_provenance(self):
        (self.assets / NAMES[0]).write_bytes(b"changed binary")
        self.assert_denied(self.verify())
        self.assertFalse(Path(self.env["GH_CALLS"]).exists())

    def test_symlink_asset_denies(self):
        target = self.assets / NAMES[0]
        original = self.base / "original"
        target.rename(original)
        target.symlink_to(original)
        self.assert_denied(self.verify())

    def test_manifest_grammar_rejects_whole_file(self):
        lines = self.manifest.splitlines(keepends=True)
        invalid = {
            "blank": self.manifest + b"\n", "missing newline": self.manifest[:-1],
            "crlf": self.manifest.replace(b"\n", b"\r\n"),
            "duplicate": lines[0] + lines[0] + b"".join(lines[2:]),
            "unsorted": b"".join(reversed(lines)), "comment": b"# comment\n" + self.manifest,
            "one space": self.manifest.replace(b"  ", b" "),
            "path": self.manifest.replace(b"  secret", b"  ./secret"),
            "uppercase": self.manifest.upper(),
            "other version": self.manifest.replace(b"v0.2.0", b"v0.2.1"),
            "windows": self.manifest.replace(b"darwin", b"windows"),
        }
        for name, content in invalid.items():
            with self.subTest(name=name):
                (self.assets / MANIFEST).write_bytes(content)
                self.assert_denied(self.script("verify-release.sh", "--checksums", self.assets))

    def test_changed_checksum_asset_or_checkout_manifest_denies(self):
        (self.assets / MANIFEST).write_bytes(self.manifest + b"\n")
        self.assert_denied(self.verify())
        (self.assets / MANIFEST).write_bytes(self.manifest)
        (self.repo / "dist" / MANIFEST).write_bytes(self.manifest.replace(b"a", b"b", 1))
        self.assert_denied(self.verify())

    def test_invalid_provenance_and_authenticated_identity_denies(self):
        for mode in ("repo", "workflow", "source", "ref", "issuer", "candidate", "subject",
                     "digest", "duplicate", "malformed-subject", "predicate", "empty", "json"):
            with self.subTest(mode=mode):
                self.env["GH_MODE"] = mode
                self.assert_denied(self.verify())

    def test_wrong_tag_target_denies(self):
        self.git("tag", "-f", "-a", TAG, self.source, "-m", "wrong target")
        self.assert_denied(self.verify())

    def test_lightweight_tag_denies(self):
        self.git("tag", "-d", TAG)
        self.git("tag", TAG)
        self.assert_denied(self.verify())

    def test_wrong_or_short_source_denies(self):
        for sha in (self.source, self.final[:12], "f" * 40):
            self.assert_denied(self.script("verify-release.sh", self.assets, sha))

    def test_exact_source_boundary_and_shared_epoch(self):
        self.assert_ok(self.script("verify-release.sh", "--check-source", self.source, self.final))
        result = self.script("verify-release.sh", "--source")
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), self.source)

    def test_nonmanifest_input_drift_denies(self):
        for name in ("source.go", ".github/workflows/release.yml", "README.md", "plugin.json"):
            with self.subTest(name=name):
                self.git("checkout", "-q", "--detach", self.source)
                path = self.repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("changed input\n")
                (self.repo / "dist").mkdir(exist_ok=True)
                (self.repo / "dist" / MANIFEST).write_bytes(self.manifest)
                bad_final = self.save("bad checksum commit")
                self.assert_denied(self.script("verify-release.sh", "--check-source", self.source, bad_final))

    def test_source_and_checksum_must_be_adjacent(self):
        self.assert_denied(self.script("verify-release.sh", "--check-source", self.final, self.final))
        (self.repo / "other").write_text("extra commit\n")
        later = self.save("extra commit")
        self.assert_denied(self.script("verify-release.sh", "--check-source", self.source, later))

    def test_existing_manifest_change_is_not_a_new_checksum_boundary(self):
        (self.repo / "dist" / MANIFEST).write_bytes(self.manifest + b"\n")
        later = self.save("changed existing checksum manifest")
        self.assert_denied(self.script("verify-release.sh", "--check-source", self.final, later))
        self.assert_denied(self.script("verify-release.sh", "--source"))

    def test_fixture_marker_cannot_ship(self):
        self.git("checkout", "-q", "--detach", self.source)
        (self.repo / ".secret-release-test-fixture").write_bytes(b"")
        self.save("fixture must not ship")
        self.assert_denied(self.script("verify-release.sh", "--source"))

    def bundles(self):
        directory = self.base / "bundles"
        directory.mkdir()
        for name in NAMES + [MANIFEST]:
            digest = hashlib.sha256((self.assets / name).read_bytes()).hexdigest()
            (directory / ("sha256:" + digest + ".jsonl")).write_text("synthetic bundle " + digest + "\n")
        return directory

    def test_bundle_verification_keeps_authenticated_trust_policy(self):
        bundles = self.bundles()
        (bundles / "trusted_root.jsonl").write_text("untrusted supplied root\n")
        self.assert_ok(self.verify("--bundle-dir", bundles))
        last = json.loads(Path(self.env["GH_CALLS"]).read_text().splitlines()[-1])
        self.assertIn("--bundle", last)
        self.assertNotIn("--custom-trusted-root", last)
        self.assert_denied(self.verify("--offline"))
        for bundle in bundles.glob("sha256:*.jsonl"):
            bundle.unlink()
        self.assert_denied(self.verify("--bundle-dir", bundles))

    def test_workflow_bundle_transport_round_trip(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()

        def run_step(name, cwd):
            match = re.search(r"^      - name: " + re.escape(name)
                              + r"\n.*?^        run: \|\n((?:          [^\n]*\n)+)",
                              workflow, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, name)
            result = subprocess.run(["sh", "-eu", "-c", textwrap.dedent(match[1])],
                                    cwd=cwd, env=self.env, capture_output=True, text=True)
            self.assert_ok(result)

        self.env.update(GITHUB_SHA=self.final, RUNNER_TEMP=str(self.base))
        assets = self.repo / "assets"
        shutil.copytree(self.assets, assets)
        run_step("Verify final C, tag, certificate, workflow and all five subjects", self.repo)
        bundles = {path.name: path.read_bytes() for path in assets.glob("sha256:*.jsonl")}
        self.assertEqual(len(bundles), 5)
        for name in bundles:
            self.assertRegex(name, r"^sha256:[0-9a-f]{64}\.jsonl$")

        # Match upload-artifact's validateFilePath restrictions, including colon.
        forbidden = set('\":<>|*?\r\n')
        self.assertTrue(any(set(name) & forbidden for name in bundles))
        run_step("Encode bundle names for artifact transport", self.repo)
        upload = re.search(r"name: release-verified\n          path: (\S+)", workflow)
        self.assertIsNotNone(upload)
        upload_dir = self.repo / upload[1]
        for path in upload_dir.rglob("*"):
            self.assertFalse(set(str(path.relative_to(upload_dir))) & forbidden, path)
        self.assertEqual(sorted(path.name for path in upload_dir.iterdir()),
                         sorted(NAMES + [MANIFEST]
                                + [name.replace("sha256:", "sha256-", 1) for name in bundles]))

        # Model upload/download into a fresh job, then execute the actual restore step.
        approved = self.base / "approved job"
        approved.mkdir()
        downloaded = approved / "assets"
        shutil.copytree(upload_dir, downloaded)
        run_step("Restore gh bundle names after artifact transport", approved)
        self.assertEqual({path.name: path.read_bytes() for path in downloaded.glob("sha256:*.jsonl")},
                         bundles)
        Path(self.env["GH_CALLS"]).unlink()
        self.assert_ok(self.script("verify-release.sh", downloaded, self.final,
                                   "--bundle-dir", downloaded))
        calls = [json.loads(line) for line in Path(self.env["GH_CALLS"]).read_text().splitlines()]
        self.assertEqual(len(calls), 5)
        for call in calls:
            bundle = Path(call[call.index("--bundle") + 1])
            # The verifier resolves paths physically, e.g. macOS /var -> /private/var.
            self.assertEqual(bundle.parent.resolve(), downloaded.resolve())
            self.assertIn(bundle.name, bundles)

        # A renamed bundle is not enough: verification must consume its intact payload.
        bundle.write_text("corrupt transported bundle\n")
        self.assert_denied(self.script("verify-release.sh", downloaded, self.final,
                                       "--bundle-dir", downloaded))

    def test_build_frozen_environment_names_flags_and_source_epoch(self):
        self.env.update(GOFLAGS="-tags=secretstub", GOAMD64="v4", GOARM64="v9.0",
                        CGO_ENABLED="1", SOURCE_DATE_EPOCH="0", GOTOOLCHAIN="auto")
        output = self.base / "build output"
        self.assert_ok(self.script("build-release.sh", output))
        self.assertEqual(sorted(path.name for path in output.iterdir()), sorted(NAMES + [MANIFEST]))
        self.assert_ok(self.script("verify-release.sh", "--checksums", output))
        calls = [json.loads(line) for line in Path(self.env["GO_CALLS"]).read_text().splitlines()]
        self.assertEqual(len(calls), 4)
        self.assertEqual({call["SOURCE_DATE_EPOCH"] for call in calls},
                         {self.git("show", "-s", "--format=%ct", self.source)})

    def test_build_rejects_nonempty_output_and_wrong_toolchain(self):
        self.assert_denied(self.script("build-release.sh", self.assets))
        self.env["FAKE_GO_VERSION"] = "go1.27.1"
        self.assert_denied(self.script("build-release.sh", self.base / "bad-toolchain"))

    def test_compiler_failure_does_not_produce_an_accepted_manifest(self):
        self.env["GO_FAIL_BUILD"] = "1"
        output = self.base / "failed-build"
        self.assert_denied(self.script("build-release.sh", output))
        self.assertFalse((output / MANIFEST).exists())

    def test_candidate_source_selection(self):
        self.git("checkout", "-q", "--detach", self.source)
        result = self.script("verify-release.sh", "--source")
        self.assert_ok(result)
        self.assertEqual(result.stdout.strip(), self.source)


class WorkflowTest(unittest.TestCase):
    def test_candidate_and_final_job_boundaries(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        jobs = dict(re.findall(r"^  (release-[a-z-]+):\n(.*?)(?=^  release-|\Z)",
                               workflow, re.MULTILINE | re.DOTALL))
        self.assertEqual(set(jobs), {"release-build-a", "release-build-b", "release-repro",
                                     "release-attest", "release-verify", "release-publish"})
        for name in ("release-attest", "release-verify", "release-publish"):
            self.assertIn("github.event_name == 'push'", jobs[name])
            self.assertIn("github.ref == 'refs/tags/v0.2.0'", jobs[name])
            self.assertIn("github.repository == 'avhn/secret'", jobs[name])
        for name in ("release-build-a", "release-build-b"):
            self.assertIn("cache: false", jobs[name])
            self.assertIn("GOMODCACHE=", jobs[name])
            self.assertNotIn("GH_TOKEN:", jobs[name])
        self.assertIn("cmp ", jobs["release-repro"])
        self.assertIn("environment: release-publish", jobs["release-publish"])
        self.assertIn("--draft --title", jobs["release-publish"])
        self.assertIn('select(.type == "required_reviewers" and (.reviewers | length) > 0)', jobs["release-verify"])
        self.assertIn(".deployment_branch_policy.custom_branch_policies == true", jobs["release-verify"])
        self.assertIn('[{"name": "v0.2.0", "type": "tag"}]', jobs["release-verify"])
        self.assertNotIn("prevent_self_review", jobs["release-verify"])
        self.assertIn("attestations: read", jobs["release-verify"])
        self.assertLess(jobs["release-verify"].index("Encode bundle names for artifact transport"),
                        jobs["release-verify"].index("name: release-verified"))
        self.assertLess(jobs["release-publish"].index("Restore gh bundle names after artifact transport"),
                        jobs["release-publish"].index("Reverify approved assets and create draft only"))
        self.assertEqual(workflow.count("contents: write"), 1)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertEqual(workflow.count("attestations: write"), 1)
        for action in re.findall(r"uses: (\S+)", workflow):
            self.assertRegex(action, r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
