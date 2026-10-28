#!/usr/bin/env python3
"""Synthetic release-boundary tests. No network, providers or real HOME use."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.3"
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
if args[:2] == ["release", "create"]:
    import shutil
    assert args[2] == "v0.2.3"
    assert "--draft" in args and "--verify-tag" in args
    assert args[args.index("--target") + 1] == os.environ["EXPECTED_COMMIT"]
    assert args[args.index("--repo") + 1] == "avhn/secret"
    assets = [pathlib.Path(arg) for arg in args if arg.startswith("assets/")]
    assert len(assets) == 10
    destination = pathlib.Path(os.environ["GH_RELEASE_ASSETS"])
    destination.mkdir()
    for asset in assets:
        assert all(char.isascii() and (char.isalnum() or char in "-_.") for char in asset.name)
        shutil.copyfile(asset, destination / asset.name)
    sys.exit(0)
if args[:2] == ["release", "download"]:
    import shutil
    assert args[2:5] == ["v0.2.3", "--repo", "avhn/secret"]
    destination = pathlib.Path(args[args.index("--dir") + 1])
    assert not any(destination.iterdir())
    for asset in pathlib.Path(os.environ["GH_RELEASE_ASSETS"]).iterdir():
        shutil.copyfile(asset, destination / asset.name)
    if os.environ.get("GH_MODE") == "corrupt-draft":
        (destination / "secret-v0.2.3-linux-amd64").write_bytes(b"corrupt uploaded binary")
    sys.exit(0)
assert args[:2] == ["attestation", "verify"]
for group in (("--owner", "--repo"),
              ("--cert-identity", "--cert-identity-regex", "--signer-repo", "--signer-workflow")):
    assert sum(flag in args for flag in group) <= 1, "mutually exclusive gh flags"
expected = {
    "--repo": "avhn/secret",
    "--source-digest": os.environ["EXPECTED_COMMIT"],
    "--signer-digest": os.environ["EXPECTED_COMMIT"],
    "--source-ref": "refs/tags/v0.2.3",
    "--cert-identity": "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.2.3",
    "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
    "--format": "json",
}
for flag, value in expected.items():
    assert args[args.index(flag) + 1] == value
assert "--deny-self-hosted-runners" in args
mode = os.environ.get("GH_MODE", "valid")
# Emulate gh rejecting authenticated identities that do not match pinned flags.
if mode in ("repo", "workflow", "source", "ref", "issuer", "candidate"):
    print("synthetic public attestation diagnostic", file=sys.stderr)
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
    print(os.environ.get("FAKE_GO_VERSION", "go1.26.10"))
    sys.exit(0)
if args in (["mod", "download"], ["mod", "verify"]):
    sys.exit(0)
assert args[:3] == ["build", "-trimpath", "-buildvcs=false"]
assert args[3] == "-ldflags=-buildid= -s -w -X main.version=0.2.3"
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


def workflow_jobs(filename):
    workflow = (ROOT / ".github/workflows" / filename).read_text()
    return dict(re.findall(r"^  ([a-z][a-z-]+):\n(.*?)(?=^  [a-z][a-z-]+:|\Z)",
                           workflow, re.MULTILINE | re.DOTALL))


def workflow_step(job, name):
    match = re.search(r"^      - name: " + re.escape(name)
                      + r"\n.*?^        run: \|\n((?:          [^\n]*\n)+)",
                      job, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError("missing workflow step: " + name)
    return textwrap.dedent(match[1])


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
        (self.repo / "go.mod").write_text("module synthetic.invalid/release\n\ngo 1.26.10\n")
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

    def test_valid_final_and_all_five_pinned_verifications(self):
        self.assert_ok(self.verify())
        calls = [json.loads(line) for line in Path(self.env["GH_CALLS"]).read_text().splitlines()]
        self.assertEqual(sorted(Path(call[2]).name for call in calls), sorted(NAMES + [MANIFEST]))

    def test_gh_failure_preserves_public_diagnosis_and_names_subject(self):
        self.env["GH_MODE"] = "source"
        result = self.verify()
        self.assert_denied(result)
        self.assertIn("synthetic public attestation diagnostic", result.stderr)
        self.assertIn("secret: gh attestation verification failed for " + NAMES[0], result.stderr)
        self.assertIn("secret: release verification failed", result.stderr)
        self.assertEqual(result.stdout, "")

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
            "other version": self.manifest.replace(b"v0.2.3", b"v0.2.4"),
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

    def tag_check_steps(self):
        release = workflow_jobs("release.yml")
        plugin = workflow_jobs("plugin.yml")
        return [(name, workflow_step(release[name], "Restore and check annotated release tag"))
                for name in ("release-repro", "release-verify", "release-publish")] + [
                    (name, workflow_step(plugin[name],
                                         "Require final checksum commit C for published verification"))
                    for name in ("plugin-install-linux", "plugin-install-macos")]

    def tag_origin(self):
        origin = self.base / "origin.git"
        subprocess.run(["git", "clone", "--quiet", "--bare", str(self.repo), str(origin)],
                       env=self.env, check=True, capture_output=True)
        self.git("remote", "add", "origin", str(origin))
        self.env.update(GITHUB_SHA=self.final, GITHUB_REF="refs/tags/" + TAG)
        self.git("checkout", "-q", "--detach", self.final)
        return origin

    def run_tag_step(self, step):
        return subprocess.run(["sh", "-eu", "-c", step], cwd=self.repo, env=self.env,
                              capture_output=True, text=True)

    def test_tag_jobs_restore_checkout_clobbered_annotated_tag(self):
        original = self.git("rev-parse", "refs/tags/" + TAG)
        origin = self.tag_origin()
        for name, step in self.tag_check_steps():
            with self.subTest(job=name):
                # Reproduce checkout's tag-push refspec: commit SHA replaces tag object.
                self.git("fetch", "--no-tags", "--force", "origin",
                         self.final + ":refs/tags/" + TAG)
                self.assertEqual(self.git("cat-file", "-t", "refs/tags/" + TAG), "commit")
                self.assert_denied(self.verify())
                self.assert_ok(self.run_tag_step(step))
                self.assertEqual(self.git("rev-parse", "refs/tags/" + TAG), original)
                self.assert_ok(self.verify())
        remote = subprocess.check_output(["git", "--git-dir", str(origin), "rev-parse",
                                          "refs/tags/" + TAG], env=self.env).decode().strip()
        self.assertEqual(remote, original, "restoration must not change the remote tag")

    def test_tag_jobs_reject_remote_lightweight_tag(self):
        self.git("tag", "-f", TAG, self.final)
        self.tag_origin()
        for name, step in self.tag_check_steps():
            with self.subTest(job=name):
                self.assert_denied(self.run_tag_step(step))

    def test_tag_jobs_reject_remote_annotated_tag_at_wrong_commit(self):
        self.git("tag", "-f", "-a", TAG, self.source, "-m", "wrong target")
        self.tag_origin()
        for name, step in self.tag_check_steps():
            with self.subTest(job=name):
                self.assert_denied(self.run_tag_step(step))

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

    def draft_step(self, mode):
        self.env.update(GITHUB_SHA=self.final, RUNNER_TEMP=str(self.base), GH_MODE=mode,
                        GH_RELEASE_ASSETS=str(self.base / "draft release"))
        assets = self.repo / "assets"
        shutil.copytree(self.assets, assets)
        for bundle in self.bundles().iterdir():
            shutil.copyfile(bundle, assets / bundle.name)
        step = workflow_step(workflow_jobs("release.yml")["release-publish"],
                             "Reverify approved assets and create draft only")
        return self.run_tag_step(step)

    def test_workflow_draft_portable_names_and_final_reverification(self):
        self.assert_ok(self.draft_step("valid"))
        uploaded = Path(self.env["GH_RELEASE_ASSETS"])
        self.assertEqual(len(list(uploaded.glob("sha256-*.jsonl"))), 5)
        self.assertFalse(list(uploaded.glob("sha256:*.jsonl")))
        calls = [json.loads(line) for line in Path(self.env["GH_CALLS"]).read_text().splitlines()]
        self.assertEqual([call[:2] for call in calls],
                         [["attestation", "verify"]] * 5
                         + [["release", "create"], ["release", "download"]]
                         + [["attestation", "verify"]] * 5)

    def test_workflow_draft_changed_uploaded_bytes_denies(self):
        self.assert_denied(self.draft_step("corrupt-draft"))

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
    def test_only_bounded_fuzz_steps_override_the_pinned_toolchain(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("\nenv:\n  GOTOOLCHAIN: local\n", workflow)
        job = workflow_jobs("ci.yml")["go"]
        self.assertIn('go-version: "1.26.10"', job)
        steps = re.split(r"^      - ", job, flags=re.MULTILINE)[1:]
        fuzz_names = {"Bounded feature fuzzing", "Bounded age fuzzing"}
        found = set()
        for step in steps:
            name = step.splitlines()[0].removeprefix("name: ")
            with self.subTest(step=name):
                if name in fuzz_names:
                    found.add(name)
                    self.assertIn("        if: runner.os == 'Linux'\n", step)
                    self.assertIn("        env:\n          GOTOOLCHAIN: go1.27.3\n", step)
                    self.assertNotIn("continue-on-error", step)
                    commands = [line.strip() for line in step.splitlines() if "go test " in line]
                    for command in commands:
                        self.assertTrue(command.endswith(" -fuzztime=15s -parallel=2"))
                else:
                    self.assertNotIn("go1.27.3", step)
        self.assertEqual(found, fuzz_names)
        self.assertEqual(workflow.count("GOTOOLCHAIN: go1.27.3"), 2)
        for target in ("FuzzMetadataSelection", "FuzzPrivateImporterJSON", "FuzzMCPProtocol",
                       "FuzzAgeEnvelope", "FuzzAgeDecrypt", "FuzzAgeKeyFiles"):
            self.assertEqual(job.count(target), 1, target)

    def test_every_tag_check_follows_explicit_annotated_tag_restoration(self):
        fetch = 'git fetch --no-tags --force origin "refs/tags/v0.2.3:refs/tags/v0.2.3"'
        tag_type = 'git cat-file -t refs/tags/v0.2.3'
        peel = "git rev-parse 'refs/tags/v0.2.3^{commit}'"
        for filename, names in (
                ("release.yml", ("release-repro", "release-verify", "release-publish")),
                ("plugin.yml", ("plugin-install-linux", "plugin-install-macos"))):
            jobs = workflow_jobs(filename)
            for name in names:
                with self.subTest(workflow=filename, job=name):
                    job = jobs[name]
                    self.assertIn("fetch-depth: 0", job)
                    self.assertIn("persist-credentials: false", job)
                    self.assertLess(job.index("uses: actions/checkout@"), job.index(fetch))
                    self.assertLess(job.index(fetch), job.index(tag_type))
                    self.assertLess(job.index(tag_type), job.index(peel))
                    self.assertIn('test "$(' + peel + ')" = "$GITHUB_SHA"', job)
                    # Script entry points can inspect tags too, so restore before them.
                    self.assertLess(job.index(fetch), job.index("sh scripts/verify-release.sh"))
                    if filename == "plugin.yml":
                        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.published", job)
                        self.assertLess(job.index(fetch), job.index("--published"))

    def test_real_provenance_rehearsal_is_read_only_and_runs_on_pr_head(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        job = workflow_jobs("release.yml")["release-rehearsal"]
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("if: github.event_name == 'pull_request' || github.event_name == 'workflow_dispatch'", job)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", job)
        self.assertIn("fetch-depth: 0", job)
        self.assertIn("persist-credentials: false", job)
        permissions = re.search(r"^    permissions:\n((?:      [^\n]*\n)+)", job, re.MULTILINE)
        self.assertIsNotNone(permissions)
        self.assertEqual(textwrap.dedent(permissions[1]), "contents: read\nattestations: read\n")
        self.assertNotIn("secrets.", job)
        self.assertIn("GH_TOKEN: ${{ github.token }}", job)
        self.assertIn("go-version: '1.26.10'", job)
        self.assertIn("GOTOOLCHAIN: local", job)
        self.assertIn("python3 -I scripts/rehearse-release.py", job)
        rehearsal = (ROOT / "scripts/rehearse-release.py").read_text()
        self.assertIn('TAG = "v0.2.2"', rehearsal)
        self.assertIn('FINAL = "68b2cf8c5e9196f4d79afc032ea95b535751971d"', rehearsal)
        self.assertIn('source.replace("0.2.3", "0.2.2")', rehearsal)
        self.assertIn('"cat-file", "-t", "refs/tags/" + TAG', rehearsal)
        self.assertIn('run("sh", verify, assets, FINAL, env=env)', rehearsal)
        self.assertIn('"--bundle-dir", bundles', rehearsal)
        self.assertIn('run("sh", install, "--from-dir", inputs, env=env)', rehearsal)
        self.assertIn('run("sh", verify, corrupt, FINAL, "--bundle-dir", bundles, env=env, deny=True)', rehearsal)
        self.assertIn('run("sh", install, "--from-dir", corrupt, env=bad_env, deny=True)', rehearsal)
        self.assertIn('run("sh", verify, assets, source, env=env, deny=True)', rehearsal)
        self.assertIn('("--source-digest", source)', rehearsal)
        self.assertIn('("--source-ref", "refs/tags/v0.2.3")', rehearsal)
        self.assertIn('"--offline", "--from-dir", inputs', rehearsal)
        self.assertIn('"worktree", "remove", "--force", worktree', rehearsal)
        self.assertLess(rehearsal.index('worktree / "scripts/build-release.sh"'),
                        rehearsal.index('source.replace("0.2.3", "0.2.2")'))

    def test_gh_attestation_argvs_respect_mutually_exclusive_flag_groups(self):
        # gh 2.102.0 verify/verify.go and download/download.go declare these
        # groups. Scan executable Python argv lists, embedded Python, shell,
        # workflow run blocks and documented commands, without requiring gh.
        groups = ({"--owner", "--repo"},
                  {"--cert-identity", "--cert-identity-regex", "--signer-repo", "--signer-workflow"})
        aliases = {"-o": "--owner", "-R": "--repo", "-i": "--cert-identity-regex"}
        found = []
        paths = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "--cached", "--others",
                                         "--exclude-standard"], text=True).splitlines()
        for name in paths:
            path = ROOT / name
            if path.suffix not in (".sh", ".py", ".yml", ".md"):
                continue
            text = path.read_text()
            # Shell and Markdown continuations are one argv, not separate lines.
            shell = text.replace("\\\n", " ")
            for match in re.finditer(r"\bgh\s+attestation\s+(verify|download)\b[^\n]*", shell):
                found.append((name, match[1], shlex.split(match[0])))
            sources = [text] if path.suffix == ".py" else re.findall(
                r"<<'PY'[^\n]*\n(.*?)^PY$", text, re.MULTILINE | re.DOTALL)
            for source in sources:
                for node in ast.walk(ast.parse(source)):
                    if not isinstance(node, ast.List) or len(node.elts) < 3:
                        continue
                    prefix = [item.value if isinstance(item, ast.Constant) else None
                              for item in node.elts[:3]]
                    if prefix[:2] == ["gh", "attestation"] and prefix[2] in ("verify", "download"):
                        found.append((name, prefix[2], [item.value for item in node.elts
                                                       if isinstance(item, ast.Constant)
                                                       and isinstance(item.value, str)]))
        self.assertTrue(any(name == "scripts/verify-release.sh" for name, _, _ in found))
        self.assertTrue(any(name == "scripts/install-release.sh" for name, _, _ in found))
        self.assertTrue(any(name == "scripts/rehearse-release.py" for name, _, _ in found))
        for name, operation, argv in found:
            with self.subTest(path=name, operation=operation, argv=argv):
                flags = {aliases.get(arg.split("=", 1)[0], arg.split("=", 1)[0]) for arg in argv}
                for group in groups[:2 if operation == "verify" else 1]:
                    self.assertLessEqual(len(flags & group), 1, "mutually exclusive gh attestation flags")

    def test_candidate_and_final_job_boundaries(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        jobs = dict(re.findall(r"^  (release-[a-z-]+):\n(.*?)(?=^  release-|\Z)",
                               workflow, re.MULTILINE | re.DOTALL))
        self.assertEqual(set(jobs), {"release-build-a", "release-build-b", "release-repro",
                                     "release-attest", "release-verify", "release-publish",
                                     "release-rehearsal"})
        for name in ("release-attest", "release-verify", "release-publish"):
            self.assertIn("github.event_name == 'push'", jobs[name])
            self.assertIn("github.ref == 'refs/tags/v0.2.3'", jobs[name])
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
        self.assertIn('[{"name": "v0.2.3", "type": "tag"}]', jobs["release-verify"])
        self.assertNotIn("prevent_self_review", jobs["release-verify"])
        self.assertIn("attestations: read", jobs["release-verify"])
        for job, dependency in (("release-attest", "release-repro"),
                                ("release-verify", "release-attest"),
                                ("release-publish", "release-verify")):
            self.assertIn("needs: " + dependency, jobs[job])
        self.assertIn("id-token: write", jobs["release-attest"])
        self.assertIn("attestations: write", jobs["release-attest"])
        self.assertIn("contents: write", jobs["release-publish"])
        self.assertIn('--bundle-dir "$PWD/assets"', jobs["release-publish"])
        self.assertIn('--verify-tag --target "$GITHUB_SHA"', jobs["release-publish"])
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
