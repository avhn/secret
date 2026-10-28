#!/usr/bin/env python3
"""Native install integration in disposable HOME directories, never host protection.

Run with Python -I and absolute checkout and candidate asset directories. Candidate
checksums and the attestation bypass marker exist only in disposable clones.
Transport fault injection is a PATH shim in the test, not a production option.
--published repeats the public release install without the fixture bypass.
The default --stage m4 retains Bash installation and checks version equality.
--stage v0.3.0 additionally requires the release version, without Go activation.
--stage m4.1 explicitly selects deferred activation, never the release gate.
Linux/macOS checkout-launcher tests are separate from test-release-windows.ps1.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SCRIPT = Path(__file__).resolve()
CONTRACT = json.loads((SCRIPT.parent.parent / "testdata/plugin/contracts.json").read_text())
VERSION = CONTRACT["version"]
ASSETS = CONTRACT["assets"]
CHECKOUT = None
ASSET_DIR = None
PUBLISHED = False


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def transport(name, args):
    """Test-only executables. Never contact a network or accept provenance."""
    config = json.loads(Path(os.environ["PLUGIN_TRANSPORT_CONFIG"]).read_text())
    root = Path(config["root"])
    with (root / (name + ".calls")).open("a") as stream:
        stream.write(json.dumps(args) + "\n")
    if name == "gh":
        # These responses only drive negative cases. No synthetic attestation is
        # permitted to result in a successful installation.
        if args[:2] == ["attestation", "download"]:
            sha = digest(Path(args[2]))
            Path("sha256:" + sha + ".jsonl").write_text("{}\n")
            return 0
        if args[:2] == ["attestation", "trusted-root"]:
            print("{}")
            return 0
        if args[:2] == ["attestation", "verify"]:
            required = {"--repo": "avhn/secret",
                        "--cert-identity": "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v" + VERSION,
                        "--signer-digest": "1" * 40,
                        "--source-digest": "1" * 40,
                        "--source-ref": "refs/tags/v" + VERSION,
                        "--cert-oidc-issuer": "https://token.actions.githubusercontent.com"}
            for flag, value in required.items():
                if flag not in args or args[args.index(flag) + 1] != value:
                    return 96
            (root / "verify.reached").touch()
            if config["mode"] == "wrong-subject":
                print(json.dumps([{"verificationResult": {"statement": {
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [{"name": "wrong-release-subject", "digest": {"sha256": digest(Path(args[2]))}}]
                }}}]))
                return 0
            print("synthetic verifier rejection", file=sys.stderr)
            return 1
        return 96
    if name == "git":
        # Pin only the disposable negative-test checkout. This is deliberately
        # not evidence of final C/tag authentication.
        if args[-3:] == ["cat-file", "-t", "refs/tags/v" + VERSION]:
            if config["mode"] == "missing-tag":
                return 1
            print("commit" if config["mode"] == "lightweight-tag" else "tag")
            return 0
        if args[-3:] == ["rev-parse", "--verify", "HEAD"]:
            print("1" * 40)
            return 0
        if args[-3:] == ["rev-parse", "--verify", "refs/tags/v" + VERSION + "^{commit}"]:
            print(("2" if config["mode"] == "wrong-tag-target" else "1") * 40)
            return 0
        if args[-2:] == ["show", "HEAD:dist/checksums-v" + VERSION + ".txt"]:
            sys.stdout.write(Path(config["manifest"]).read_text())
            return 0
        return subprocess.call([config["git"], *args])
    if name == "cp":
        if any(Path(arg).name in ASSETS for arg in args):
            (root / "copy.started").touch()
            while not (root / "copy.release").exists():
                time.sleep(0.05)
        return subprocess.call([config["cp"], *args])
    if name == "curl":
        # Assert that production supplies bounded, HTTPS-only transport options.
        if not ("--max-time" in args and "--connect-timeout" in args
                and "--proto" in args and "=https" in args):
            return 96
        if "--location" in args or "-L" in args:
            if "--proto-redir" not in args or "--max-redirs" not in args:
                return 96
        url = next((arg for arg in args if arg.startswith("https://")), "")
        prefix = "https://github.com/avhn/secret/releases/download/v" + VERSION + "/"
        if not url.startswith(prefix) or url[len(prefix):] not in ASSETS:
            return 96
        output = None
        for index, arg in enumerate(args[:-1]):
            if arg in ("--output", "-o"):
                output = Path(args[index + 1])
        if output is None:
            return 96
        mode = config["mode"]
        if mode == "stall":
            (root / "curl.started").touch()
            # Obey curl's production deadline, rather than a test-only timeout.
            limit = float(args[args.index("--max-time") + 1])
            time.sleep(limit + 0.1)
            return 28
        if mode == "redirect":
            # Return a real HTTP redirect response to the production parser.
            # It must reject this host without making a second request.
            headers = Path(args[args.index("--dump-header") + 1])
            headers.write_bytes(b"HTTP/1.1 302 Found\r\nLocation: https://untrusted.example/asset\r\n\r\n")
            output.write_bytes(b"")
            print("302", end="")
            return 0
        source = Path(config["assets"]) / url[len(prefix):]
        data = source.read_bytes()
        if mode == "truncated":
            data = data[:64]
        elif mode == "corrupt":
            data = data[:-1] + bytes([data[-1] ^ 1])
        output.write_bytes(data)
        print("200", end="")
        return 0
    raise ValueError("unknown test transport: " + name)


class HTTPNetworkWitness:
    """Deny and count proxy connections, without logging requests or forwarding.

    Real gh uses the standard HTTP(S) proxy environment. This witnesses that
    transport, not arbitrary networking or host-level sandbox protection.
    """

    def __init__(self):
        self.attempts = 0
        self.lock = threading.Lock()
        witness = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with witness.lock:
                    witness.attempts += 1
                try:
                    self.request.sendall(b"HTTP/1.1 502 Network disabled\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def environment(self, env):
        result = dict(env)
        proxy = "http://127.0.0.1:" + str(self.server.server_address[1])
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            result[name] = proxy
        result.update(NO_PROXY="", no_proxy="")
        return result


class OfflineNetworkTests(unittest.TestCase):
    def test_network_witness_blocks_real_gh(self):
        with tempfile.TemporaryDirectory(prefix="secret-plugin-network-") as name:
            root = Path(name).resolve()
            env = {"PATH": os.environ["PATH"], "HOME": str(root), "GH_CONFIG_DIR": str(root / "gh"),
                   "XDG_CACHE_HOME": str(root / "cache"), "GH_PROMPT_DISABLED": "1",
                   "GH_TOKEN": "synthetic-network-probe-not-a-credential"}
            with HTTPNetworkWitness() as network:
                result = subprocess.run(["gh", "api", "--hostname", "github.com", "/meta"],
                                        cwd=root, env=network.environment(env),
                                        capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0, "network probe unexpectedly succeeded")
                self.assertGreater(network.attempts, 0, "real gh bypassed the network witness")


class ManifestTests(unittest.TestCase):
    def test_four_versions_and_codex_paths(self):
        versions = []
        self.assertEqual(len(CONTRACT["manifests"]), 4)
        for name, keys in CONTRACT["manifests"].items():
            value = json.loads((CHECKOUT / name).read_text())
            for key in keys:
                value = value[key]
            self.assertIsInstance(value, str)
            self.assertTrue(value)
            versions.append(value)
        self.assertEqual(len(set(versions)), 1, "all four manifest versions must agree")
        for name, command in CONTRACT["codex_commands"].items():
            with self.subTest(codex=name):
                groups = json.loads((CHECKOUT / name).read_text())["hooks"]["PreToolUse"]
                self.assertTrue(groups)
                hooks = [hook for group in groups for hook in group["hooks"]]
                self.assertTrue(hooks)
                for hook in hooks:
                    self.assertEqual(hook["command"], command)
                    self.assertEqual(hook["timeout"], 5)
                    self.assertEqual(hook["type"], "command")
                    self.assertNotIn("onFailure", hook)

    def test_no_shipped_bypass_marker(self):
        marker = CHECKOUT / ".secret-release-test-fixture"
        self.assertFalse(marker.exists() or marker.is_symlink())
        result = subprocess.run(["git", "-C", str(CHECKOUT), "ls-files",
                                 ".secret-release-test-fixture"],
                                capture_output=True, check=True)
        self.assertEqual(result.stdout, b"")


class M4ShippedManifestTests(unittest.TestCase):
    """M4 packages opt-in launchers without changing what the plugins install."""

    def test_claude_stays_on_bash(self):
        groups = json.loads((CHECKOUT / "hooks/hooks.json").read_text())["hooks"]["PreToolUse"]
        self.assertEqual(len(groups), 2)
        self.assertEqual([group["matcher"] for group in groups],
                         ["Bash", "Read|Grep|Edit|Write|MultiEdit|NotebookEdit"])
        for group in groups:
            self.assertTrue(group["hooks"])
            for hook in group["hooks"]:
                self.assertEqual(hook["type"], "command")
                self.assertEqual(hook["timeout"], 5)
                self.assertEqual(hook["command"], "${CLAUDE_PLUGIN_ROOT}/hooks/guard-secrets")
                self.assertNotIn("onFailure", hook)

    def test_go_launchers_exist_but_are_not_activated(self):
        for name in ("hooks/guard-go", "bin/secret-go"):
            path = CHECKOUT / name
            self.assertTrue(path.is_file(), "missing staged launcher: " + name)
            self.assertTrue(os.access(path, os.X_OK), "launcher is not executable: " + name)
        manifests = set(CONTRACT["manifests"]) | set(CONTRACT["codex_commands"]) | {"hooks/hooks.json"}
        for name in manifests:
            with self.subTest(manifest=name):
                contents = (CHECKOUT / name).read_text()
                self.assertNotIn("guard-go", contents)
                self.assertNotIn("secret-go", contents)


class V030ManifestTests(M4ShippedManifestTests):
    """Version-only release: inherit the unchanged Bash/nonactivation contract."""

    def test_four_versions_match_release(self):
        self.assertEqual(VERSION, "0.3.0")
        for name, keys in CONTRACT["manifests"].items():
            with self.subTest(manifest=name):
                value = json.loads((CHECKOUT / name).read_text())
                for key in keys:
                    value = value[key]
                self.assertEqual(value, VERSION)


class M41ActivationManifestTests(unittest.TestCase):
    """Deferred cutover gate, enabled explicitly with --stage m4.1 only."""

    def test_four_versions_match_release(self):
        for name, keys in CONTRACT["manifests"].items():
            with self.subTest(manifest=name):
                value = json.loads((CHECKOUT / name).read_text())
                for key in keys:
                    value = value[key]
                self.assertEqual(value, VERSION)

    def test_claude_activation_contract(self):
        groups = json.loads((CHECKOUT / "hooks/hooks.json").read_text())["hooks"]["PreToolUse"]
        self.assertEqual(len(groups), 2)
        for group in groups:
            self.assertTrue(group["hooks"])
            for hook in group["hooks"]:
                self.assertEqual(hook["type"], "command")
                self.assertEqual(hook["timeout"], 5)
                self.assertEqual(hook["onFailure"], "block")
                self.assertIn('"', hook["command"])
                self.assertIn("/hooks/guard-go", hook["command"])
                self.assertNotIn("guard-secrets", hook["command"])


class InstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = {"Linux": "linux", "Darwin": "darwin"}
        arches = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
        if platform.system() not in names or platform.machine() not in arches:
            raise RuntimeError("native Linux/macOS amd64/arm64 is required; no silent skip")
        cls.asset = "secret-v%s-%s-%s" % (VERSION, names[platform.system()], arches[platform.machine()])
        for name in ASSETS:
            if not (ASSET_DIR / name).is_file():
                raise RuntimeError("missing release asset: " + name)
        cls.expected_manifest = "".join(digest(ASSET_DIR / name) + "  " + name + "\n" for name in ASSETS)
        if (ASSET_DIR / ("checksums-v" + VERSION + ".txt")).read_bytes() != cls.expected_manifest.encode():
            raise RuntimeError("candidate checksum manifest does not match all eight payloads")
        cls.required = ["scripts/install-release.sh", "hooks/guard-go", "bin/secret-go"]
        for name in cls.required:
            if not (CHECKOUT / name).is_file():
                raise RuntimeError("missing frozen release entrypoint: " + name)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="secret-plugin-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home with spaces"
        self.home.mkdir(mode=0o700)
        self.other = self.root / "other cwd"
        self.other.mkdir()
        self.checkout = self.home / ".local/share/secret"
        self.checkout.parent.mkdir(parents=True)
        # Exercise the README clone layout without network or host HOME writes.
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home), "LC_ALL": "C",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(CHECKOUT), str(self.checkout)],
                       cwd=self.other, env=env, capture_output=True, check=True)
        # Candidate workflows and local workers can have changes not yet committed.
        for name in self.required:
            dest = self.checkout / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(CHECKOUT / name, dest)
            dest.chmod(0o700)
        self.manifest = self.checkout / ("dist/checksums-v" + VERSION + ".txt")
        self.manifest.parent.mkdir(exist_ok=True)
        self.manifest.write_text(self.expected_manifest)
        self.manifest.chmod(0o600)
        (self.checkout / ".secret-release-test-fixture").touch(mode=0o600)
        self.assets = self.root / "downloaded assets"
        self.assets.mkdir(mode=0o700)
        for name in ASSETS:
            shutil.copy2(ASSET_DIR / name, self.assets / name)
        self.cache_home = self.home / ".cache"
        self.cache_home.mkdir(mode=0o700)
        self.cache = self.cache_home / "secret" / ("v" + VERSION)
        self.lock = Path(str(self.cache) + ".lock")
        self.tools = self.root / "test tools"
        self.tools.mkdir(mode=0o700)
        self.config = self.root / "transport.json"
        self.config.write_text(json.dumps({"root": str(self.root), "assets": str(self.assets),
                                          "mode": "valid", "cp": shutil.which("cp"),
                                          "git": shutil.which("git"), "manifest": str(self.manifest)}))
        self.env = dict(env, XDG_CACHE_HOME=str(self.cache_home),
                        SECRET_RELEASE_TEST_ROOT=str(self.cache_home),
                        PLUGIN_TRANSPORT_CONFIG=str(self.config), TMPDIR=str(self.root))
        # A PATH secret must never be used as a launcher fallback.
        self.fallback = self.root / "fallback.witness"
        self.script(self.tools / "secret", "printf fallback > " + shlex.quote(str(self.fallback)) + "\nexit 99\n")
        self.env["PATH"] = str(self.tools) + os.pathsep + env["PATH"]
        self.store = self.home / "synthetic.secret"
        self.store.write_text(CONTRACT["synthetic_store"])
        self.store.chmod(0o600)
        self.env.update(SECRETS_ENV=str(self.store), SECRETS_DIR=str(self.home / "absent stores"))
        self.cli = self.checkout / "bin/secret-go"
        self.hook = self.checkout / "hooks/guard-go"
        self.installer = self.checkout / "scripts/install-release.sh"

    @staticmethod
    def script(path, body):
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o700)

    def shim(self, name):
        self.script(self.tools / name, "exec " + shlex.quote(sys.executable) + " -I "
                    + shlex.quote(str(SCRIPT)) + " --transport " + name + ' "$@"\n')

    def configure_transport(self, mode):
        config = json.loads(self.config.read_text())
        config["mode"] = mode
        self.config.write_text(json.dumps(config))
        self.shim("curl")
        self.shim("gh")

    def trusted_negative_pin(self):
        (self.checkout / ".secret-release-test-fixture").unlink()
        self.env.pop("SECRET_RELEASE_TEST_ROOT")
        self.shim("git")

    def command(self, args, status=0, timeout=90, input=None, env=None):
        result = subprocess.run([str(arg) for arg in args], input=input, cwd=self.other,
                                env=env or self.env, capture_output=True, timeout=timeout)
        # Synthetic values are never emitted as assertion diagnostics.
        sentinel = CONTRACT["synthetic_store"].split("=", 1)[1].strip().encode()
        self.assertNotIn(sentinel, result.stdout + result.stderr, "synthetic value leaked")
        self.assertEqual(result.returncode, status,
                         "unexpected status for " + Path(args[0]).name + ": "
                         + str(result.returncode) + "; stderr=" + result.stderr[-1500:].decode(errors="replace"))
        self.assertFalse(self.fallback.exists(), "launcher executed PATH fallback")
        return result

    def install(self, status=0, extra=(), env=None):
        return self.command([self.installer, "--from-dir", self.assets, *extra], status=status, env=env)

    def deny(self, env=None):
        result = self.command([self.hook], input=b'{"tool_name":"Bash","tool_input":{"command":"true"}}', env=env)
        self.assertEqual(result.stdout, (json.dumps(CONTRACT["bootstrap_denial"], separators=(",", ":")) + "\n").encode())
        self.assertEqual(result.stderr, b"")
        result = self.command([self.cli, "version"], status=70, env=env)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"secret: verified binary unavailable; run scripts/install-release.sh\n")
        self.assertFalse((self.root / "child.witness").exists())

    def assert_published(self):
        binary = self.cache / "secret"
        self.assertTrue(binary.is_file(), "installer did not publish the frozen cache path")
        self.assertFalse(binary.is_symlink())
        self.assertEqual(digest(binary), digest(self.assets / self.asset))
        self.assertEqual({path.name for path in self.cache.iterdir()}, {"secret", "verified"})
        for path, mode in ((self.cache, 0o700), (binary, 0o500), (self.cache / "verified", 0o600)):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            self.assertEqual(path.stat().st_uid, os.getuid())
        metadata = (self.cache / "verified").read_text().splitlines()
        self.assertEqual(len(metadata), 5)
        fields = dict(line.split("=", 1) for line in metadata)
        self.assertEqual(set(fields), {"version", "asset", "sha256", "commit", "tag"})
        self.assertEqual(fields["version"], VERSION)
        self.assertEqual(fields["asset"], self.asset)
        self.assertEqual(fields["sha256"], digest(binary))
        self.assertEqual(fields["tag"], "v" + VERSION)
        self.assertEqual(fields["commit"], "fixture")
        self.assertFalse(self.lock.exists(), "successful installer left its lock")
        self.assertFalse(list(self.cache.parent.glob(".install.*")), "successful installer left scratch state")

    def test_cold_install_warm_offline_readme_flow(self):
        self.install()
        self.assert_published()
        self.configure_transport("redirect")
        self.install(extra=("--offline",))
        links = self.home / ".local/bin"
        links.mkdir(parents=True)
        absolute = links / "secret"
        absolute.symlink_to(self.cli)
        middle = links / "relative-middle"
        middle.symlink_to(os.path.relpath(self.cli, links))
        relative = links / "relative-secret"
        relative.symlink_to("relative-middle")
        for launcher in (absolute, relative):
            with self.subTest(launcher=launcher.name):
                version = self.command([launcher, "version"])
                self.assertEqual(version.stdout, ("secret " + VERSION + " (go)\n").encode())
                shown = self.command([launcher, "show", self.store])
                self.assertIn(b"PLUGIN_TOKEN=<", shown.stdout)
                witness = self.root / "child.witness"
                result = self.command([launcher, "run", "-f", self.store, "--key", "PLUGIN_TOKEN", "--",
                                       "/bin/sh", "-c", 'printf "%s\\n" "$PLUGIN_TOKEN"; : > "$1"',
                                       "synthetic-child", witness])
                self.assertTrue(witness.exists(), "verified Go CLI did not run the child")
                self.assertIn(b"<redacted>", result.stdout)
                witness.unlink()
        # A protected-path denial proves that the verified hook received stdin.
        request = json.dumps({"tool_name": "Read", "tool_input": {"file_path": str(self.store)},
                              "cwd": str(self.other)}).encode()
        guarded = self.command([self.hook], input=request)
        self.assertEqual(json.loads(guarded.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertFalse((self.root / "curl.calls").exists(), "warm offline operation used network")
        self.assertFalse((self.root / "gh.calls").exists(), "fixture tried provenance network")

    def test_cold_offline_denial(self):
        self.configure_transport("valid")
        self.trusted_negative_pin()
        self.command([self.installer, "--offline"], status=1)
        self.deny()
        self.assertFalse((self.root / "curl.calls").exists())

    def test_production_pin_rejects_missing_lightweight_or_wrong_target_tag(self):
        self.trusted_negative_pin()
        for mode in ("missing-tag", "lightweight-tag", "wrong-tag-target"):
            with self.subTest(tag=mode):
                self.configure_transport(mode)
                self.command([self.installer], status=1)
                self.install(status=1, extra=("--offline",))
                self.assertFalse((self.root / "curl.calls").exists())
                self.assertFalse((self.root / "gh.calls").exists())
                self.assertFalse((self.cache / "secret").exists())

    def test_fixture_environment_alone_never_bypasses_verification(self):
        (self.checkout / ".secret-release-test-fixture").unlink()
        self.configure_transport("valid")
        self.install(status=1)
        self.deny()
        self.assertFalse((self.cache / "secret").exists())

    def test_malformed_manifests(self):
        lines = self.expected_manifest.splitlines(keepends=True)
        variants = {
            "duplicate": self.expected_manifest + lines[0],
            "missing": "".join(lines[1:]),
            "unsorted": "".join(reversed(lines)),
            "uppercase": self.expected_manifest.upper(),
            "path": self.expected_manifest.replace("  secret-", "  ../secret-", 1),
            "blank": self.expected_manifest + "\n",
            "comment": "# synthetic\n" + self.expected_manifest,
            "single-space": self.expected_manifest.replace("  ", " ", 1),
            "crlf": self.expected_manifest.replace("\n", "\r\n"),
            "no-final-lf": self.expected_manifest.rstrip("\n"),
            "wrong-version": self.expected_manifest.replace("v" + VERSION, "v0.0.0"),
        }
        for name, contents in variants.items():
            with self.subTest(malformed=name):
                self.manifest.write_text(contents)
                self.install(status=1)
                self.deny()
                self.assertFalse((self.cache / "secret").exists())

    def test_wrong_digest_and_corrupt_local_asset(self):
        path = self.assets / self.asset
        original = path.read_bytes()
        for contents in (original[:64], original[:-1] + bytes([original[-1] ^ 1])):
            with self.subTest(length=len(contents)):
                path.write_bytes(contents)
                self.install(status=1)
                self.deny()
                self.assertFalse((self.cache / "secret").exists())

    def test_native_arch_alias_and_unsupported_platform(self):
        alias = {"x86_64": "amd64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "aarch64"}[platform.machine()]

        def uname(os_name, arch):
            self.script(self.tools / "uname", 'case "$1" in\n-s) printf "%s\\n" '
                        + shlex.quote(os_name) + ' ;;\n-m) printf "%s\\n" '
                        + shlex.quote(arch) + ' ;;\n*) exit 1 ;;\nesac\n')

        uname(platform.system(), alias)
        self.install()
        self.assert_published()
        for os_name, arch in (("Plan9", alias), (platform.system(), "riscv64")):
            with self.subTest(os=os_name, arch=arch):
                uname(os_name, arch)
                self.install(status=4)
                self.deny()

    def test_wrong_binary_architecture_and_version(self):
        other_asset = next(name for name in ASSETS if name != self.asset)
        native = self.assets / self.asset
        original = native.read_bytes()
        wrong_version = original.replace(VERSION.encode(), b"0.0.0")
        self.assertNotEqual(original, wrong_version, "release version not found in native asset")
        for label, contents in (("architecture", (self.assets / other_asset).read_bytes()),
                                ("version", wrong_version)):
            with self.subTest(binary=label):
                native.write_bytes(contents)
                sha = digest(native)
                self.manifest.write_text("".join(sha + line[64:] if self.asset in line else line
                                                 for line in self.expected_manifest.splitlines(keepends=True)))
                self.install(status=1)
                self.deny()
                self.assertFalse((self.cache / "secret").exists())

    def test_unsafe_manifest_and_cache_destinations(self):
        self.install()
        binary = self.cache / "secret"
        original = binary.read_bytes()
        binary.unlink()
        outside = self.root / "outside-binary"
        outside.write_bytes(original)
        outside.chmod(0o500)
        binary.symlink_to(outside)
        self.deny()
        self.install(status=1)
        self.assertTrue(binary.is_symlink())
        self.assertEqual(digest(outside), digest(self.assets / self.asset))
        binary.unlink()
        binary.write_bytes(original)
        binary.chmod(0o500)
        original_manifest = self.manifest.read_text()
        self.manifest.chmod(0o666)
        self.deny()
        self.install(status=1)
        self.manifest.chmod(0o600)
        self.manifest.unlink()
        alternate = self.root / "alternate-manifest"
        alternate.write_text(original_manifest)
        alternate.chmod(0o600)
        self.manifest.symlink_to(alternate)
        self.deny()
        self.install(status=1)

    def test_cached_binary_rehashed_before_each_exec(self):
        self.install()
        binary = self.cache / "secret"
        binary.chmod(0o700)
        binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        binary.chmod(0o500)
        self.deny()

    def test_wrong_platform_manifest_cannot_execute(self):
        self.install()
        lines = self.expected_manifest.splitlines(keepends=True)
        self.manifest.write_text("".join("0" * 64 + line[64:] if self.asset in line else line for line in lines))
        self.deny()

    def test_missing_hash_utilities(self):
        self.install()
        restricted = self.root / "restricted tools"
        restricted.mkdir()
        # Neither sha256sum nor shasum nor openssl is available. Preserve other
        # ordinary tools so this tests the hash dependency, not checkout discovery.
        for name in ("uname", "id", "stat", "readlink", "dirname", "basename", "awk", "sed", "grep", "cat",
                     "head", "tail", "cut", "tr", "wc", "od", "ls", "test", "pwd", "date", "cmp", "chmod",
                     "mv", "cp", "rm", "rmdir", "mkdir", "mktemp", "sleep", "git", "python3"):
            tool = shutil.which(name)
            if tool:
                (restricted / name).symlink_to(tool)
        env = dict(self.env, PATH=str(restricted))
        self.deny(env=env)

    def test_lock_timeout_no_stealing(self):
        self.lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock.mkdir(mode=0o700)
        owner = self.lock / "owner"
        original = "pid=999999\ntoken=synthetic-stale-lock-token\n"
        owner.write_text(original)
        owner.chmod(0o600)
        result = self.install(status=3)
        self.assertEqual(result.stderr, b"secret: installation lock timeout; verify and remove stale lock manually\n")
        self.assertEqual(owner.read_text(), original)
        self.deny()

    def test_simultaneous_first_installs(self):
        args = [str(self.installer), "--from-dir", str(self.assets)]
        processes = [subprocess.Popen(args, cwd=self.other, env=self.env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            for process in processes:
                process.communicate(timeout=90)
                self.assertEqual(process.returncode, 0)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assert_published()
        self.command([self.cli, "version"])

    def test_killed_installer_keeps_owned_lock_and_no_partial_exec(self):
        self.shim("cp")
        process = subprocess.Popen([str(self.installer), "--from-dir", str(self.assets)],
                                   cwd=self.other, env=self.env, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while not (self.root / "copy.started").exists():
                self.assertIsNone(process.poll(), "installer exited before copy fault injection")
                if time.monotonic() > deadline:
                    self.fail("installer did not reach the copy fault injection")
                time.sleep(0.02)
            self.assertTrue(self.lock.is_dir())
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertTrue((self.lock / "owner").is_file(), "killed owner lock was stolen or removed")
            self.assertFalse((self.cache / "secret").exists(), "partial binary published")
            self.deny()
            (self.tools / "cp").unlink()
            self.install(status=3)
            self.assertTrue((self.lock / "owner").is_file())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()

    def test_missing_verifier(self):
        self.trusted_negative_pin()
        restricted = self.root / "no verifier"
        restricted.mkdir()
        for name in ("uname", "id", "stat", "readlink", "dirname", "basename", "awk", "sed", "grep", "cat",
                     "head", "tail", "cut", "tr", "wc", "od", "ls", "date", "mkdir", "rmdir", "rm", "chmod",
                     "cp", "mv", "sha256sum", "shasum", "openssl", "curl", "sort", "sleep", "mktemp", "cmp", "python3"):
            tool = shutil.which(name)
            if tool:
                (restricted / name).symlink_to(tool)
        (restricted / "git").symlink_to(self.tools / "git")
        self.install(status=4, env=dict(self.env, PATH=str(restricted)))
        self.deny()

    def test_download_faults_and_negative_provenance(self):
        self.trusted_negative_pin()
        for mode in ("truncated", "corrupt", "redirect", "stall", "valid", "wrong-subject"):
            with self.subTest(transport=mode):
                self.configure_transport(mode)
                result = self.command([self.installer], status=1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"secret: release installation failed\n")
                self.assertTrue((self.root / "curl.calls").exists(), "fault transport was not exercised")
                calls = [json.loads(line) for line in (self.root / "curl.calls").read_text().splitlines()]
                self.assertTrue(calls)
                self.assertEqual(len(calls), 1, "unexpected redirect or repeated download")
                if mode in ("valid", "wrong-subject"):
                    self.assertTrue((self.root / "verify.reached").exists(), "negative provenance verifier not reached")
                    (self.root / "verify.reached").unlink()
                else:
                    self.assertFalse((self.root / "verify.reached").exists())
                self.deny()
                self.assertFalse((self.cache / "secret").exists())
                (self.root / "curl.calls").unlink()


class PublishedTests(unittest.TestCase):
    def test_public_release_without_fixture_bypass(self):
        with tempfile.TemporaryDirectory(prefix="secret-plugin-public-") as name:
            root = Path(name).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            other = root / "other"
            other.mkdir()
            env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_CACHE_HOME": str(home / ".cache"),
                   "LC_ALL": "C", "TMPDIR": str(root), "GH_PROMPT_DISABLED": "1"}
            # The workflow provides only its read-only repository token. Forward
            # it to gh without placing it in argv, diagnostics or test evidence.
            if "GH_TOKEN" in os.environ:
                env["GH_TOKEN"] = os.environ["GH_TOKEN"]
            # The checkout must already be the authenticated final C, not S.
            self.assertFalse((CHECKOUT / ".secret-release-test-fixture").exists())
            self.assertTrue((CHECKOUT / ("dist/checksums-v" + VERSION + ".txt")).is_file())

            def git(*args):
                return subprocess.check_output(["git", "-C", str(CHECKOUT), *args],
                                               cwd=other, env=env, stderr=subprocess.DEVNULL).strip()

            self.assertEqual(git("rev-parse", "--is-shallow-repository"), b"false")
            self.assertEqual(git("cat-file", "-t", "refs/tags/v" + VERSION), b"tag")
            commit = git("rev-parse", "HEAD")
            self.assertEqual(commit, git("rev-parse", "refs/tags/v" + VERSION + "^{commit}"))
            installer = CHECKOUT / "scripts/install-release.sh"

            def command(arguments, expected=0, environment=None, input=None):
                result = subprocess.run([str(arg) for arg in arguments], cwd=other,
                                        env=environment or env, input=input,
                                        capture_output=True, timeout=180)
                # Do not attach network output, credentials or bundles to failures.
                self.assertEqual(result.returncode, expected,
                                 "unexpected public install/launcher status: " + str(result.returncode))
                return result

            command([CHECKOUT / "scripts/verify-release.sh", "--source"])
            # Public standalone installation is distinct from the checkout
            # cache. Neither path may overwrite an existing Bash CLI name.
            standalone_dir = home / "standalone binary with spaces"
            standalone_dir.mkdir(mode=0o700)
            bash_cli = standalone_dir / "secret"
            bash_cli.write_bytes(b"synthetic-existing-bash-cli\n")
            bash_cli.chmod(0o500)
            standalone = standalone_dir / "secret-go"
            bootstrap = CHECKOUT / "install.sh"
            command(["sh", bootstrap, "--version", VERSION, "--commit", commit.decode(),
                     "--dir", standalone_dir])
            self.assertEqual(bash_cli.read_bytes(), b"synthetic-existing-bash-cli\n")
            self.assertEqual(command([standalone, "version"]).stdout,
                             ("secret " + VERSION + " (go)\n").encode())
            standalone_digest = digest(standalone)
            # Omitted C must come from agreeing verified attestations, never
            # latest or a checksum-only path. Replacement keeps exact bytes.
            command(["sh", bootstrap, "--version", VERSION, "--dir", standalone_dir])
            self.assertEqual(digest(standalone), standalone_digest)
            self.assertEqual(bash_cli.read_bytes(), b"synthetic-existing-bash-cli\n")
            command([installer])
            cache = home / (".cache/secret/v" + VERSION)
            binary = cache / "secret"
            metadata = cache / "verified"
            fields = dict(line.split("=", 1) for line in metadata.read_text().splitlines())
            self.assertEqual(fields["commit"], commit.decode())
            self.assertEqual(fields["sha256"], digest(binary))
            expected_metadata = metadata.read_bytes()
            sha = digest(binary)
            # These bytes and the bundle came from the real published install,
            # not candidate ASSET_DIR or fixture-mode provenance.
            downloads = root / "published assets"
            downloads.mkdir(mode=0o700)
            shutil.copyfile(binary, downloads / fields["asset"])
            shutil.copyfile(cache / "attestation.jsonl", downloads / ("sha256:" + sha + ".jsonl"))
            saved_trust = root / "authenticated trust"
            saved_trust.mkdir(mode=0o700)
            shutil.copyfile(cache / "trusted_root.jsonl", saved_trust / "trusted_root.jsonl")

            # Record real verifier dispatch without replacing its behavior. No
            # network-oriented gh subcommand is permitted in the offline phase.
            tools = root / "offline tools"
            tools.mkdir(mode=0o700)
            calls = root / "offline-verification.calls"
            unexpected = root / "offline-unexpected-gh.witness"
            real_gh = shutil.which("gh", path=env["PATH"])
            self.assertIsNotNone(real_gh)
            InstallTests.script(tools / "gh",
                                'if [ "$1" != attestation ] || [ "$2" != verify ]; then\n'
                                + "  : > " + shlex.quote(str(unexpected)) + "\n  exit 96\nfi\n"
                                + "printf 'verify\\n' >> " + shlex.quote(str(calls)) + "\n"
                                + "exec " + shlex.quote(real_gh) + ' "$@"\n')
            offline = dict(env, PATH=str(tools) + os.pathsep + env["PATH"],
                           GH_CONFIG_DIR=str(root / "empty gh config"),
                           XDG_CONFIG_HOME=str(root / "empty xdg config"),
                           XDG_DATA_HOME=str(root / "empty xdg data"))
            offline.pop("GH_TOKEN", None)
            with HTTPNetworkWitness() as network:
                offline = network.environment(offline)
                # Keep the warm shortcut as separate evidence. It must not call gh.
                command([installer, "--offline"], environment=offline)
                self.assertFalse(calls.exists())
                self.assertEqual(network.attempts, 0, "warm cache contacted the network")

                binary.unlink()
                metadata.unlink()
                (cache / "trusted_root.jsonl").unlink()
                self.assertFalse(binary.exists())
                # A bundle alone is insufficient; no trust bootstrap is allowed.
                command([installer, "--from-dir", downloads, "--offline"], 1, offline)
                self.assertFalse(binary.exists(), "trustless offline install published a binary")
                self.assertFalse(metadata.exists())
                self.assertFalse(calls.exists(), "verification ran without authenticated trust")
                result = command([CHECKOUT / "bin/secret-go", "version"], 70, offline)
                self.assertEqual(result.stdout, b"")
                result = command([CHECKOUT / "hooks/guard-go"], environment=offline, input=b"{}")
                self.assertEqual(json.loads(result.stdout), CONTRACT["bootstrap_denial"])
                self.assertEqual(network.attempts, 0, "missing trust triggered network bootstrap")

                shutil.copyfile(saved_trust / "trusted_root.jsonl", cache / "trusted_root.jsonl")
                (cache / "trusted_root.jsonl").chmod(0o600)
                self.assertFalse(binary.exists(), "offline provenance test has a current executable")
                self.assertFalse(metadata.exists())
                command([installer, "--from-dir", downloads, "--offline"], environment=offline)
                self.assertEqual(calls.read_text(), "verify\n", "real gh verifier was not exercised exactly once")
                self.assertFalse(unexpected.exists(), "offline installer attempted a network gh operation")
                self.assertEqual(network.attempts, 0, "real offline verification contacted the network")
                self.assertEqual(digest(binary), sha)
                self.assertEqual(metadata.read_bytes(), expected_metadata)
                for path, mode in ((cache, 0o700), (binary, 0o500), (metadata, 0o600)):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                    self.assertEqual(path.stat().st_uid, os.getuid())
                self.assertFalse(Path(str(cache) + ".lock").exists())
                result = command([CHECKOUT / "bin/secret-go", "version"], environment=offline)
                self.assertEqual(result.stdout, ("secret " + VERSION + " (go)\n").encode())
                binary.chmod(0o700)
                binary.write_bytes(b"#!/bin/sh\nexit 0\n")
                binary.chmod(0o500)
                result = command([CHECKOUT / "hooks/guard-go"], environment=offline, input=b"{}")
                self.assertEqual(json.loads(result.stdout), CONTRACT["bootstrap_denial"])
                self.assertEqual(network.attempts, 0, "offline launcher contacted the network")


def main():
    global CHECKOUT, ASSET_DIR, PUBLISHED
    os.umask(0o077)
    if len(sys.argv) > 2 and sys.argv[1] == "--transport":
        return transport(sys.argv[2], sys.argv[3:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("asset_dir", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--manifest-only", action="store_true")
    mode.add_argument("--published", action="store_true")
    parser.add_argument("--stage", choices=("m4", "m4.1", "v0.3.0"), default="m4",
                        help="default: m4 equality/Bash; v0.3.0 pins versions only; m4.1 is deferred activation")
    args = parser.parse_args()
    if not args.checkout.is_absolute() or not args.asset_dir.is_absolute():
        parser.error("checkout and asset directory must be absolute paths")
    manifest_only, PUBLISHED = args.manifest_only, args.published
    CHECKOUT, ASSET_DIR = [path.resolve(strict=True) for path in (args.checkout, args.asset_dir)]
    print(json.dumps({"os": platform.system(), "architecture": platform.machine(),
                      "image": os.environ.get("ImageOS", "local"),
                      "image_version": os.environ.get("ImageVersion", "unknown"),
                      "runner_arch": os.environ.get("RUNNER_ARCH", "local"),
                      "evidence": ("manifest contract only" if manifest_only else
                                   "native published install" if PUBLISHED else
                                   "native synthetic candidate")}), flush=True)
    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    suite.addTests(loader.loadTestsFromTestCase(ManifestTests))
    stage_checks = {"m4": M4ShippedManifestTests, "m4.1": M41ActivationManifestTests,
                    "v0.3.0": V030ManifestTests}[args.stage]
    suite.addTests(loader.loadTestsFromTestCase(stage_checks))
    if manifest_only:
        pass
    elif PUBLISHED:
        suite.addTests(loader.loadTestsFromTestCase(OfflineNetworkTests))
        suite.addTests(loader.loadTestsFromTestCase(PublishedTests))
    else:
        suite.addTests(loader.loadTestsFromTestCase(OfflineNetworkTests))
        suite.addTests(loader.loadTestsFromTestCase(InstallTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun == 0 or result.skipped:
        print("missing or skipped native install evidence", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
