#!/usr/bin/env python3
"""Offline Registry contract tests. No GitHub, publisher or Registry calls escape."""

from contextlib import contextmanager
import copy
import hashlib
from http.client import HTTPMessage
import importlib.util
import io
import json
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("release_manifest", ROOT / "scripts/release_manifest.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
VERSION = "0.3.0"
TAG = "v" + VERSION
COMMIT = "a" * 40


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def bundle_manifest():
    value = json.loads((ROOT / "packaging/mcpb/manifest.template.json").read_bytes())
    value["version"] = VERSION
    value["documentation"] = f"https://github.com/avhn/secret/blob/{TAG}/docs/setup.md"
    return value


def make_inputs(directory, mutation=None, manifest_bytes=None):
    for name in M.payload_names(VERSION):
        if name not in ("server.json", f"secret-{TAG}-desktop.mcpb"):
            (directory / name).write_bytes(b"synthetic " + name.encode())
    windows = bytearray(96)
    windows[:2] = b"MZ"
    struct.pack_into("<I", windows, 60, 64)
    windows[64:70] = b"PE\0\0\x64\x86"
    struct.pack_into("<H", windows, 88, 0x20B)
    (directory / f"secret-{TAG}-windows-amd64.exe").write_bytes(windows)
    for cpu, subtype, arch in ((0x01000007, 3, "amd64"), (0x0100000C, 0, "arm64")):
        part = bytearray(64)
        part[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<III", part, 4, cpu, subtype, 2)
        (directory / f"secret-{TAG}-darwin-{arch}").write_bytes(part)
    amd = (directory / f"secret-{TAG}-darwin-amd64").read_bytes()
    arm = (directory / f"secret-{TAG}-darwin-arm64").read_bytes()
    mac = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
           + struct.pack(">IIIII", 0x01000007, 3, 48, len(amd), 0)
           + struct.pack(">IIIII", 0x0100000C, 0, 48 + len(amd), len(arm), 0) + amd + arm)
    manifest = bundle_manifest()
    if mutation is not None:
        mutation(manifest)
    entries = {"manifest.json": manifest_bytes if manifest_bytes is not None else json_bytes(manifest),
               "LICENSE": b"synthetic license", "icon.png": b"synthetic icon",
               "server/secret-go": mac, "server/secret-go.exe": bytes(windows)}
    with zipfile.ZipFile(directory / f"secret-{TAG}-desktop.mcpb", "w") as archive:
        for name, value in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if name.startswith("server/") else 0o644)) << 16
            archive.writestr(info, value)


def active_record(value, status="active"):
    return {"server": copy.deepcopy(value),
            "_meta": {"io.modelcontextprotocol.registry/official": {"status": status}}}


class OfflineTest(unittest.TestCase):
    def setUp(self):
        # A missed mock fails instead of opening even a local network connection.
        self.network = patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="secret-registry-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.assets = self.base / "assets"
        self.assets.mkdir()


class GenerationTests(OfflineTest):
    def test_determinism_and_exact_contract(self):
        make_inputs(self.assets)
        other = self.base / "second absolute path"
        other.mkdir()
        make_inputs(other)
        first = M.generate(VERSION, self.assets)
        self.assertEqual(first, M.generate(VERSION, other))
        self.assertEqual(first, M.generate(VERSION, self.assets))
        for name in ("server.json", M.checksum_name(VERSION)):
            self.assertEqual((self.assets / name).read_bytes(), (other / name).read_bytes())
        package = first["packages"]
        self.assertEqual(len(package), 1)
        self.assertEqual(package[0], {"registryType": "mcpb",
                         "identifier": "https://github.com/avhn/secret/releases/download/v0.3.0/secret-v0.3.0-desktop.mcpb",
                         "version": VERSION, "fileSha256": M.digest(self.assets / f"secret-{TAG}-desktop.mcpb"),
                         "transport": {"type": "stdio"}})
        data = (self.assets / M.checksum_name(VERSION)).read_bytes()
        self.assertEqual(len(data.splitlines()), 8)
        self.assertTrue(data.endswith(b"\n"))
        self.assertNotIn(b"\r", data)
        self.assertEqual([line[66:].decode() for line in data.splitlines()], M.payload_names(VERSION))
        self.assertEqual(first["$schema"], M.SCHEMA)
        self.assertEqual(first["name"], M.NAME)
        self.assertNotIn("remotes", first)
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/release_manifest.py"),
                                 "generate", "--version", VERSION, "--assets", str(self.assets)],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bad_versions(self):
        for version in ("v0.3.0", "0.03.0", "0.3.0-rc1", "0.3", "0.3.0\n", "../0.3.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                M.payload_names(version)

    def test_wrong_bundle_identity_platforms_and_config(self):
        mutations = [lambda m: m.update(name="other"), lambda m: m.update(version="0.2.3"),
                     lambda m: m["compatibility"].update(platforms=["linux"]),
                     lambda m: m["compatibility"].update(platforms=["darwin", "win32", "linux"]),
                     lambda m: m["server"]["mcp_config"].update(args=["mcp"]),
                     lambda m: m["server"]["mcp_config"].update(env={"TOKEN": "value"}),
                     lambda m: m["user_config"]["store_reference"].update(default="file:/default"),
                     lambda m: m["user_config"]["store_reference"].update(required=False),
                     lambda m: m.update(compatibility=[]), lambda m: m.update(server=[]),
                     lambda m: m.update(user_config=[]),
                     lambda m: m["user_config"].update(store_reference=[])]
        for index, mutation in enumerate(mutations):
            directory = self.base / str(index)
            directory.mkdir()
            make_inputs(directory, mutation)
            with self.subTest(index=index), self.assertRaises(ValueError):
                M.generate(VERSION, directory)

    def test_duplicate_keys_everywhere(self):
        for raw in (b'{"name":1,"name":2}', b'{"nested":{"x":1,"x":2}}', b'{"n":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.read_json(raw)
        make_inputs(self.assets, manifest_bytes=b'{"name":"secret","name":"secret"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            M.generate(VERSION, self.assets)
        make_inputs(self.assets)
        M.generate(VERSION, self.assets)
        path = self.assets / "server.json"
        path.write_bytes(path.read_bytes().replace(b'"version": "0.3.0",', b'"version": "0.3.0", "version": "0.3.0",', 1))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            M.generate(VERSION, self.assets)

    def test_source_template_identity_and_duplicates(self):
        template = self.base / "packaging/registry"
        template.mkdir(parents=True)
        original = json.loads((ROOT / "packaging/registry/server.template.json").read_bytes())
        for changes in ({"name": "io.github.other/secret"}, {"repository": {"url": "https://example.com"}},
                        {"packages": []}, {"version": VERSION}, {"$schema": "old"}):
            value = dict(original, **changes)
            (template / "server.template.json").write_bytes(json_bytes(value))
            with self.subTest(changes=changes), patch.object(M, "ROOT", self.base), self.assertRaises(ValueError):
                M.source_metadata(VERSION)
        (template / "server.template.json").write_bytes(b'{"name":1,"name":1}')
        with patch.object(M, "ROOT", self.base), self.assertRaisesRegex(ValueError, "duplicate"):
            M.source_metadata(VERSION)

    def test_unexpected_missing_partial_and_symlink_files(self):
        make_inputs(self.assets)
        extra = self.assets / "unexpected"
        extra.write_bytes(b"extra")
        with self.assertRaises(ValueError):
            M.generate(VERSION, self.assets)
        extra.unlink()
        extra = self.assets / "server.json"
        extra.write_bytes(b"{}")
        with self.assertRaises(ValueError):
            M.generate(VERSION, self.assets)
        extra.unlink()
        target = self.assets / f"secret-{TAG}-linux-amd64"
        target.unlink()
        target.symlink_to(self.base / "outside")
        with self.assertRaises(ValueError):
            M.generate(VERSION, self.assets)

    def test_bundle_native_platforms_and_universal_formats(self):
        make_inputs(self.assets)
        bundle = self.assets / f"secret-{TAG}-desktop.mcpb"
        with zipfile.ZipFile(bundle) as archive:
            original = {info.filename: (info, archive.read(info)) for info in archive.infolist()}

        def replace_entry(name, data):
            with zipfile.ZipFile(bundle, "w") as archive:
                for key, (info, value) in original.items():
                    archive.writestr(info, data if name == key else value)

        windows = bytearray(original["server/secret-go.exe"][1])
        windows[68:70] = b"\x64\xaa"
        replace_entry("server/secret-go.exe", windows)
        with self.assertRaisesRegex(ValueError, "Windows bundle architecture"):
            M.generate(VERSION, self.assets)
        mac = bytearray(original["server/secret-go"][1])
        mac[52:56] = struct.pack("<I", 0x0100000C)
        replace_entry("server/secret-go", mac)
        with self.assertRaisesRegex(ValueError, "Mach-O architecture"):
            M.generate(VERSION, self.assets)
        amd = (self.assets / f"secret-{TAG}-darwin-amd64").read_bytes()
        arm = (self.assets / f"secret-{TAG}-darwin-arm64").read_bytes()
        fat64 = (b"\xca\xfe\xba\xbf" + struct.pack(">I", 2)
                 + struct.pack(">IIQQII", 0x01000007, 3, 72, len(amd), 0, 0)
                 + struct.pack(">IIQQII", 0x0100000C, 0, 72 + len(amd), len(arm), 0, 0) + amd + arm)
        replace_entry("server/secret-go", fat64)
        M.generate(VERSION, self.assets)

    def test_stale_hash_and_exact_checksum_grammar(self):
        make_inputs(self.assets)
        M.generate(VERSION, self.assets)
        manifest = self.assets / M.checksum_name(VERSION)
        good = manifest.read_bytes()
        variants = [good[:-1], good.replace(b"\n", b"\r\n"), good + b"\n", good.upper(),
                    good.replace(b"  ", b" ", 1), b"# comment\n" + good,
                    b"".join(good.splitlines(keepends=True)[::-1]),
                    good.replace(b"server.json", b"../server.json"),
                    good.splitlines(keepends=True)[0] * 8,
                    b"0" * 64 + good[64:]]
        for data in variants:
            manifest.write_bytes(data)
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                M.generate(VERSION, self.assets)
        manifest.write_bytes(good)
        target = self.assets / f"secret-{TAG}-linux-amd64"
        target.write_bytes(b"changed bytes")
        with self.assertRaisesRegex(ValueError, "checksums"):
            M.generate(VERSION, self.assets)

    def test_stale_bundle_hash_and_payload_mismatch(self):
        make_inputs(self.assets)
        M.generate(VERSION, self.assets)
        server = self.assets / "server.json"
        value = json.loads(server.read_bytes())
        value["packages"][0]["fileSha256"] = "0" * 64
        server.write_bytes(json_bytes(value))
        with self.assertRaisesRegex(ValueError, "stale bundle hash"):
            M.generate(VERSION, self.assets)
        (self.assets / f"secret-{TAG}-windows-amd64.exe").write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "Windows payload"):
            M.generated_metadata(VERSION, self.assets)


class PublicationTests(OfflineTest):
    def setUp(self):
        super().setUp()
        make_inputs(self.assets)
        self.expected = M.generate(VERSION, self.assets)
        for name in M.payload_names(VERSION) + [M.checksum_name(VERSION)]:
            (self.assets / f"sha256-{M.digest(self.assets / name)}.jsonl").write_bytes(b"synthetic attestation\n")
        self.calls = []
        self.details = {"tagName": TAG, "isDraft": False, "isPrerelease": False,
                        "assets": [{"name": path.name, "size": path.stat().st_size} for path in self.assets.iterdir()]}
        self.failure = None
        self.bad_subject = False
        self.published_paths = []
        self.source = patch.object(M, "verify_source", return_value=(COMMIT, (self.assets / M.checksum_name(VERSION)).read_bytes()))
        self.source_mock = self.source.start()
        self.addCleanup(self.source.stop)
        self.commands = patch.object(M, "run", side_effect=self.fake_run)
        self.commands.start()
        self.addCleanup(self.commands.stop)
        self.publisher = patch.object(M, "verified_publisher", self.fake_publisher)
        self.publisher.start()
        self.addCleanup(self.publisher.stop)
        self.sleep = patch.object(M.time, "sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    @contextmanager
    def fake_publisher(self):
        home = self.base / "private publisher home"
        home.mkdir(exist_ok=True)
        yield self.base / "mcp-publisher", {"HOME": str(home)}

    def fake_run(self, command, **kwargs):
        command = [str(item) for item in command]
        self.calls.append(command)
        if command[:3] == ["gh", "release", "view"]:
            return json_bytes(self.details)
        if command[:3] == ["gh", "release", "download"]:
            name = command[command.index("--pattern") + 1]
            destination = Path(command[command.index("--dir") + 1])
            self.assertEqual(list(destination.iterdir()), [])
            (destination / name).write_bytes((self.assets / name).read_bytes())
            return b""
        if command[:3] == ["gh", "attestation", "verify"]:
            if self.failure == "attestation":
                raise subprocess.CalledProcessError(1, command)
            path = Path(command[3])
            self.assertIn("--deny-self-hosted-runners", command)
            self.assertEqual(command[command.index("--source-digest") + 1], COMMIT)
            self.assertEqual(command[command.index("--signer-digest") + 1], COMMIT)
            self.assertEqual(command[command.index("--source-ref") + 1], "refs/tags/" + TAG)
            self.assertEqual(command[command.index("--cert-identity") + 1],
                             "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/" + TAG)
            self.assertEqual(command[command.index("--cert-oidc-issuer") + 1], "https://token.actions.githubusercontent.com")
            self.assertNotIn("--signer-workflow", command)
            self.assertEqual(Path(command[command.index("--bundle") + 1]).name,
                             "sha256-" + M.digest(path) + ".jsonl")
            return json_bytes([{"verificationResult": {"statement": {
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": "wrong" if self.bad_subject else path.name,
                             "digest": {"sha256": M.digest(path)}}]}}}])
        if Path(command[0]).name == "mcp-publisher":
            action = command[1]
            if action == self.failure:
                raise subprocess.CalledProcessError(1, command)
            self.assertTrue(Path(kwargs["env"]["HOME"]).is_relative_to(self.base))
            if action in ("validate", "publish"):
                path = Path(command[2])
                self.assertTrue(path.is_absolute())
                self.assertEqual(path.read_bytes(), (self.assets / "server.json").read_bytes())
                self.published_paths.append(path)
            elif action == "login":
                self.assertEqual(command[2:], ["github-oidc"])
            return b""
        raise AssertionError("unexpected external command: " + repr(command))

    def publish(self, records):
        with patch.object(M, "registry_record", side_effect=records) as api:
            M.registry_publish(TAG, COMMIT)
        return api

    def publisher_actions(self):
        return [command[1] for command in self.calls if Path(command[0]).name == "mcp-publisher"]

    def test_publish_all_nine_subjects_then_oidc_and_poll(self):
        self.publish([None, None, active_record(self.expected, "pending"), active_record(self.expected)])
        self.assertEqual(self.publisher_actions(), ["validate", "login", "publish"])
        verifications = [command[3] for command in self.calls if command[:3] == ["gh", "attestation", "verify"]]
        self.assertEqual(sorted(Path(path).name for path in verifications),
                         sorted(M.payload_names(VERSION) + [M.checksum_name(VERSION)]))
        self.assertEqual(len(verifications), 9)
        self.assertEqual(self.published_paths[0], self.published_paths[1])
        self.assertTrue(all(not path.exists() for path in self.published_paths))

    def test_identical_active_rerun_skips_login_and_publish(self):
        self.publish([active_record(self.expected)])
        self.assertEqual(self.publisher_actions(), ["validate"])

    def test_conflicting_or_inactive_record_fails(self):
        for key, value in (("name", "other"), ("version", "0.3.1"), ("packages", [])):
            wrong = copy.deepcopy(self.expected)
            wrong[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "mismatch"):
                self.publish([active_record(wrong)])
        with self.assertRaisesRegex(ValueError, "not active"):
            self.publish([active_record(self.expected, "deleted")])
        self.assertNotIn("publish", self.publisher_actions())

    def test_validation_oidc_and_publish_failures_stop(self):
        for action in ("validate", "login", "publish", "attestation"):
            self.calls.clear()
            self.failure = action
            with self.subTest(action=action), self.assertRaises(subprocess.CalledProcessError):
                self.publish([None])
            actions = self.publisher_actions()
            if action in ("validate", "attestation"):
                self.assertNotIn("login", actions)
            if action != "publish":
                self.assertNotIn("publish", actions)

    def test_wrong_subject_fails_before_publisher(self):
        self.bad_subject = True
        with self.assertRaisesRegex(ValueError, "subject mismatch"):
            self.publish([None])
        self.assertEqual(self.publisher_actions(), [])

    def test_poll_is_bounded_and_conflict_after_publication_fails(self):
        with self.assertRaisesRegex(ValueError, "10 checks"):
            self.publish([None] * 11)
        self.assertEqual(M.time.sleep.call_count, 9)
        wrong = active_record(self.expected)
        wrong["server"]["packages"][0]["fileSha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.publish([None, wrong])

    def test_draft_prerelease_wrong_tag_and_bad_asset_sets(self):
        original = copy.deepcopy(self.details)
        for update in ({"isDraft": True}, {"isPrerelease": True}, {"tagName": "v0.3.1"},
                       {"assets": original["assets"][:-1]},
                       {"assets": [original["assets"][0]] * 18}):
            self.details = dict(original, **update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.publish([None])
        self.assertEqual(self.publisher_actions(), [])

    def test_corrupt_public_bytes_and_wrong_committed_manifest(self):
        path = self.assets / f"secret-{TAG}-linux-amd64"
        path.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksums"):
            self.publish([None])
        self.assertEqual(self.publisher_actions(), [])
        make_inputs(self.assets)
        self.source_mock.return_value = (COMMIT, b"wrong committed checksums")
        with self.assertRaisesRegex(ValueError, "differ from C"):
            self.publish([None])

    def test_unexpected_bundle_digest_fails_before_publisher(self):
        entry = next(asset for asset in self.details["assets"] if asset["name"].endswith(".jsonl"))
        (self.assets / entry["name"]).rename(self.assets / ("sha256-" + "0" * 64 + ".jsonl"))
        entry["name"] = "sha256-" + "0" * 64 + ".jsonl"
        with self.assertRaisesRegex(ValueError, "bundle set"):
            self.publish([None])
        self.assertEqual(self.publisher_actions(), [])

    def test_public_duplicate_json_with_rehashed_manifest_still_fails(self):
        server = self.assets / "server.json"
        server.write_bytes(server.read_bytes().replace(b'"name": "io.github.avhn/secret",',
                           b'"name": "io.github.avhn/secret", "name": "io.github.avhn/secret",'))
        (self.assets / M.checksum_name(VERSION)).write_bytes(M.checksum_bytes(VERSION, self.assets))
        for path in self.assets.glob("sha256-*.jsonl"):
            path.unlink()
        for name in M.payload_names(VERSION) + [M.checksum_name(VERSION)]:
            (self.assets / f"sha256-{M.digest(self.assets / name)}.jsonl").write_bytes(b"fake\n")
        self.details["assets"] = [{"name": path.name, "size": path.stat().st_size} for path in self.assets.iterdir()]
        self.source_mock.return_value = (COMMIT, (self.assets / M.checksum_name(VERSION)).read_bytes())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.publish([None])


class TrustAndNetworkTests(OfflineTest):
    def test_source_boundary(self):
        source = "b" * 40
        responses = {("fetch", "--no-tags", "--force", "origin", f"refs/tags/{TAG}:refs/tags/{TAG}"): "",
                     ("cat-file", "-t", f"refs/tags/{TAG}"): "tag\n",
                     ("rev-parse", f"refs/tags/{TAG}^{{commit}}"): COMMIT + "\n",
                     ("rev-parse", "HEAD"): COMMIT + "\n",
                     ("rev-list", "--parents", "-n", "1", COMMIT): COMMIT + " " + source + "\n",
                     ("diff-tree", "--no-commit-id", "--name-status", "-r", source, COMMIT): "A\tdist/checksums-v0.3.0.txt\n",
                     ("ls-tree", "--name-only", source, "--", ".secret-release-test-fixture"): "",
                     ("ls-tree", "--name-only", COMMIT, "--", ".secret-release-test-fixture"): ""}
        with patch.object(M, "git", side_effect=lambda *args: responses[args]), \
                patch.object(M, "run", return_value=b"committed"):
            self.assertEqual(M.verify_source(TAG, COMMIT), (COMMIT, b"committed"))
            for tag in ("v1.0.0", "v0.3.0-rc1", "v0.3.00", "v0.3.0\n"):
                with self.subTest(tag=tag), self.assertRaises(ValueError):
                    M.verify_source(tag, COMMIT)
            with self.assertRaisesRegex(ValueError, "mismatch"):
                M.verify_source(TAG, "c" * 40)
            for key, value in ((('cat-file', '-t', f'refs/tags/{TAG}'), 'commit\n'),
                               (('diff-tree', '--no-commit-id', '--name-status', '-r', source, COMMIT), 'M\tREADME.md\n'),
                               (('ls-tree', '--name-only', source, '--', '.secret-release-test-fixture'), '.secret-release-test-fixture\n')):
                original = responses[key]
                responses[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    M.verify_source(TAG, COMMIT)
                responses[key] = original

    def test_registry_api_offline_404_errors_duplicates_and_limits(self):
        class Response(io.BytesIO):
            status = 200
        with patch.object(M, "build_opener") as opener:
            opener.return_value.open.return_value = Response(json_bytes(active_record({"name": M.NAME})))
            self.assertEqual(M.registry_record(VERSION)["server"]["name"], M.NAME)
            self.assertEqual(opener.return_value.open.call_args.args[0],
                             "https://registry.modelcontextprotocol.io/v0.1/servers/io.github.avhn%2Fsecret/versions/0.3.0")
            for data in (b'{"server":{},"server":{}}', b"x" * (M.MAX_JSON + 1)):
                opener.return_value.open.return_value = Response(data)
                with self.assertRaises(ValueError):
                    M.registry_record(VERSION)
            for status in (404, 403, 500):
                opener.return_value.open.side_effect = HTTPError("https://example.test", status, "fake", HTTPMessage(), io.BytesIO())
                if status == 404:
                    self.assertIsNone(M.registry_record(VERSION))
                else:
                    with self.assertRaises(ValueError):
                        M.registry_record(VERSION)
            opener.return_value.open.side_effect = URLError("fake")
            with self.assertRaises(ValueError):
                M.registry_record(VERSION)
        with self.assertRaises(ValueError):
            M.NoRedirects().redirect_request(None, None, 302, "", {}, "https://other.test")
        for url in ("http://github.com/asset", "https://evil.test/asset", "https://github.com:444/asset"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                M.ReviewedRedirects().redirect_request(None, None, 302, "", {}, url)

    def test_https_response_time_and_size_bounds(self):
        self.assertEqual(b"".join(M.response_chunks(io.BytesIO(b"abc"), 3, 60)), b"abc")
        with self.assertRaisesRegex(ValueError, "oversized"):
            b"".join(M.response_chunks(io.BytesIO(b"abcd"), 3, 60))
        with patch.object(M.time, "monotonic", side_effect=[0, 61]), self.assertRaisesRegex(ValueError, "timed out"):
            b"".join(M.response_chunks(io.BytesIO(b"abc"), 3, 60))

    def test_pinned_publisher_checks_hash_before_extraction_and_isolates_home(self):
        archive_data = io.BytesIO()
        with tarfile.open(fileobj=archive_data, mode="w:gz") as archive:
            for name in ("LICENSE", "README.md", "mcp-publisher"):
                data = b"synthetic " + name.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        payload = archive_data.getvalue()
        with patch.object(M, "download_publisher", side_effect=lambda path: path.write_bytes(payload)), \
                patch.object(M.platform, "system", return_value="Linux"), \
                patch.object(M.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(ValueError, "checksum"):
                with M.verified_publisher():
                    self.fail("unverified publisher was yielded")
            with patch.object(M, "PUBLISHER_SHA256", hashlib.sha256(payload).hexdigest()):
                with M.verified_publisher() as (binary, env):
                    self.assertEqual(binary.read_bytes(), b"synthetic mcp-publisher")
                    self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o700)
                    homes = [Path(env[key]) for key in ("HOME", "XDG_CONFIG_HOME", "APPDATA")]
                    self.assertEqual(len(set(homes)), 3)
                    self.assertTrue(all(path.is_dir() for path in homes))
                self.assertFalse(binary.exists())
                self.assertTrue(all(not path.exists() for path in homes))

    def test_workflow_gate_and_permission_contract(self):
        text = (ROOT / ".github/workflows/registry.yml").read_text()
        self.assertIn("types: [published]", text)
        self.assertIn("github.event.release.tag_name == 'v0.3.0'", text)
        self.assertIn("github.event.release.draft == false", text)
        self.assertIn("github.event.release.prerelease == false", text)
        self.assertIn("uses: ./.github/workflows/plugin.yml", text)
        self.assertIn("needs: [resolve, public-native-installs]", text)
        self.assertIn("environment: registry-publish", text)
        self.assertEqual(text.count("id-token: write"), 1)
        self.assertGreater(text.index("id-token: write"), text.index("  publish:"))
        self.assertNotIn("secrets:", text)
        for line in text.splitlines():
            if "uses: actions/" in line:
                self.assertRegex(line, r"@[0-9a-f]{40} #")


if __name__ == "__main__":
    unittest.main(verbosity=2)
