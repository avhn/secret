#!/usr/bin/env python3
"""Offline MCPB contracts and isolated native smoke. Run with python3 -I.

Requires npm ci --prefix packaging/mcpb --ignore-scripts and Go 1.27.3.
Synthetic Mach-O/PE fixtures test packaging, not native executable compatibility.
Only the current host's freshly built Go binary runs; no Desktop or model calls.
"""

import argparse
from contextlib import redirect_stdout
import copy
from html.parser import HTMLParser
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit
import warnings
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "package_mcpb.py"
spec = importlib.util.spec_from_file_location("secret_package_mcpb", SCRIPT)
mcpb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcpb)
VERSION = "0.3.4"


def thin(arch):
    return struct.pack("<IIIIIIII", 0xFEEDFACF, mcpb.CPU[arch],
                       3 if arch == "amd64" else 0, 2, 0, 0, 0, 0) + bytes(32)


def fat(parts, wide=False):
    offsets = [4096, 8192]
    data = bytearray(8192 + len(parts["arm64"]))
    struct.pack_into(">II", data, 0, 0xCAFEBABF if wide else 0xCAFEBABE, 2)
    for index, (arch, offset) in enumerate(zip(("amd64", "arm64"), offsets)):
        values = [mcpb.CPU[arch], 3 if arch == "amd64" else 0, offset, len(parts[arch]), 12]
        if wide:
            values.append(0)
        struct.pack_into(">IIQQII" if wide else ">IIIII", data, 8 + index * (32 if wide else 20), *values)
        data[offset:offset + len(parts[arch])] = parts[arch]
    return bytes(data)


def pe(machine=0x8664):
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    struct.pack_into("<H", data, 88, 0x20B)
    return bytes(data)


class BrandingTests(unittest.TestCase):
    def test_packaging_icons_match_reviewed_resources(self):
        for source, target in (("logo.svg", "icon.svg"), ("logo-256.png", "icon.png")):
            with self.subTest(source=source):
                self.assertEqual((ROOT / "resources" / source).read_bytes(),
                                 (mcpb.PACKAGING / target).read_bytes())
        manifest = json.loads((mcpb.PACKAGING / "manifest.template.json").read_text())
        self.assertEqual(manifest["icon"], "icon.png")

    def test_reviewed_png_dimensions(self):
        for path, size in ((mcpb.PACKAGING / "icon.png", 256),
                           (ROOT / "resources/logo-512.png", 512)):
            with self.subTest(path=path):
                data = path.read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(data[8:16], b"\x00\x00\x00\x0dIHDR")
                self.assertEqual(struct.unpack_from(">II", data, 16), (size, size))

    def test_readme_header_local_links_exist(self):
        class HeaderLinks(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []

            def handle_starttag(self, tag, attrs):
                self.links.extend(value for name, value in attrs
                                  if name in ("src", "href") and value is not None)

        header = (ROOT / "README.md").read_text(encoding="utf-8").split("\n## ", 1)[0]
        parser = HeaderLinks()
        parser.feed(header)
        self.assertTrue(parser.links)
        local = []
        for link in parser.links:
            url = urlsplit(link)
            if not url.scheme and not url.netloc and url.path:
                local.append(unquote(url.path))
        self.assertIn("resources/logo.svg", local)
        for path in local:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), f"missing README header target: {path}")

    def sync(self, *args):
        return subprocess.run([sys.executable, "-I", str(ROOT / "scripts/sync-branding.py"),
                               *map(str, args)], cwd=ROOT, capture_output=True, text=True, timeout=15)

    def test_sync_check_real_tree(self):
        result = self.sync("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS branding", result.stdout)

    def test_sync_copies_reviewed_bytes(self):
        with tempfile.TemporaryDirectory(prefix="secret-branding-") as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "resources", root / "resources")
            sources = {path.name: path.read_bytes() for path in (root / "resources").iterdir()}
            result = self.sync("--root", root)
            self.assertEqual(result.returncode, 0, result.stderr)
            for source, target in (("logo.svg", "icon.svg"), ("logo-256.png", "icon.png")):
                self.assertEqual((root / "packaging/mcpb" / target).read_bytes(), sources[source])
            self.assertEqual({path.name: path.read_bytes() for path in (root / "resources").iterdir()},
                             sources)
            self.assertEqual(self.sync("--root", root, "--check").returncode, 0)

    def test_sync_check_rejects_mismatch_and_missing_files_without_writing(self):
        for relative, problem in (("packaging/mcpb/icon.svg", "mismatch"),
                                  ("packaging/mcpb/icon.png", "mismatch"),
                                  ("packaging/mcpb/icon.svg", "missing"),
                                  ("packaging/mcpb/icon.png", "missing"),
                                  ("resources/logo.svg", "missing"),
                                  ("resources/logo-256.png", "missing")):
            with self.subTest(path=relative, problem=problem), \
                    tempfile.TemporaryDirectory(prefix="secret-branding-") as temporary:
                root = Path(temporary)
                shutil.copytree(ROOT / "resources", root / "resources")
                packaging = root / "packaging/mcpb"
                packaging.mkdir(parents=True)
                for name in ("icon.svg", "icon.png"):
                    shutil.copyfile(mcpb.PACKAGING / name, packaging / name)
                path = root / relative
                if problem == "missing":
                    path.unlink()
                else:
                    path.write_bytes(b"synthetic mismatched icon")
                before = {item.relative_to(root): item.read_bytes()
                          for item in root.rglob("*") if item.is_file()}
                result = self.sync("--root", root, "--check")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(relative, result.stderr)
                self.assertIn("missing source" if relative.startswith("resources/") else "differs from",
                              result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual({item.relative_to(root): item.read_bytes()
                                  for item in root.rglob("*") if item.is_file()}, before)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="secret-mcpb-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.parts = {arch: thin(arch) for arch in mcpb.CPU}
        for arch, data in self.parts.items():
            (self.root / arch).write_bytes(data)
        (self.root / "windows.exe").write_bytes(pe())
        (self.root / "universal").write_bytes(fat(self.parts))
        self.args = argparse.Namespace(version=VERSION, darwin_amd64=self.root / "amd64",
                                       darwin_arm64=self.root / "arm64", darwin_universal=self.root / "universal",
                                       windows_amd64=self.root / "windows.exe", out=self.root / "out")
        self.stage = self.root / "stage"
        self.stage.mkdir()
        mcpb.stage_payloads(self.args, self.stage)
        (self.stage / "manifest.json").write_bytes((json.dumps(mcpb.manifest(VERSION), indent=2) + "\n").encode())
        shutil.copyfile(ROOT / "LICENSE", self.stage / "LICENSE")
        shutil.copyfile(mcpb.PACKAGING / "icon.png", self.stage / "icon.png")

    def build(self):
        # Synthetic bytes are never executable, even on a matching native host.
        with patch.object(mcpb.platform, "system", return_value="Linux"), redirect_stdout(io.StringIO()):
            return mcpb.build(self.args)

    def test_locked_cli_and_manifest_validation(self):
        mcpb.check_cli()
        result = mcpb.cli("validate", self.stage / "manifest.json")
        self.assertIn("Manifest schema validation passes", result.stdout)

    @unittest.skipUnless(sys.platform.startswith("linux"), "synthetic desktop CLI build is Linux-only")
    def test_cli_prebuilt_universal_with_relative_paths(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--version", VERSION,
                                 "--darwin-amd64", "amd64", "--darwin-arm64", "arm64",
                                 "--darwin-universal", "universal", "--windows-amd64", "windows.exe",
                                 "--out", "output with spaces"], cwd=self.root,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        bundle = self.root / "output with spaces" / "secret-v0.3.4-desktop.mcpb"
        mcpb.inspect_zip(bundle, self.stage)

    def test_wrong_locked_cli_version_fails(self):
        package = self.root / "wrong-cli"
        package.mkdir()
        (package / "package.json").write_text('{"version":"2.1.3"}')
        with patch.object(mcpb, "CLI_PACKAGE", package):
            with self.assertRaisesRegex(ValueError, "exact locked"):
                mcpb.check_cli()

    def test_dependency_lock_and_licenses(self):
        package = json.loads((mcpb.PACKAGING / "package.json").read_text())
        lock = json.loads((mcpb.PACKAGING / "package-lock.json").read_text())
        self.assertEqual(package["devDependencies"], {"@anthropic-ai/mcpb": "2.1.2"})
        overrides = {"node-forge": "1.4.1", "tmp": "0.2.7", "zod": "3.25.76"}
        self.assertEqual(package["overrides"], overrides)
        for name, version in overrides.items():
            installed = json.loads((mcpb.PACKAGING / "node_modules" / name / "package.json").read_text())
            self.assertEqual(installed["version"], version)
            copies = [item["version"] for path, item in lock["packages"].items()
                      if path.endswith("node_modules/" + name)]
            self.assertEqual(copies, [version])
        self.assertEqual(lock["lockfileVersion"], 3)
        self.assertEqual(lock["packages"][""]["devDependencies"], package["devDependencies"])
        licenses = {"MIT", "ISC", "(BSD-3-Clause OR GPL-2.0)", "(MIT OR CC0-1.0)"}
        for name, entry in lock["packages"].items():
            if not name:
                continue
            with self.subTest(package=name):
                self.assertTrue(entry["resolved"].startswith("https://registry.npmjs.org/"))
                self.assertTrue(entry["integrity"].startswith("sha512-"))
                self.assertIn(entry["license"], licenses)
                self.assertNotIn("hasInstallScript", entry)
        self.assertEqual(lock["packages"]["node_modules/@anthropic-ai/mcpb"]["version"], mcpb.CLI_VERSION)

    def test_advisory_v4_implementation_is_not_reachable(self):
        # No registry access: the actual installed CLI validates with v4 blocked.
        mcpb.check_v3_validation()

    def test_overridden_tmp_name_api_and_type_confusion_rejection(self):
        code = r'''
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const tmp = require(process.argv[1]);
const root = process.argv[2];
const name = tmp.tmpNameSync({ tmpdir: root, prefix: "synthetic", postfix: ".txt" });
assert.equal(path.dirname(name), root);
fs.writeFileSync(name, "synthetic test only", { flag: "wx" });
fs.unlinkSync(name);
assert.throws(() => tmp.tmpNameSync({ tmpdir: root, prefix: { toString: () => "../escape" } }));
'''
        mcpb.run(["node", "-e", code, mcpb.PACKAGING / "node_modules" / "tmp", self.root], capture_output=True)

    def reviewed_audit(self):
        findings = {}
        for name in ("zod", "@anthropic-ai/mcpb", "zod-to-json-schema"):
            via = ["zod"]
            if name == "zod":
                via = [{"name": "zod", "dependency": "zod", "range": "<4.6.6",
                        "url": "https://github.com/advisories/GHSA-mrhx-c7xc-m3w5"}]
            findings[name] = {"name": name, "severity": "high", "via": via,
                              "nodes": ["node_modules/" + name]}
        return {"auditReportVersion": 2, "vulnerabilities": findings,
                "metadata": {"vulnerabilities": {"total": 3}}}

    def test_offline_audit_policy_accepts_only_documented_exception(self):
        report = self.reviewed_audit()
        self.assertEqual(mcpb.check_dependency_audit(report), sorted(report["vulnerabilities"]))
        clean = {"auditReportVersion": 2, "vulnerabilities": {},
                 "metadata": {"vulnerabilities": {"total": 0}}}
        self.assertEqual(mcpb.check_dependency_audit(clean), [])
        path = self.root / "synthetic-audit.json"
        path.write_text(json.dumps(report))
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--version", VERSION,
                                 "--audit-report", str(path)], cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        for name in report["vulnerabilities"]:
            self.assertIn(name.encode(), result.stdout)

    def test_offline_audit_policy_rejects_new_findings_and_invalid_reports(self):
        variants = [None, {}, {"error": {"code": "ENOTFOUND"}},
                    {**self.reviewed_audit(), "metadata": None}]
        report = self.reviewed_audit()
        report["vulnerabilities"]["tmp"] = {"name": "tmp"}
        report["metadata"]["vulnerabilities"]["total"] = 4
        variants.append(report)
        for field, value in (("url", "https://github.com/advisories/GHSA-new-finding"),
                             ("range", "<5"), ("dependency", "other")):
            report = self.reviewed_audit()
            report["vulnerabilities"]["zod"]["via"][0][field] = value
            variants.append(report)
        for name, field, value in (("@anthropic-ai/mcpb", "via", ["tmp", "zod"]),
                                   ("zod", "severity", "critical"), ("zod", "nodes", ["nested/zod"]),
                                   ("zod", "via", []), ("zod", "via", "zod")):
            report = self.reviewed_audit()
            report["vulnerabilities"][name][field] = value
            variants.append(report)
        for report in variants:
            with self.subTest(report=report), self.assertRaises(ValueError):
                mcpb.check_dependency_audit(report)

    def test_oversized_manifest_is_rejected_before_cli_validation(self):
        package = self.root / "oversized-manifest"
        package.mkdir()
        (package / "manifest.template.json").write_bytes(b" " * ((64 << 10) + 1))
        with patch.object(mcpb, "PACKAGING", package):
            with self.assertRaisesRegex(ValueError, "oversized"):
                mcpb.manifest(VERSION)

    def test_manifest_exact_configuration_and_privacy(self):
        manifest = mcpb.manifest(VERSION)
        self.assertEqual(manifest["manifest_version"], "0.3")
        self.assertEqual(manifest["name"], "secret")
        self.assertTrue(manifest["display_name"])
        self.assertEqual(manifest["license"], "GPL-3.0-or-later")
        self.assertEqual(manifest["author"]["name"], "Mert Dede")
        for field in ("repository", "homepage", "support"):
            self.assertIn("https://github.com/avhn/secret", str(manifest[field]))
        setting = manifest["user_config"]["store_reference"]
        self.assertEqual(setting["type"], "string")
        self.assertIs(setting["required"], True)
        self.assertNotIn("default", setting)
        self.assertIn("exact", setting["title"].lower())
        self.assertIn("file:/absolute/path", setting["description"])
        self.assertIn("libsecret:name", setting["description"])
        self.assertEqual(manifest["compatibility"], {"platforms": ["darwin", "win32"]})
        config = manifest["server"]["mcp_config"]
        self.assertEqual(config["args"], ["mcp", "--store", "${user_config.store_reference}"])
        self.assertNotIn("env", config)
        self.assertEqual(config["command"], "${__dirname}/server/secret-go")
        self.assertEqual(config["platform_overrides"], {"win32": {"command": "${__dirname}/server/secret-go.exe"}})
        self.assertEqual([tool["name"] for tool in manifest["tools"]], ["list", "show", "diff", "health"])
        privacy = manifest["long_description"].lower()
        for text in ("key names", "labels", "presence", "paths", "account ids", "model", "hashes",
                     "lengths", "opens local file bytes", "unauthenticated", "not evidenced", "hook"):
            self.assertIn(text, privacy)

    def test_interpolation_remains_exactly_one_literal_argument(self):
        args = mcpb.manifest(VERSION)["server"]["mcp_config"]["args"]
        for reference in ('file:/a path/quote\'"/$HOME.secret', r'file:C:\a path\quote".secret',
                          "libsecret:human-approved", "file:/a,libsecret:b", "$(not-a-command)"):
            actual = [arg.replace("${user_config.store_reference}", reference) for arg in args]
            self.assertEqual(actual, ["mcp", "--store", reference])
            self.assertEqual(len(actual), 3)

    def test_manifest_rejects_scope_widening_or_command_changes(self):
        original = json.loads((mcpb.PACKAGING / "manifest.template.json").read_text())
        variants = []
        for name, value in (("default", "file:/ambient"), ("required", False), ("type", "directory")):
            changed = copy.deepcopy(original)
            changed["user_config"]["store_reference"][name] = value
            variants.append(changed)
        for config in ({"command": "sh", "args": ["-c", "secret-go mcp"]},
                       {**original["server"]["mcp_config"], "env": {"TOKEN": "value"}},
                       {**original["server"]["mcp_config"], "args": ["mcp"]}):
            changed = copy.deepcopy(original)
            changed["server"]["mcp_config"] = config
            variants.append(changed)
        for changed in variants:
            with self.subTest(variant=changed["server"]), patch.object(mcpb, "regular_bytes", return_value=json.dumps(changed).encode()):
                with self.assertRaises(ValueError):
                    mcpb.manifest(VERSION)

    def test_two_builds_byte_identical_in_independent_paths(self):
        first = self.build()
        second_root = self.root / "other absolute path"
        second_root.mkdir()
        self.args.out = second_root / "out"
        for name in ("darwin_amd64", "darwin_arm64", "darwin_universal", "windows_amd64"):
            original = getattr(self.args, name)
            copied = second_root / original.name
            shutil.copyfile(original, copied)
            os.utime(copied, (1700000000, 1700000000))
            copied.chmod(0o600)
            setattr(self.args, name, copied)
        second = self.build()
        self.assertEqual(first.name, "secret-v0.3.4-desktop.mcpb")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        mcpb.inspect_zip(first, self.stage)
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(archive.namelist(), sorted(mcpb.APPROVED))
            for entry in archive.infolist():
                self.assertEqual(entry.date_time, mcpb.ZIP_TIME)
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(entry.external_attr >> 16, mcpb.zip_mode(entry.filename))
                self.assertFalse(entry.extra)
            self.assertEqual(archive.read("server/secret-go"), fat(self.parts))
            self.assertEqual(archive.read("server/secret-go.exe"), pe())

    def test_unpack_exact_bytes_and_modes(self):
        bundle = self.root / "test.mcpb"
        mcpb.write_zip(bundle, self.stage)
        destination = self.root / "extracted"
        destination.mkdir()
        mcpb.unpack(bundle, destination, self.stage)
        actual = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}
        self.assertEqual(actual, mcpb.APPROVED)
        for name in actual:
            self.assertEqual((destination / name).read_bytes(), (self.stage / name).read_bytes())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), stat.S_IMODE(mcpb.zip_mode(name)))
        with self.assertRaises(FileExistsError):
            mcpb.unpack(bundle, destination, self.stage)

    def test_existing_bundle_is_never_overwritten(self):
        output = self.build()
        content = output.read_bytes()
        with self.assertRaisesRegex(ValueError, "replace"):
            self.build()
        self.assertEqual(output.read_bytes(), content)

    def test_invalid_versions(self):
        for version in ("v0.3.4", "0.03.0", "0.3", "0.3.4-rc1", "1.2.3\n", "../../bad", ""):
            with self.subTest(version=version), self.assertRaises(ValueError):
                mcpb.release_version(version)

    def test_invalid_payloads(self):
        for name, data in (("darwin_amd64", thin("arm64")), ("windows_amd64", pe(0xAA64)),
                           ("windows_amd64", b"not executable"), ("darwin_amd64", b""),
                           ("darwin_universal", thin("amd64"))):
            with self.subTest(name=name, data=data[:8]):
                bad = self.root / "bad"
                bad.write_bytes(data)
                changed = copy.copy(self.args)
                setattr(changed, name, bad)
                stage = self.root / "bad-stage"
                stage.mkdir(exist_ok=True)
                with self.assertRaises(ValueError):
                    mcpb.stage_payloads(changed, stage)
                shutil.rmtree(stage)

    @unittest.skipIf(os.name == "nt", "Windows symlink creation needs extra privilege")
    def test_symlink_inputs_and_output_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.args.windows_amd64)
        with self.assertRaises(ValueError):
            mcpb.regular_bytes(link)
        self.args.out.mkdir()
        output = self.args.out / "secret-v0.3.4-desktop.mcpb"
        output.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(ValueError, "replace"):
            self.build()

    def test_oversized_input(self):
        path = self.root / "oversized"
        with path.open("wb") as output:
            output.truncate(mcpb.MAX_PAYLOAD + 1)
        with self.assertRaisesRegex(ValueError, "oversized"):
            mcpb.regular_bytes(path)

    def test_no_lipo_has_clear_prebuilt_requirement(self):
        self.args.darwin_universal = None
        stage = self.root / "no-lipo"
        stage.mkdir()
        with patch.object(mcpb.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "--darwin-universal"):
                mcpb.stage_payloads(self.args, stage)

    def test_lipo_assembly_and_exact_slice_validation(self):
        self.args.darwin_universal = None
        stage = self.root / "lipo"
        stage.mkdir()

        def lipo(command, **kwargs):
            self.assertEqual(command[:2], ["lipo", "-create"])
            Path(command[-1]).write_bytes(fat(self.parts))

        with patch.object(mcpb.shutil, "which", return_value="/synthetic/lipo"), patch.object(mcpb, "run", side_effect=lipo):
            mcpb.stage_payloads(self.args, stage)
        self.assertEqual((stage / "server/secret-go").read_bytes(), fat(self.parts))
        changed = bytearray(fat(self.parts))
        changed[-1] ^= 1
        self.args.darwin_universal = self.root / "modified-universal"
        self.args.darwin_universal.write_bytes(changed)
        stage = self.root / "wrong-slice"
        stage.mkdir()
        with self.assertRaisesRegex(ValueError, "differ"):
            mcpb.stage_payloads(self.args, stage)

    def test_universal_fat32_fat64_and_malformed_headers(self):
        for wide in (False, True):
            self.assertEqual(mcpb.universal_slices(fat(self.parts, wide)), self.parts)
        for offset, fmt, value in ((4, ">I", 3), (28, ">I", mcpb.CPU["amd64"]),
                                   (16, ">I", 0), (20, ">I", 1 << 30), (24, ">I", 31),
                                   (40, ">I", 4096)):
            data = bytearray(fat(self.parts))
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                mcpb.universal_slices(data)

    def archive(self, change=None, extra=None, reverse=False):
        bundle = self.root / "bad.mcpb"
        if bundle.exists():
            bundle.unlink()
        names = sorted(mcpb.APPROVED, reverse=reverse)
        with warnings.catch_warnings(), zipfile.ZipFile(bundle, "x") as archive:
            warnings.simplefilter("ignore", UserWarning)
            for name in names:
                entry = zipfile.ZipInfo(name, mcpb.ZIP_TIME)
                entry.create_system = 3
                entry.external_attr = mcpb.zip_mode(name) << 16
                data = (self.stage / name).read_bytes()
                if change:
                    entry, data = change(entry, data)
                archive.writestr(entry, data)
            if extra:
                entry = zipfile.ZipInfo(extra, mcpb.ZIP_TIME)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(entry, b"unapproved")
        return bundle

    def test_zip_traversal_duplicates_and_unapproved_entries(self):
        for name in ("../outside", "/absolute", "server/../../outside", r"server\secret-go",
                     "C:/outside", "./manifest.json", "server//other", "unexpected", "manifest.json"):
            bundle = self.archive(extra=name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                mcpb.inspect_zip(bundle, self.stage)
        self.assertFalse((self.root / "outside").exists())

    def test_zip_symlinks_modes_timestamps_compression_and_order(self):
        for field, value in (("external_attr", (stat.S_IFLNK | 0o777) << 16),
                             ("external_attr", (stat.S_IFREG | 0o777) << 16),
                             ("create_system", 0), ("date_time", (2020, 1, 1, 0, 0, 0)),
                             ("extra", b"\x01\x00\x00\x00"), ("comment", b"unexpected"),
                             ("compress_type", zipfile.ZIP_DEFLATED)):
            def change(entry, data):
                setattr(entry, field, value)
                return entry, data
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                mcpb.inspect_zip(self.archive(change=change), self.stage)
        with self.assertRaises(ValueError):
            mcpb.inspect_zip(self.archive(reverse=True), self.stage)

    def test_zip_missing_changed_or_duplicate_json_content(self):
        def changed(entry, data):
            return entry, data + b"x" if entry.filename == "LICENSE" else data
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            mcpb.inspect_zip(self.archive(change=changed), self.stage)

        def duplicate(entry, data):
            if entry.filename == "manifest.json":
                data = b'{"name":"secret",' + data[1:]
            return entry, data
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            mcpb.inspect_zip(self.archive(change=duplicate))
        bundle = self.root / "missing.mcpb"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("manifest.json", b"{}")
        with self.assertRaises(ValueError):
            mcpb.inspect_zip(bundle)

    def test_cli_missing_inputs_and_conflicting_modes(self):
        for arguments in (("--version", VERSION), ("--version", "v0.3.4"),
                          ("--version", VERSION, "--smoke-binary", "absent", "--out", str(self.root))):
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), *arguments], cwd=ROOT,
                                    capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"Traceback", result.stderr)


class NativeSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("go") is None:
            raise unittest.SkipTest("Go unavailable; native smoke did not run")
        cls.temporary = tempfile.TemporaryDirectory(prefix="secret-mcpb-native-")
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name).resolve()
        cls.binary = root / ("secret-go.exe" if os.name == "nt" else "secret-go")
        home = root / "home"
        home.mkdir(mode=0o700)
        env = os.environ.copy()
        env.update({"HOME": str(home), "USERPROFILE": str(home), "GOCACHE": str(root / "go-cache"),
                    "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOENV": "off", "GOWORK": "off",
                    "GOFLAGS": "", "GOEXPERIMENT": ""})
        result = subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid= -s -w -X main.version=0.3.4",
                                 "-o", str(cls.binary), "./cmd/secret"], env=env, cwd=ROOT,
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError("native Go build failed:\n" + result.stdout + result.stderr)

    def test_smoke_native_binary_with_synthetic_store(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--version", VERSION,
                                 "--smoke-binary", str(self.binary)], cwd=ROOT,
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"PASS native payload", result.stdout)
        self.assertNotIn(b"mcpb-synthetic-value-not-for-metadata", result.stdout + result.stderr)

    def test_smoke_wrong_binary_version_fails(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--version", "0.3.5",
                                 "--smoke-binary", str(self.binary)], cwd=ROOT,
                                capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"version differs", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
