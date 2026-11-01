#!/usr/bin/env python3
"""Deterministic, names-only Desktop bundle builder. Run with python3 -I.

Release tooling pins: Python 3.14.8, Node 26.10.0, npm 11.19.1, MCPB 2.1.2.
Install only with npm ci --prefix packaging/mcpb --ignore-scripts.
The lock's build-only packages use MIT, ISC, BSD-3-Clause (node-forge's
alternative) and MIT (type-fest's alternative) licenses. None ships in MCPB.
Exact overrides fix node-forge (1.4.1) and tmp (0.2.7, including the additional
GHSA-7c78-jf6q-g5cm found in 0.2.6). tmp is outside external-editor's ^0.0.33
range; its tmpNameSync API remains compatible and the locked CLI is validated.

Zod is pinned to 3.25.76, within MCPB's ^3.25.67 and zod-to-json-schema's
^3.25.28 || ^4 range. GHSA-mrhx-c7xc-m3w5 names v4's $ZodArray/handleArrayResult;
upstream PRs 6475 and 6652 change v4 only. The published patched version 4.6.6
is outside both declared ranges. The CLI imports v3, not the shipped v4 subpath.
Only reviewed, size-bounded local manifests are passed to its validator, never
third-party manifests. The offline reachability check blocks all v4 loads while
running real CLI validation; this is not a general safety claim for Zod v3.

CI must obtain fresh advisory data online (audit is not deterministic offline):
  npm audit --prefix packaging/mcpb --ignore-scripts --json > AUDIT_JSON
Preserve that command's exit status: 0 or 1 may proceed to the check; any other
status fails. Then run this script with --version V --audit-report AUDIT_JSON.
The check accepts only the exact documented Zod advisory and its MCPB and
zod-to-json-schema ancestors, prints every exception, and reruns v3 reachability.
Any other finding or failed/invalid audit report fails. Do not use --omit=dev,
--audit-level or an unconditional success fallback to hide packaging findings.

--version V --darwin-amd64 P --darwin-arm64 P --windows-amd64 P --out DIR
writes DIR/secret-vV-desktop.mcpb, exclusively. Native lipo creates the Mac
universal payload. Without lipo, --darwin-universal P is required; its slices
must equal the supplied thin inputs. No downloads, builds, signing or publishing.

--version V --smoke-binary P tests an already extracted native payload using
its documented stash command in a disposable HOME, then MCP stdio. It does not
prove Claude Desktop installation, user_config interpolation or restart behavior.
Archives contain only manifest.json, LICENSE, icon.png and the two executables.
Stored ZIP entries, sorted names, 1980 timestamps, fixed Unix modes and empty
extra fields make packaging independent of cwd, wall clock and compression tools.
"""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging" / "mcpb"
CLI_PACKAGE = PACKAGING / "node_modules" / "@anthropic-ai" / "mcpb"
CLI_VERSION = "2.1.2"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_PAYLOAD = 256 << 20
CPU = {"amd64": 0x01000007, "arm64": 0x0100000C}
APPROVED = {"LICENSE", "icon.png", "manifest.json", "server/secret", "server/secret.exe"}


def run(args, **kwargs):
    """Tools never run with downloaded, extracted or staging content as cwd."""
    return subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True,
                          timeout=60, **kwargs)


def json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def load_json(data):
    return json.loads(data, object_pairs_hook=json_object)


def release_version(value):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("version must be stable semver without a leading v")
    return value


def regular_bytes(path, limit=MAX_PAYLOAD):
    if path is None or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("input must be a regular file, not a symlink")
    size = path.stat().st_size
    if size == 0 or size > limit:
        raise ValueError("input is empty or oversized")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) != size:
        raise ValueError("input changed while reading")
    return data


def check_thin(data, arch):
    if (len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe"
            or struct.unpack_from("<I", data, 4)[0] != CPU[arch]
            or struct.unpack_from("<I", data, 12)[0] != 2):
        raise ValueError("Darwin input must be the requested 64-bit Mach-O executable")


def universal_slices(data):
    """Inspect FAT32/FAT64 headers and embedded Mach-O CPU types, without tools."""
    if len(data) < 8 or data[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        raise ValueError("macOS payload must be a universal Mach-O binary")
    wide = data[:4] == b"\xca\xfe\xba\xbf"
    width = 32 if wide else 20
    if struct.unpack_from(">I", data, 4)[0] != 2 or len(data) < 8 + 2 * width:
        raise ValueError("universal payload must have exactly amd64 and arm64 slices")
    slices, regions = {}, []
    for index in range(2):
        fields = struct.unpack_from(">IIQQII" if wide else ">IIIII", data, 8 + index * width)
        cpu, subtype, offset, size, align = fields[:5]
        arch = next((name for name, value in CPU.items() if cpu == value), None)
        if (arch is None or arch in slices or align > 30 or offset % (1 << align)
                or offset < 8 + 2 * width or size < 32 or offset + size > len(data)
                or (wide and fields[5] != 0)):
            raise ValueError("invalid, duplicate or out-of-bounds universal slice")
        part = data[offset:offset + size]
        check_thin(part, arch)
        if struct.unpack_from("<I", part, 8)[0] != subtype:
            raise ValueError("universal slice subtype differs from embedded header")
        slices[arch] = part
        regions.append((offset, offset + size))
    regions.sort()
    if regions[0][1] > regions[1][0]:
        raise ValueError("overlapping universal slices")
    return slices


def check_windows(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Windows input must be an amd64 PE executable")
    offset = struct.unpack_from("<I", data, 60)[0]
    if (offset < 64 or offset + 26 > len(data) or data[offset:offset + 6] != b"PE\0\0\x64\x86"
            or struct.unpack_from("<H", data, offset + 24)[0] != 0x20B):
        raise ValueError("Windows input must be an amd64 PE32+ executable")


def manifest(version):
    value = load_json(regular_bytes(PACKAGING / "manifest.template.json", 64 << 10))
    value["version"] = release_version(version)
    value["documentation"] = f"https://github.com/avhn/secret/blob/v{version}/docs/setup.md"
    config = value["user_config"]
    setting = config["store_reference"]
    mcp = value["server"]["mcp_config"]
    if (set(config) != {"store_reference"} or setting["type"] != "string"
            or setting.get("required") is not True or "default" in setting
            or mcp != {"command": "${__dirname}/server/secret",
                       "args": ["mcp", "--store", "${user_config.store_reference}"],
                       "platform_overrides": {"win32": {"command": "${__dirname}/server/secret.exe"}}}
            or value["compatibility"] != {"platforms": ["darwin", "win32"]}
            or value["manifest_version"] != "0.3" or value["name"] != "secret"
            or value["server"]["type"] != "binary" or value["server"]["entry_point"] != "server/secret"
            or [tool["name"] for tool in value["tools"]] != ["list", "show", "diff", "health"]):
        raise ValueError("manifest violates the exact names-only configuration contract")
    return value


def cli(*args):
    return run(["node", CLI_PACKAGE / "dist" / "cli" / "cli.js", *args],
               capture_output=True, text=True)


def check_cli():
    if not (CLI_PACKAGE / "package.json").is_file():
        raise ValueError("missing locked MCPB CLI; run npm ci --prefix packaging/mcpb --ignore-scripts")
    package = load_json(regular_bytes(CLI_PACKAGE / "package.json", 64 << 10))
    if package["version"] != CLI_VERSION or cli("--version").stdout.strip() != CLI_VERSION:
        raise ValueError("MCPB CLI must match the exact locked 2.1.2 version")


def check_v3_validation():
    """Prove the actual CLI validator cannot load the advisory's v4 implementation."""
    for name, version in (("node-forge", "1.4.1"), ("tmp", "0.2.7"), ("zod", "3.25.76")):
        package = load_json(regular_bytes(PACKAGING / "node_modules" / name / "package.json", 64 << 10))
        if package["version"] != version:
            raise ValueError("installed packaging dependency differs from the reviewed override")
    regular_bytes(PACKAGING / "manifest.template.json", 64 << 10)
    code = r'''
import { registerHooks } from "node:module";
import { pathToFileURL } from "node:url";
let loadedV3 = false;
registerHooks({
  load(url, context, nextLoad) {
    if (url.includes("/node_modules/zod/v4")) {
      throw new Error("unreviewed Zod v4 reachability");
    }
    if (url.includes("/node_modules/zod/v3/") && !loadedV3) {
      loadedV3 = true;
      console.log("PASS reviewed Zod v3 loaded; v4 blocked");
    }
    return nextLoad(url, context);
  }
});
process.on("exit", () => { if (!loadedV3) process.exitCode = 1; });
const [cli, manifest] = process.argv.slice(1);
// Commander detects eval mode and consumes arguments from argv[1].
process.argv = [process.execPath, "validate", manifest];
await import(pathToFileURL(cli).href);
'''
    result = run(["node", "--input-type=module", "-e", code,
                  CLI_PACKAGE / "dist" / "cli" / "cli.js", PACKAGING / "manifest.template.json"],
                 capture_output=True, text=True)
    if ("PASS reviewed Zod v3 loaded; v4 blocked" not in result.stdout
            or "Manifest schema validation passes!" not in result.stdout):
        raise ValueError("could not prove v3-only CLI manifest validation")


def check_dependency_audit(report):
    """Offline, fail-on-new-findings policy for an online npm audit JSON report."""
    if not isinstance(report, dict) or report.get("error") or report.get("auditReportVersion") != 2:
        raise ValueError("audit did not produce a successful version-2 report")
    findings = report.get("vulnerabilities")
    allowed = {"zod", "@anthropic-ai/mcpb", "zod-to-json-schema"}
    if not isinstance(findings, dict) or set(findings) - allowed:
        raise ValueError("audit contains an unreviewed dependency finding")
    metadata = report.get("metadata")
    counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    if not isinstance(counts, dict) or counts.get("total") != len(findings):
        raise ValueError("audit finding count differs from report metadata")
    for name, finding in findings.items():
        if (not isinstance(finding, dict) or finding.get("name") != name or finding.get("severity") != "high"
                or finding.get("nodes") != ["node_modules/" + name]):
            raise ValueError("audit finding differs from the reviewed dependency instance")
        via = finding.get("via")
        if name == "zod":
            if not isinstance(via, list) or len(via) != 1 or not isinstance(via[0], dict):
                raise ValueError("audit contains an unreviewed Zod advisory")
            advisory = via[0]
            if (advisory.get("url") != "https://github.com/advisories/GHSA-mrhx-c7xc-m3w5"
                    or advisory.get("name") != "zod" or advisory.get("dependency") != "zod"
                    or advisory.get("range") != "<4.6.6"):
                raise ValueError("audit contains an unreviewed Zod advisory")
        elif via != ["zod"] or "zod" not in findings:
            raise ValueError("audit contains an unreviewed ancestor advisory")
    return sorted(findings)


def stage_payloads(args, stage):
    windows = regular_bytes(args.windows_amd64)
    check_windows(windows)
    thin = {arch: regular_bytes(getattr(args, "darwin_" + arch)) for arch in CPU}
    for arch, data in thin.items():
        check_thin(data, arch)
    server = stage / "server"
    server.mkdir(mode=0o700)
    binary = server / "secret"
    if args.darwin_universal is not None:
        universal = regular_bytes(args.darwin_universal)
    else:
        if shutil.which("lipo") is None:
            raise ValueError("macOS lipo is required; on Linux supply --darwin-universal with both exact slices")
        run(["lipo", "-create", args.darwin_amd64, args.darwin_arm64, "-output", binary],
            capture_output=True)
        universal = regular_bytes(binary)
    if universal_slices(universal) != thin:
        raise ValueError("universal slices differ from the approved Darwin inputs")
    binary.write_bytes(universal)
    (server / "secret.exe").write_bytes(windows)
    for path in server.iterdir():
        path.chmod(0o755)


def zip_mode(name):
    return stat.S_IFREG | (0o755 if name.startswith("server/") else 0o644)


def write_zip(bundle, stage):
    with zipfile.ZipFile(bundle, "x", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(APPROVED):
            entry = zipfile.ZipInfo(name, ZIP_TIME)
            entry.create_system = 3
            entry.external_attr = zip_mode(name) << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, regular_bytes(stage / name))


def inspect_zip(bundle, stage=None):
    """Reject unsafe archives before extraction; compare approved staging bytes."""
    with zipfile.ZipFile(bundle) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(set(names)) != len(names):
            raise ValueError("duplicate ZIP entry")
        for entry in entries:
            name, mode = entry.filename, entry.external_attr >> 16
            path = PurePosixPath(name)
            if (path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name
                    or str(path) != name or name not in APPROVED or entry.is_dir()):
                raise ValueError("unsafe or unapproved ZIP entry")
            if (entry.create_system != 3 or mode != zip_mode(name) or entry.flag_bits != 0
                    or entry.compress_type != zipfile.ZIP_STORED or entry.date_time != ZIP_TIME
                    or entry.extra or entry.comment or entry.file_size < 1
                    or entry.file_size > MAX_PAYLOAD or entry.compress_size != entry.file_size):
                raise ValueError("noncanonical ZIP entry attributes or size")
        if set(names) != APPROVED or names != sorted(names) or archive.comment:
            raise ValueError("ZIP must contain exactly the sorted approved files")
        for entry in entries:
            data = archive.read(entry)
            if stage is not None and data != regular_bytes(stage / entry.filename):
                raise ValueError("ZIP bytes differ from approved staging bytes")
        universal_slices(archive.read("server/secret"))
        check_windows(archive.read("server/secret.exe"))
        embedded = load_json(archive.read("manifest.json"))
        if embedded != manifest(embedded["version"]):
            raise ValueError("ZIP manifest differs from reviewed template")


def unpack(bundle, destination, stage):
    inspect_zip(bundle, stage)
    # No extractall: only approved regular files are created, each exclusively.
    (destination / "server").mkdir(mode=0o700)
    with zipfile.ZipFile(bundle) as archive:
        for name in sorted(APPROVED):
            path = destination / name
            with path.open("xb") as output:
                output.write(archive.read(name))
            path.chmod(stat.S_IMODE(zip_mode(name)))
            if regular_bytes(path) != regular_bytes(stage / name):
                raise ValueError("unpacked bytes differ from approved staging bytes")
            if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != stat.S_IMODE(zip_mode(name)):
                raise ValueError("unpacked mode differs")


def windows_stash(binary, reference, env, value):
    """Use ConPTY for documented Windows stash, which correctly rejects pipes."""
    import ctypes
    from ctypes import wintypes as w
    import threading

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = w.HANDLE
    size_t = ctypes.c_size_t

    class Coord(ctypes.Structure):
        _fields_ = [("X", w.SHORT), ("Y", w.SHORT)]

    class Startup(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR),
                   ("title", w.LPWSTR), ("x", w.DWORD), ("y", w.DWORD),
                   ("xsize", w.DWORD), ("ysize", w.DWORD), ("xchars", w.DWORD),
                   ("ychars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                   ("show", w.WORD), ("reservedsize", w.WORD), ("reserved2", ctypes.c_void_p),
                   ("stdin", handle), ("stdout", handle), ("stderr", handle)]

    class StartupEx(ctypes.Structure):
        _fields_ = [("startup", Startup), ("attributes", ctypes.c_void_p)]

    class Process(ctypes.Structure):
        _fields_ = [("process", handle), ("thread", handle), ("pid", w.DWORD), ("tid", w.DWORD)]

    signatures = {
        "CreatePipe": ([ctypes.POINTER(handle), ctypes.POINTER(handle), ctypes.c_void_p, w.DWORD], w.BOOL),
        "CreatePseudoConsole": ([Coord, handle, handle, w.DWORD, ctypes.POINTER(handle)], ctypes.c_long),
        "ClosePseudoConsole": ([handle], None),
        "CloseHandle": ([handle], w.BOOL),
        "InitializeProcThreadAttributeList": ([ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(size_t)], w.BOOL),
        "UpdateProcThreadAttribute": ([ctypes.c_void_p, w.DWORD, size_t, ctypes.c_void_p, size_t, ctypes.c_void_p, ctypes.c_void_p], w.BOOL),
        "DeleteProcThreadAttributeList": ([ctypes.c_void_p], None),
        "CreateProcessW": ([w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD,
                            ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(Process)], w.BOOL),
        "ReadFile": ([handle, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p], w.BOOL),
        "WriteFile": ([handle, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p], w.BOOL),
        "WaitForSingleObject": ([handle, w.DWORD], w.DWORD),
        "GetExitCodeProcess": ([handle, ctypes.POINTER(w.DWORD)], w.BOOL),
        "TerminateProcess": ([handle, w.UINT], w.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result

    def require(ok):
        if not ok:
            raise ValueError("Windows synthetic stash console operation failed")

    handles, console, attributes, process = [], handle(), None, Process()
    attributes_ready, reader_thread = False, None
    prompt = threading.Event()
    try:
        incoming, writer, reader, outgoing = handle(), handle(), handle(), handle()
        require(kernel.CreatePipe(ctypes.byref(incoming), ctypes.byref(writer), None, 0))
        handles.extend([incoming, writer])
        require(kernel.CreatePipe(ctypes.byref(reader), ctypes.byref(outgoing), None, 0))
        handles.extend([reader, outgoing])
        require(kernel.CreatePseudoConsole(Coord(120, 30), incoming, outgoing, 0, ctypes.byref(console)) == 0)
        for item in (incoming, outgoing):
            kernel.CloseHandle(item)
            handles.remove(item)
        length = size_t()
        kernel.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(length))
        attributes = ctypes.create_string_buffer(length.value)
        require(kernel.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(length)))
        attributes_ready = True
        require(kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020016, console,
                                                ctypes.sizeof(console), None, None))
        startup = StartupEx()
        startup.startup.cb = ctypes.sizeof(startup)
        startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(binary), "stash", reference, "MCPB_SYNTHETIC"]))
        environment = ctypes.create_unicode_buffer("\0".join(f"{key}={env[key]}" for key in sorted(env)) + "\0\0")
        require(kernel.CreateProcessW(str(binary), command, None, None, False, 0x00080000 | 0x00000400,
                                      environment, str(ROOT), ctypes.byref(startup), ctypes.byref(process)))
        handles.extend([process.process, process.thread])

        def drain():
            pending = b""
            buffer, count = ctypes.create_string_buffer(4096), w.DWORD()
            while kernel.ReadFile(reader, buffer, len(buffer), ctypes.byref(count), None) and count.value:
                pending = (pending + buffer.raw[:count.value])[-8192:]
                if b"MCPB_SYNTHETIC: " in pending:
                    prompt.set()

        reader_thread = threading.Thread(target=drain, daemon=True)
        reader_thread.start()
        require(prompt.wait(15))
        written = w.DWORD()
        payload = value + b"\r"
        require(kernel.WriteFile(writer, payload, len(payload), ctypes.byref(written), None))
        require(written.value == len(payload))
        require(kernel.WaitForSingleObject(process.process, 15000) == 0)
        code = w.DWORD()
        require(kernel.GetExitCodeProcess(process.process, ctypes.byref(code)))
        require(code.value == 0)
    finally:
        if process.process and kernel.WaitForSingleObject(process.process, 0) != 0:
            kernel.TerminateProcess(process.process, 1)
            kernel.WaitForSingleObject(process.process, 5000)
        if attributes_ready:
            kernel.DeleteProcThreadAttributeList(attributes)
        if console:
            kernel.ClosePseudoConsole(console)
        if reader_thread is not None:
            reader_thread.join(timeout=5)
        for item in reversed(handles):
            kernel.CloseHandle(item)


def smoke(binary, version):
    regular_bytes(binary)
    with tempfile.TemporaryDirectory(prefix="secret-mcpb-smoke-") as temporary:
        home = Path(temporary).resolve()
        stores = home / "stores"
        stores.mkdir(mode=0o700)
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
        env.update({"HOME": str(home), "USERPROFILE": str(home), "SECRETS_DIR": str(stores),
                    "SECRETS_ENV": str(home / "unused"), "XDG_CONFIG_HOME": str(home / "config"),
                    "XDG_DATA_HOME": str(home / "data"), "XDG_CACHE_HOME": str(home / "cache"),
                    "APPDATA": str(home / "config"), "LOCALAPPDATA": str(home / "local"),
                    "TMP": str(home), "TEMP": str(home), "TMPDIR": str(home), "LC_ALL": "C"})
        if run([binary, "version"], env=env, capture_output=True, text=True).stdout.strip() != f"secret {version} (go)":
            raise ValueError("native payload version differs from bundle version")
        reference = "file:" + str(stores / "synthetic store.secret")
        value = b"mcpb-synthetic-value-not-for-metadata"
        if os.name == "nt":
            windows_stash(binary, reference, env, value)
        else:
            run([binary, "stash", reference, "MCPB_SYNTHETIC"], env=env, input=value, capture_output=True)
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "synthetic-mcpb-test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "health", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "show", "arguments": {"reference": reference}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "show", "arguments": {"reference": "file:" + str(home / "outside")}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "get", "arguments": {}}},
        ]
        frames = b"".join(json.dumps(item).encode() + b"\n" for item in messages)
        result = run([binary, "mcp", "--store", reference], env=env, input=frames, capture_output=True)
        if value in result.stdout or value in result.stderr or len(result.stdout) > 1 << 20:
            raise ValueError("synthetic MCP output violated the names-only boundary")
        replies = [load_json(line) for line in result.stdout.splitlines()]
        if ([reply.get("id") for reply in replies] != [1, 2, 3, 4, 5, 6]
                or any(reply.get("jsonrpc") != "2.0" for reply in replies)
                or any("error" in reply for reply in replies[:4])
                or any("error" not in reply for reply in replies[4:])):
            raise ValueError("unexpected MCP smoke responses or allowlist behavior")
        initialized = replies[0]["result"]
        if (initialized["serverInfo"] != {"name": "secret-metadata", "version": "1"}
                or initialized["protocolVersion"] != "2025-06-18"
                or initialized["capabilities"] != {"tools": {}}):
            raise ValueError("MCP initialize contract differs")
        tools = replies[1]["result"]["tools"]
        if ([tool["name"] for tool in tools] != ["list", "show", "diff", "health"]
                or any(tool["annotations"] != {"readOnlyHint": True, "destructiveHint": False,
                                               "openWorldHint": False} for tool in tools)):
            raise ValueError("MCP tools differ from the names-only contract")
        health = replies[2]["result"]["content"]
        if (len(health) != 1 or health[0]["type"] != "text"
                or load_json(health[0]["text"]) != {"version": 1, "status": "ready", "stores": 1}
                or b"MCPB_SYNTHETIC" not in json.dumps(replies[3]).encode()):
            raise ValueError("MCP health or synthetic store metadata differs")
        # Invalid settings cannot initialize or touch a discovered/default store.
        for args in ([], ["--store", ""], ["--store", "file:relative"],
                     ["--store", "*"], ["--store", reference + ",libsecret:other"]):
            failure = subprocess.run([str(binary), "mcp", *args], cwd=ROOT, env=env, input=frames,
                                     capture_output=True, timeout=15)
            # Commas are literal file-name characters, never a second reference.
            if args and "," in args[-1]:
                responses = [load_json(line) for line in failure.stdout.splitlines()]
                if failure.returncode != 0 or "error" not in responses[3]:
                    raise ValueError("MCP unexpectedly split a literal store reference")
            elif failure.returncode == 0 or failure.stdout:
                raise ValueError("MCP accepted a missing or malformed store setting")
    print("PASS native payload: version, initialize, tools/list, health, names-only show and exact allowlist")


def build(args):
    version = release_version(args.version)
    check_cli()
    args.out.mkdir(parents=True, exist_ok=True)
    output = args.out / f"secret-v{version}-desktop.mcpb"
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to replace an existing MCPB")
    with tempfile.TemporaryDirectory(prefix="secret-mcpb-stage-") as staging, \
            tempfile.TemporaryDirectory(prefix="secret-mcpb-packed-") as packed, \
            tempfile.TemporaryDirectory(prefix="secret-mcpb-unpacked-") as extracted:
        stage, unpacked = Path(staging), Path(extracted)
        stage_payloads(args, stage)
        (stage / "manifest.json").write_bytes((json.dumps(manifest(version), indent=2) + "\n").encode())
        for source, name in ((ROOT / "LICENSE", "LICENSE"), (PACKAGING / "icon.png", "icon.png")):
            (stage / name).write_bytes(regular_bytes(source))
        for name in APPROVED - {"server/secret", "server/secret.exe"}:
            (stage / name).chmod(0o644)
        cli("validate", stage / "manifest.json")
        bundle = Path(packed) / output.name
        write_zip(bundle, stage)
        inspect_zip(bundle, stage)
        unpack(bundle, unpacked, stage)
        cli("validate", unpacked / "manifest.json")
        native = {"Darwin": "secret", "Windows": "secret.exe"}.get(platform.system())
        if native:
            smoke(unpacked / "server" / native, version)
        else:
            print("SKIP native Desktop payload smoke: this host is not macOS or Windows")
        with output.open("xb") as destination, bundle.open("rb") as source:
            shutil.copyfileobj(source, destination)
    print(f"PASS deterministic MCPB: {output}")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    for name in ("darwin-amd64", "darwin-arm64", "darwin-universal", "windows-amd64", "out", "smoke-binary", "audit-report"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    for name in ("darwin_amd64", "darwin_arm64", "darwin_universal", "windows_amd64", "out", "smoke_binary", "audit_report"):
        path = getattr(args, name)
        if path is not None:
            # Preserve final symlinks so regular_bytes can reject them.
            setattr(args, name, path.absolute())
    release_version(args.version)
    if args.audit_report is not None:
        if any((args.darwin_amd64, args.darwin_arm64, args.darwin_universal, args.windows_amd64, args.out, args.smoke_binary)):
            parser.error("--audit-report accepts only --version and an npm audit JSON report")
        findings = check_dependency_audit(load_json(regular_bytes(args.audit_report, 1 << 20)))
        check_cli()
        check_v3_validation()
        print("PASS audit policy: only documented unreachable Zod v4 findings: " + (", ".join(findings) or "none"))
        return
    if args.smoke_binary is not None:
        if any((args.darwin_amd64, args.darwin_arm64, args.darwin_universal, args.windows_amd64, args.out)):
            parser.error("--smoke-binary accepts only --version and the extracted native payload path")
        smoke(args.smoke_binary.absolute(), args.version)
        return
    if not all((args.darwin_amd64, args.darwin_arm64, args.windows_amd64, args.out)):
        parser.error("build requires both --darwin-* thin inputs, --windows-amd64 and --out")
    build(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, struct.error, zipfile.BadZipFile,
            subprocess.SubprocessError) as error:
        # Do not print child output: smoke diagnostics must not relay value bytes.
        print(f"FAIL MCPB: {type(error).__name__}: " + (str(error) if isinstance(error, ValueError) else "packaging operation failed"), file=sys.stderr)
        sys.exit(1)
