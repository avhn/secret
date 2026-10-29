#!/usr/bin/env python3
"""Generate exact release metadata, or verify public bytes before Registry OIDC.

Run with python3 -I. Generation is offline; publisher-validate uses the separately
pinned official Linux publisher. Publication never uploads or replaces GitHub
assets. All downloads, publisher extraction and authentication use private scratch.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, build_opener
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPO = "avhn/secret"
REPOSITORY = "https://github.com/" + REPO
NAME = "io.github.avhn/secret"
SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
PUBLISH_TAG = "v0.3.1"
PUBLISHER_VERSION = "1.8.1"
PUBLISHER_SHA256 = "a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc"
PUBLISHER_URL = ("https://github.com/modelcontextprotocol/registry/releases/download/v"
                 + PUBLISHER_VERSION + "/mcp-publisher_linux_amd64.tar.gz")
MAX_ASSET = 256 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def read_json(data):
    def invalid_constant(_):
        raise ValueError("invalid JSON constant")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def object_json(data):
    value = read_json(data)
    require(isinstance(value, dict), "JSON document must be an object")
    return value


def version_check(version):
    require(isinstance(version, str) and re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version),
        "expected exact stable version")
    return version


def payload_names(version):
    version_check(version)
    return sorted([f"secret-v{version}-{system}-{arch}"
                   for system in ("darwin", "linux") for arch in ("amd64", "arm64")]
                  + [f"secret-v{version}-windows-{arch}.exe" for arch in ("amd64", "arm64")]
                  + [f"secret-v{version}-desktop.mcpb", "server.json"])


def checksum_name(version):
    return f"checksums-v{version_check(version)}.txt"


def file_bytes(path, limit=MAX_ASSET):
    require(path.is_file() and not path.is_symlink(), "missing or nonregular release file")
    require(path.stat().st_size <= limit, "oversized release file")
    return path.read_bytes()


def digest(path):
    require(path.is_file() and not path.is_symlink(), "missing or nonregular release file")
    require(path.stat().st_size <= MAX_ASSET, "oversized release file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_metadata(version):
    value = object_json(file_bytes(ROOT / "packaging/registry/server.template.json", MAX_JSON))
    require(set(value) == {"$schema", "name", "title", "description", "repository"},
            "source must contain only reviewed metadata fields, without a version or packages")
    require(value["$schema"] == SCHEMA and value["name"] == NAME
            and value["title"] == "secret", "unexpected schema or server identity")
    require(value["repository"] == {"url": REPOSITORY, "source": "github"}, "unexpected repository")
    require(isinstance(value["description"], str) and 0 < len(value["description"]) <= 100,
            "invalid server description")
    value["version"] = version_check(version)
    return value


def inspect_bundle(path, version, directory):
    """Inspect only allowlisted bytes, never extract or execute downloaded code."""
    file_bytes(path)
    expected = {"manifest.json", "LICENSE", "icon.png", "server/secret-go", "server/secret-go.exe"}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and set(names) == expected
                and names == sorted(names) and not archive.comment, "invalid bundle layout")
        for info in archive.infolist():
            mode = info.external_attr >> 16
            require(info.create_system == 3 and not info.flag_bits & 1
                    and stat.S_IFMT(mode) in (0, stat.S_IFREG), "nonregular or encrypted bundle entry")
            require(stat.S_IMODE(mode) == (0o755 if info.filename.startswith("server/") else 0o644),
                    "invalid bundle permissions")
            require(info.flag_bits == 0 and info.compress_type == zipfile.ZIP_STORED
                    and info.date_time == (1980, 1, 1, 0, 0, 0) and not info.extra and not info.comment
                    and info.compress_size == info.file_size, "noncanonical bundle entry")
            require(0 < info.file_size <= (MAX_JSON if info.filename == "manifest.json" else MAX_ASSET),
                    "empty or oversized bundle entry")
        manifest = object_json(archive.read("manifest.json"))
        require(manifest.get("manifest_version") == "0.3" and manifest.get("name") == "secret"
                and manifest.get("version") == version, "bundle identity/version mismatch")
        compatibility = manifest.get("compatibility")
        require(isinstance(compatibility, dict) and compatibility.get("platforms") == ["darwin", "win32"],
                "bundle platform mismatch")
        server = manifest.get("server", {})
        require(isinstance(server, dict) and server.get("type") == "binary" and server.get("entry_point") == "server/secret-go",
                "invalid bundle server")
        config = server.get("mcp_config", {})
        require(config == {"command": "${__dirname}/server/secret-go",
                           "args": ["mcp", "--store", "${user_config.store_reference}"],
                           "platform_overrides": {"win32": {"command": "${__dirname}/server/secret-go.exe"}}},
                "invalid bundle argv or transport")
        settings = manifest.get("user_config", {})
        require(isinstance(settings, dict) and set(settings) == {"store_reference"}, "unexpected bundle settings")
        setting = settings["store_reference"]
        require(isinstance(setting, dict) and setting.get("type") == "string" and setting.get("required") is True
                and "default" not in setting, "store reference must be explicitly configured")
        reviewed = object_json(file_bytes(ROOT / "packaging/mcpb/manifest.template.json", MAX_JSON))
        reviewed["version"] = version
        reviewed["documentation"] = f"{REPOSITORY}/blob/v{version}/docs/setup.md"
        require(manifest == reviewed, "bundle manifest differs from reviewed template")
        windows = archive.read("server/secret-go.exe")
        require(len(windows) >= 64 and windows[:2] == b"MZ", "missing Windows executable")
        offset = struct.unpack_from("<I", windows, 60)[0]
        require(offset >= 64 and offset + 26 <= len(windows)
                and windows[offset:offset + 6] == b"PE\0\0\x64\x86"
                and struct.unpack_from("<H", windows, offset + 24)[0] == 0x20B,
                "wrong Windows bundle architecture")
        require(windows == file_bytes(directory / f"secret-v{version}-windows-amd64.exe"),
                "bundle Windows payload differs from release")
        mac = archive.read("server/secret-go")
        require(len(mac) >= 8 and mac[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
                and struct.unpack_from(">I", mac, 4)[0] == 2, "missing two-slice universal Mach-O")
        wide = mac[:4] == b"\xca\xfe\xba\xbf"
        width = 32 if wide else 20
        header_size = 8 + 2 * width
        require(len(mac) >= header_size, "truncated universal header")
        slices = {}
        ranges = []
        for index in range(2):
            fields = struct.unpack_from(">IIQQII" if wide else ">IIIII", mac, 8 + index * width)
            cpu, subtype, offset, size, alignment = fields[:5]
            require(cpu not in slices and offset >= header_size and size >= 32 and offset + size <= len(mac)
                    and alignment <= 30 and offset % (1 << alignment) == 0
                    and (not wide or fields[5] == 0), "invalid universal slice")
            part = mac[offset:offset + size]
            require(part[:4] == b"\xcf\xfa\xed\xfe"
                    and struct.unpack_from("<III", part, 4) == (cpu, subtype, 2),
                    "invalid embedded Mach-O architecture")
            ranges.append((offset, offset + size))
            slices[cpu] = part
        require(set(slices) == {0x01000007, 0x0100000C}
                and (ranges[0][1] <= ranges[1][0] or ranges[1][1] <= ranges[0][0]),
                "wrong or overlapping universal slices")
        for cpu, arch in ((0x01000007, "amd64"), (0x0100000C, "arm64")):
            require(slices[cpu] == file_bytes(directory / f"secret-v{version}-darwin-{arch}"),
                    "bundle Darwin slice differs from release")
    return manifest


def generated_metadata(version, directory):
    value = source_metadata(version)
    bundle = f"secret-v{version}-desktop.mcpb"
    inspect_bundle(directory / bundle, version, directory)
    value["packages"] = [{"registryType": "mcpb",
                          "identifier": f"{REPOSITORY}/releases/download/v{version}/{bundle}",
                          "version": version, "fileSha256": digest(directory / bundle),
                          "transport": {"type": "stdio"}}]
    return value


def encoded_metadata(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def checksum_bytes(version, directory, server=None):
    lines = []
    for name in payload_names(version):
        sha = hashlib.sha256(server).hexdigest() if name == "server.json" and server is not None else digest(directory / name)
        lines.append(f"{sha}  {name}\n")
    return "".join(lines).encode("ascii")


def verify_checksums(version, directory):
    data = file_bytes(directory / checksum_name(version), 4096)
    # Byte equality enforces lowercase digests, exact basenames/order, two spaces,
    # exactly eight records, LF endings and the mandatory final newline.
    require(data == checksum_bytes(version, directory), "stale or invalid checksums")
    return data


def generate(version, directory):
    require(directory.is_dir() and not directory.is_symlink(), "assets must be a real directory")
    names = {path.name for path in directory.iterdir()}
    inputs = set(payload_names(version)) - {"server.json"}
    outputs = {"server.json", checksum_name(version)}
    require(names in (inputs, inputs | outputs), "generation requires exactly seven inputs or the complete nine-file set")
    value = generated_metadata(version, directory)
    server = encoded_metadata(value)
    checksums = checksum_bytes(version, directory, server)
    if names == inputs | outputs:
        require(object_json(file_bytes(directory / "server.json", MAX_JSON)) == value,
                "invalid generated metadata or stale bundle hash")
        require(file_bytes(directory / "server.json", MAX_JSON) == server,
                "generated metadata differs from canonical bytes")
        verify_checksums(version, directory)
    else:
        with (directory / "server.json").open("xb") as stream:
            stream.write(server)
        with (directory / checksum_name(version)).open("xb") as stream:
            stream.write(checksums)
    return value


class ReviewedRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        from urllib.parse import urlsplit
        target = urlsplit(newurl)
        require(target.scheme == "https" and target.hostname in
                {"github.com", "release-assets.githubusercontent.com"}
                and target.port in (None, 443) and target.username is None,
                "unreviewed download redirect")
        return super().redirect_request(request, response, code, message, headers, newurl)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise ValueError("unexpected Registry API redirect")


def response_chunks(response, limit, seconds):
    total = 0
    deadline = time.monotonic() + seconds
    while True:
        require(time.monotonic() < deadline, "HTTPS response timed out")
        # read1 performs one buffered read, so a peer sending occasional bytes
        # cannot indefinitely extend an exact-length read past the deadline.
        data = response.read1(64 * 1024)
        if not data:
            return
        total += len(data)
        require(total <= limit, "oversized HTTPS response")
        yield data


def download_publisher(destination):
    with build_opener(ReviewedRedirects()).open(PUBLISHER_URL, timeout=30) as response:
        require(response.status == 200, "publisher download failed")
        with destination.open("xb") as stream:
            for data in response_chunks(response, MAX_ASSET, 120):
                stream.write(data)


def run(command, *, env=None, cwd=ROOT, timeout=120):
    # Never echo publisher authentication output or inspect token files.
    return subprocess.check_output([str(item) for item in command], cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout)


@contextmanager
def verified_publisher():
    require(platform.system() == "Linux" and platform.machine().lower() in ("amd64", "x86_64"),
            "publisher validation requires Linux amd64")
    with tempfile.TemporaryDirectory(prefix="publisher-download-") as download, \
            tempfile.TemporaryDirectory(prefix="publisher-extracted-") as extracted, \
            tempfile.TemporaryDirectory(prefix="publisher-home-") as home:
        archive_path = Path(download) / "publisher.tar.gz"
        download_publisher(archive_path)
        require(digest(archive_path) == PUBLISHER_SHA256, "publisher checksum mismatch")
        binary = Path(extracted) / "mcp-publisher"
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            require(sorted(member.name for member in members) == ["LICENSE", "README.md", "mcp-publisher"]
                    and all(member.isfile() and member.size <= MAX_ASSET for member in members),
                    "invalid publisher archive")
            with archive.extractfile("mcp-publisher") as source, binary.open("xb") as target:
                shutil.copyfileobj(source, target)
        binary.chmod(0o700)
        env = os.environ.copy()
        for variable in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                         "XDG_RUNTIME_DIR", "APPDATA", "LOCALAPPDATA", "USERPROFILE"):
            location = Path(home) / variable.lower()
            location.mkdir(mode=0o700)
            env[variable] = str(location)
        yield binary, env


def publisher_validate(path, publisher):
    binary, env = publisher
    run([binary, "validate", path.resolve()], env=env)


def git(*args):
    return run(["git", "-C", ROOT, *args]).decode("utf-8")


def verify_source(tag, commit=None):
    require(tag == PUBLISH_TAG, "registry publication requires exactly v0.3.1")
    if commit is not None:
        require(re.fullmatch(r"[0-9a-f]{40}", commit), "expected full commit SHA")
    git("fetch", "--no-tags", "--force", "origin", f"refs/tags/{tag}:refs/tags/{tag}")
    require(git("cat-file", "-t", f"refs/tags/{tag}").strip() == "tag", "release tag must be annotated")
    final = git("rev-parse", f"refs/tags/{tag}^{{commit}}").strip()
    require(re.fullmatch(r"[0-9a-f]{40}", final) and (commit is None or final == commit), "tag/commit mismatch")
    require(git("rev-parse", "HEAD").strip() == final, "checkout is not final commit C")
    parents = git("rev-list", "--parents", "-n", "1", final).split()
    require(len(parents) == 2 and parents[0] == final, "C must have exactly one parent S")
    path = "dist/" + checksum_name(tag[1:])
    require(git("diff-tree", "--no-commit-id", "--name-status", "-r", parents[1], final) == "A\t" + path + "\n",
            "only checksum manifest may change S..C")
    require(not (ROOT / ".secret-release-test-fixture").exists()
            and not (ROOT / ".secret-release-test-fixture").is_symlink(), "fixture marker must not ship")
    for revision in (parents[1], final):
        require(not git("ls-tree", "--name-only", revision, "--", ".secret-release-test-fixture"),
                "fixture marker must not ship")
    return final, run(["git", "-C", ROOT, "show", final + ":" + path])


def verify_attestations(directory, version, final):
    for name in payload_names(version) + [checksum_name(version)]:
        sha = digest(directory / name)
        bundle = directory / f"sha256-{sha}.jsonl"
        file_bytes(bundle, 16 * 1024 * 1024)
        verified = read_json(run([
            "gh", "attestation", "verify", directory / name, "--bundle", bundle,
            "--repo", REPO, "--source-digest", final, "--signer-digest", final,
            "--source-ref", "refs/tags/v" + version,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--cert-identity", f"{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{version}",
            "--deny-self-hosted-runners", "--format", "json"]))
        require(isinstance(verified, list) and verified, "missing verified attestations")
        for entry in verified:
            statement = entry["verificationResult"]["statement"]
            require(statement["predicateType"] == "https://slsa.dev/provenance/v1", "unexpected provenance type")
            subjects = statement["subject"]
            require(isinstance(subjects, list) and subjects
                    and all(isinstance(subject, dict) for subject in subjects), "invalid provenance subjects")
            matches = [subject for subject in subjects if subject.get("name") == name]
            require(len(matches) == 1 and matches[0].get("digest") == {"sha256": sha},
                    "provenance subject mismatch")


def registry_record(version):
    url = f"https://registry.modelcontextprotocol.io/v0.1/servers/io.github.avhn%2Fsecret/versions/{version}"
    try:
        with build_opener(NoRedirects()).open(url, timeout=30) as response:
            require(response.status == 200, "Registry API request failed")
            return object_json(b"".join(response_chunks(response, MAX_JSON, 60)))
    except HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise ValueError("Registry API request failed") from error
    except URLError as error:
        raise ValueError("Registry API request failed") from error


def require_registry_match(record, expected):
    server = record.get("server")
    require(isinstance(server, dict) and all(server.get(key) == expected[key]
            for key in ("name", "version", "packages")), "Registry name/version/packages mismatch")


def registry_active(record):
    meta = record.get("_meta")
    official = meta.get("io.modelcontextprotocol.registry/official") if isinstance(meta, dict) else None
    return isinstance(official, dict) and official.get("status") == "active"


def registry_publish(tag, commit=None):
    final, committed_checksums = verify_source(tag, commit)
    version = tag[1:]
    details = object_json(run(["gh", "release", "view", tag, "--repo", REPO,
                               "--json", "tagName,isDraft,isPrerelease,assets"]))
    require(details.get("tagName") == tag and details.get("isDraft") is False
            and details.get("isPrerelease") is False, "release must be published, not draft or prerelease")
    assets = details.get("assets")
    require(isinstance(assets, list) and len(assets) == 18, "release requires exactly eighteen public assets")
    names = [asset["name"] for asset in assets]
    require(len(names) == len(set(names)) and all(isinstance(asset.get("size"), int)
            and 0 < asset["size"] <= MAX_ASSET for asset in assets), "invalid release assets")
    with tempfile.TemporaryDirectory(prefix="registry-assets-") as downloaded, \
            tempfile.TemporaryDirectory(prefix="registry-regenerated-") as regenerated:
        directory = Path(downloaded)
        # Each untrusted input gets its own initially empty download directory.
        for name in names:
            require(name in payload_names(version) + [checksum_name(version)]
                    or re.fullmatch(r"sha256-[0-9a-f]{64}\.jsonl", name), "unexpected public asset")
            with tempfile.TemporaryDirectory(prefix="registry-input-") as scratch:
                run(["gh", "release", "download", tag, "--repo", REPO, "--pattern", name, "--dir", scratch])
                source = Path(scratch) / name
                require({path.name for path in Path(scratch).iterdir()} == {name}, "unexpected downloaded files")
                file_bytes(source)
                shutil.copyfile(source, directory / name)
        verify_checksums(version, directory)
        require(file_bytes(directory / checksum_name(version), 4096) == committed_checksums,
                "public checksums differ from C")
        subjects = payload_names(version) + [checksum_name(version)]
        expected_names = set(subjects) | {f"sha256-{digest(directory / name)}.jsonl" for name in subjects}
        require(len(expected_names) == 18 and set(names) == expected_names, "unexpected attestation bundle set")
        verify_attestations(directory, version, final)
        for name in payload_names(version):
            if name != "server.json":
                shutil.copyfile(directory / name, Path(regenerated) / name)
        # Parse downloaded JSON too: duplicate keys must not be normalized away.
        actual = object_json(file_bytes(directory / "server.json", MAX_JSON))
        expected = generate(version, Path(regenerated))
        require(actual == expected, "invalid generated metadata or stale bundle hash")
        for name in ("server.json", checksum_name(version)):
            require(file_bytes(directory / name) == file_bytes(Path(regenerated) / name),
                    "downloaded metadata differs from regenerated public bytes")
        path = (directory / "server.json").resolve()
        with verified_publisher() as publisher:
            publisher_validate(path, publisher)
            record = registry_record(version)
            if record is not None:
                require_registry_match(record, expected)
                require(registry_active(record), "existing Registry record is not active")
                print("secret: identical Registry record already active")
                return
            binary, env = publisher
            run([binary, "login", "github-oidc"], env=env)
            run([binary, "publish", path], env=env, timeout=180)
            for attempt in range(10):
                record = registry_record(version)
                if record is not None:
                    require_registry_match(record, expected)
                    if registry_active(record):
                        print("secret: Registry publication verified active")
                        return
                if attempt < 9:
                    time.sleep(6)
            raise ValueError("Registry publication did not become active after 10 checks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("generate")
    command.add_argument("--version", required=True)
    command.add_argument("--assets", required=True, type=Path)
    command = commands.add_parser("publisher-validate")
    command.add_argument("--input", required=True, type=Path)
    command = commands.add_parser("registry-publish")
    command.add_argument("--tag", required=True)
    command.add_argument("--commit")
    args = parser.parse_args()
    if args.command == "generate":
        generate(args.version, args.assets)
    elif args.command == "publisher-validate":
        value = object_json(file_bytes(args.input, MAX_JSON))
        require(value == generated_metadata(value["version"], args.input.parent), "invalid generated metadata")
        verify_checksums(value["version"], args.input.parent)
        with verified_publisher() as publisher:
            publisher_validate(args.input, publisher)
    else:
        registry_publish(args.tag, args.commit)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, IndexError, struct.error,
            zipfile.BadZipFile, tarfile.TarError, subprocess.SubprocessError):
        print("secret: release metadata or Registry verification failed", file=sys.stderr)
        sys.exit(1)
