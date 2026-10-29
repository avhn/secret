#!/usr/bin/env python3
"""Offline setup examples, Go-source argv and quoting checks. Run with python3 -I.

Requires Python 3.11+ (tomllib), not Go, client binaries or a dependency cache.
No client, installer, provider, network, real HOME or store is used. Windows
configuration escaping is checked as data, not claimed as native host evidence.
"""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.2"
DOCUMENT = ROOT / "docs/setup.md"
UNIX_COMMAND = "/ABSOLUTE/INSTALL DIR/secret-go"
UNIX_STORE = "file:/ABSOLUTE/STORE DIR/STORE.secret"
WINDOWS_COMMAND = "C:\\ABSOLUTE\\INSTALL DIR\\secret-go.exe"
WINDOWS_STORE = "file:C:\\ABSOLUTE\\STORE DIR\\STORE.secret"
AUTHENTICATION_ERROR = "secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def blocks(document):
    return re.findall(r"^```(\w+)\n(.*?)^```$", document, re.MULTILINE | re.DOTALL)


def registration(language, body):
    if language == "json":
        value = json.loads(body, object_pairs_hook=unique_object)
        for root in ("mcpServers", "servers", "mcp"):
            if root in value:
                return root, value[root]["secret"]
        raise ValueError("unknown client configuration")
    value = tomllib.loads(body)
    return "mcp_servers", value["mcp_servers"]["secret"]


def server_argv(entry):
    command = entry["command"]
    if isinstance(command, list):
        return command
    return [command, *entry["args"]]


def powershell_words(line):
    # The documented subset has unquoted words and single-quoted literal paths.
    # Single quotes escape by doubling; no expansion or shell execution is used.
    token = re.compile(r"'(?:[^']|'')*'|[^\s']+")
    result, end = [], 0
    for match in token.finditer(line):
        if line[end:match.start()].strip():
            raise ValueError("unsupported PowerShell quoting")
        word = match[0]
        result.append(word[1:-1].replace("''", "'") if word.startswith("'") else word)
        end = match.end()
    if line[end:].strip():
        raise ValueError("unterminated PowerShell quoting")
    return result


def client_argv(language, body):
    words = shlex.split(body) if language == "sh" else powershell_words(body.strip())
    if words[:3] not in (["claude", "mcp", "add"], ["codex", "mcp", "add"]):
        raise ValueError("unknown registration command")
    separator = words.index("--")
    expected = (["claude", "mcp", "add", "--transport", "stdio", "--scope", "user", "secret"]
                if words[0] == "claude" else ["codex", "mcp", "add", "secret"])
    if words[:separator] != expected:
        raise ValueError("unexpected client arguments or scope")
    return words[separator + 1:]


class SetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = DOCUMENT.read_text(encoding="utf-8")
        cls.examples = blocks(cls.document)
        cls.temporary = tempfile.TemporaryDirectory(prefix="secret-setup-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        home, scratch = cls.base / "home", cls.base / "tmp"
        home.mkdir(mode=0o700)
        scratch.mkdir(mode=0o700)
        cls.env = os.environ.copy()
        cls.env.update(HOME=str(home), USERPROFILE=str(home), TMPDIR=str(scratch),
                       TMP=str(scratch), TEMP=str(scratch),
                       SECRETS_DIR=str(home / ".secrets"),
                       SECRETS_ENV=str(home / ".secrets.env"))

    def assert_argv(self, argv):
        self.assertIn(argv[0], (UNIX_COMMAND, WINDOWS_COMMAND))
        expected = UNIX_STORE if argv[0] == UNIX_COMMAND else WINDOWS_STORE
        self.assertEqual(argv[1:], ["mcp", "--store", expected])

    def test_mcp_argv_contract_matches_go_source(self):
        cli = (ROOT / "internal/cli/cli.go").read_text()
        dispatch = cli.split("switch sub {", 1)[1].split("home, homeErr :=", 1)[0]
        clauses = re.findall(r'case((?:\s*"[^"]+"\s*,?)+):', dispatch)
        subcommands = {name for clause in clauses for name in re.findall(r'"([^"]+)"', clause)}
        self.assertIn("version", subcommands)
        self.assertIn("mcp", subcommands)
        features = (ROOT / "internal/cli/features.go").read_text()
        mcp = features.split("func (c command) mcp(args []string) int {", 1)[1].split("\n}", 1)[0]
        specification = re.search(r'featureOptions\(args, "([^"]+)"\)', mcp)[1]
        self.assertEqual(specification, "--store*")
        flags = {word.rstrip("*") for word in specification.split()}
        self.assertIn('Enabled: len(options["--store"]) != 0', mcp)
        self.assertIn("if len(rest) != 0", mcp)
        for language, body in self.examples:
            if language in ("json", "toml"):
                argv = server_argv(registration(language, body)[1])
            elif "mcp add" in body:
                argv = client_argv(language, body)
            else:
                continue
            self.assertIn(argv[1], subcommands)
            self.assertEqual(argv[1], "mcp")
            self.assertIn(argv[2], flags)
            self.assert_argv(argv)

    def test_all_json_toml_and_cli_examples_have_exact_real_argv(self):
        configs, commands = 0, 0
        for language, body in self.examples:
            with self.subTest(language=language, example=configs + commands):
                if language in ("json", "toml"):
                    _, entry = registration(language, body)
                    self.assert_argv(server_argv(entry))
                    self.assertNotIn("env", entry)
                    self.assertNotIn("environment", entry)
                    configs += 1
                elif "mcp add" in body:
                    self.assert_argv(client_argv(language, body))
                    commands += 1
                else:
                    self.assertIn(language, ("sh", "powershell"))
                    self.assertIn("https://raw.githubusercontent.com/avhn/secret/v0.3.2/install.", body)
                    if language == "sh":
                        self.assertTrue(body.startswith("sh -c 'umask 077; d=$(mktemp -d) || exit\n"))
                        self.assertIn('&& sh "$d/install.sh" "$@"', body)
                    else:
                        self.assertIn("$ErrorActionPreference = 'Stop'", body)
                        child = r'& (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File "$d\install.ps1" @args'
                        self.assertIn(r'-OutFile "$d\install.ps1" -ErrorAction Stop; ' + child, body)
                        self.assertIn(child + '; $status = $LASTEXITCODE', body)
                        cleanup = "finally { Remove-Item -LiteralPath $d -Recurse -Force }"
                        self.assertIn(cleanup + "; exit $status", body)
                        self.assertLess(body.index("-ErrorAction Stop"), body.index(child))
                        self.assertLess(body.index(child), body.index("$status = $LASTEXITCODE"))
                        self.assertLess(body.index("$status = $LASTEXITCODE"), body.index(cleanup))
                        self.assertLess(body.index(cleanup), body.index("exit $status"))
                        self.assertNotIn("Set-ExecutionPolicy", body)
        self.assertEqual((configs, commands), (7, 3))

    def test_quoting_and_merge_preserve_exact_arguments(self):
        variants = [
            ('/synthetic install/with "double" and \'single\'/secret-go',
             'file:/synthetic stores/with "double" and \'single\'.secret'),
            ('C:\\synthetic install\\with "double" and \'single\'\\secret-go.exe',
             'file:C:\\synthetic stores\\with "double" and \'single\'.secret'),
        ]
        for language, body in self.examples:
            if language not in ("json", "toml"):
                continue
            root, entry = registration(language, body)
            for command, reference in variants:
                replaced = body.replace(json.dumps(UNIX_COMMAND)[1:-1], json.dumps(command)[1:-1])
                replaced = replaced.replace(json.dumps(UNIX_STORE)[1:-1], json.dumps(reference)[1:-1])
                replaced = replaced.replace(json.dumps(WINDOWS_COMMAND)[1:-1], json.dumps(command)[1:-1])
                replaced = replaced.replace(json.dumps(WINDOWS_STORE)[1:-1], json.dumps(reference)[1:-1])
                _, merged_entry = registration(language, replaced)
                self.assertEqual(server_argv(merged_entry), [command, "mcp", "--store", reference])
                existing = {root: {"unrelated": {"enabled": False}}, "unrelatedSetting": True}
                existing[root]["secret"] = merged_entry
                self.assertEqual(existing[root]["unrelated"], {"enabled": False})
                self.assertTrue(existing["unrelatedSetting"])
        for language, body in self.examples:
            if "mcp add" not in body:
                continue
            for command, reference in variants:
                if language == "sh":
                    rewritten = body.replace(shlex.quote(UNIX_COMMAND), shlex.quote(command))
                    # The docs use double quotes; replace the complete literal tokens.
                    rewritten = rewritten.replace('"' + UNIX_COMMAND + '"', shlex.quote(command))
                    rewritten = rewritten.replace('"' + UNIX_STORE + '"', shlex.quote(reference))
                else:
                    quote = lambda value: "'" + value.replace("'", "''") + "'"
                    rewritten = body.replace(quote(WINDOWS_COMMAND), quote(command)).replace(quote(WINDOWS_STORE), quote(reference))
                self.assertEqual(client_argv(language, rewritten), [command, "mcp", "--store", reference])
                if language == "sh" and os.name != "nt":
                    # Execute the exact registration shell text with a synthetic client
                    # recorder, never a real client or provider. argv survives the shell.
                    recorder = self.base / "recorder"
                    recorder.mkdir(exist_ok=True)
                    client = shlex.split(rewritten)[0]
                    script = recorder / client
                    script.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
                    script.chmod(0o700)
                    env = dict(self.env, PATH=str(recorder) + os.pathsep + self.env["PATH"])
                    result = subprocess.run(["sh", "-c", rewritten], env=env, cwd=self.base,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    words = result.stdout.splitlines()
                    self.assertEqual(words[words.index("--") + 1:], [command, "mcp", "--store", reference])

    def test_bootstrap_examples_match_readme(self):
        def installers(document):
            return {language: body for language, body in blocks(document)
                    if "https://raw.githubusercontent.com/avhn/secret/v0.3.2/install." in body}
        canonical = installers(self.document)
        self.assertEqual(set(canonical), {"sh", "powershell"})
        self.assertEqual(installers((ROOT / "README.md").read_text()), canonical)

    def test_authentication_prerequisite_and_process_only_policy_are_documented(self):
        for path in (DOCUMENT, ROOT / "README.md", ROOT / "docs/install.md", ROOT / "docs/windows.md"):
            with self.subTest(document=path.name):
                text = " ".join(path.read_text().split())
                self.assertIn(AUTHENTICATION_ERROR, text)
                self.assertIn("gh auth login", text)
                self.assertIn("GH_TOKEN", text)
                self.assertRegex(text, r"authenticated|authenticate gh")
                self.assertIn("only to that one child process", text)
                self.assertIn("persistent", text)
                self.assertNotRegex(text, r"GH_TOKEN\s*=\s*['\"]?[A-Za-z0-9_-]{16,}")

    @unittest.skipIf(os.name == "nt", "POSIX snippet execution requires a Unix shell")
    def test_download_failure_never_executes_installer_and_preserves_status(self):
        real_shell = shutil.which("sh")
        self.assertIsNotNone(real_shell)
        for document in (DOCUMENT, ROOT / "README.md"):
            examples = [body for language, body in blocks(document.read_text())
                        if language == "sh" and "https://raw.githubusercontent.com/avhn/secret/v0.3.2/install.sh" in body]
            self.assertEqual(len(examples), 1)
            for mode, installer_status, expected_status in (("fail", 0, 22), ("partial", 0, 22),
                                                           ("success", 0, 0), ("success", 7, 7)):
                with self.subTest(document=document.name, mode=mode, installer_status=installer_status):
                    root = Path(tempfile.mkdtemp(prefix="download-regression-", dir=self.base))
                    tools, scratch = root / "tools", root / "tmp"
                    tools.mkdir(mode=0o700)
                    scratch.mkdir(mode=0o700)
                    installer = root / "synthetic-installer.sh"
                    installer.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$INSTALLER_RAN"\nexit "$INSTALLER_STATUS"\n')
                    # Record a shell launch even if curl left an empty script, which
                    # would otherwise make an incorrect unconditional sh call invisible.
                    (tools / "sh").write_text('#!/bin/sh\nif [ "$1" != -c ]; then\n'
                                             '  printf "%s\\n" "$1" >> "$INSTALLER_EXECUTIONS"\nfi\n'
                                             + "exec " + shlex.quote(real_shell) + ' "$@"\n')
                    (tools / "curl").write_text('#!/bin/sh\noutput=\nwhile [ "$#" -gt 0 ]; do\n'
                                               '  if [ "$1" = -o ]; then shift; output=$1; fi\n  shift\ndone\n'
                                               'printf "%s\\n" "$output" > "$DOWNLOAD_PATH"\n'
                                               'if [ "$CURL_MODE" != fail ]; then cp "$SYNTHETIC_INSTALLER" "$output"; fi\n'
                                               'if [ "$CURL_MODE" != success ]; then exit 22; fi\n')
                    for tool in tools.iterdir():
                        tool.chmod(0o700)
                    ran, executions, downloaded = root / "ran", root / "executions", root / "download-path"
                    env = dict(self.env, PATH=str(tools) + os.pathsep + self.env["PATH"],
                               TMPDIR=str(scratch), CURL_MODE=mode, INSTALLER_STATUS=str(installer_status),
                               SYNTHETIC_INSTALLER=str(installer), INSTALLER_RAN=str(ran),
                               INSTALLER_EXECUTIONS=str(executions), DOWNLOAD_PATH=str(downloaded))
                    flags = ["--version", VERSION, "--dir", str(root / 'install dir with "quotes"')]
                    body = examples[0].strip() + " " + " ".join(shlex.quote(flag) for flag in flags)
                    result = subprocess.run([real_shell, "-c", body], cwd=root, env=env,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
                    self.assertEqual((result.stdout, result.stderr), ("", ""))
                    if mode == "success":
                        self.assertEqual(ran.read_text().splitlines(), flags)
                        self.assertEqual(len(executions.read_text().splitlines()), 1)
                    else:
                        self.assertFalse(ran.exists(), "failed download ran the installer")
                        self.assertFalse(executions.exists(), "failed download launched an installer shell")
                    self.assertFalse(Path(downloaded.read_text().strip()).parent.exists(), "temporary directory survived cleanup")

    def test_version_installer_urls_and_safe_placeholders(self):
        self.assertEqual(set(re.findall(r"(?<![\d.])v?(\d+\.\d+\.\d+)(?![\d.])", self.document)), {VERSION})
        urls = re.findall(r"https://raw\.githubusercontent\.com/[^\s`]+", self.document)
        self.assertEqual(urls, ["https://raw.githubusercontent.com/avhn/secret/v0.3.2/install.sh",
                                "https://raw.githubusercontent.com/avhn/secret/v0.3.2/install.ps1"])
        self.assertIn('curl -fsSL ' + urls[0] + ' -o "$d/install.sh" && sh "$d/install.sh" "$@"', self.document)
        self.assertIn('irm ' + urls[1] + r' -OutFile "$d\install.ps1" -ErrorAction Stop', self.document)
        self.assertNotIn(urls[0] + " | sh", self.document)
        self.assertNotIn(urls[1] + " | iex", self.document)
        self.assertIn("io.github.avhn/secret", self.document)
        self.assertIn("secret-v0.3.2-desktop.mcpb", self.document)
        for installer in ("install.sh", "install.ps1"):
            source = (ROOT / installer).read_text()
            self.assertIn("0.3.2", source)
            for option in ("SECRET_VERSION", "SECRET_RELEASE_COMMIT", "INSTALL_DIR", "--version", "--commit", "--dir", "--help"):
                self.assertIn(option, source)
        self.assertNotRegex(self.document, r"(?:sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16}|-----BEGIN .*PRIVATE KEY)")
        for _, body in self.examples:
            self.assertNotRegex(body, r"(?i)(?:token|password|api_key)\s*[=:]")
        self.assertNotIn("\u2013", self.document)
        self.assertNotIn("\u2014", self.document)
        self.assertFalse(any(0x1F000 <= ord(char) <= 0x1FAFF or 0x2600 <= ord(char) <= 0x27BF
                             or ord(char) in (0xFE0F, 0x200D) for char in self.document))

    def test_parsers_reject_ambiguous_examples(self):
        with self.assertRaises(ValueError):
            registration("json", '{"mcpServers": {}, "mcpServers": {}}')
        with self.assertRaises(tomllib.TOMLDecodeError):
            registration("toml", "[mcp_servers.secret]\ncommand='a'\ncommand='b'\n")
        with self.assertRaises(ValueError):
            powershell_words("claude 'unterminated")
        with self.assertRaises(ValueError):
            client_argv("sh", "claude mcp add --scope project secret -- /synthetic/secret-go mcp --store file:/synthetic/STORE")


if __name__ == "__main__":
    unittest.main()
