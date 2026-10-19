#!/usr/bin/env python3
"""Hosted Unix PTY coverage for the staged Go CLI, using synthetic stores only."""

import errno
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

try:
    import pty
    import termios
except ImportError:
    pty = None


class Terminal:
    def __init__(self, case, args, stdin_tty=True, stdout_tty=True):
        self.case = case
        gate_read, gate_write = os.pipe()
        try:
            self.pid, self.fd = pty.fork()
        except OSError as error:
            os.close(gate_read)
            os.close(gate_write)
            if error.errno in (errno.ENOSYS, errno.ENODEV, errno.EACCES, errno.EPERM, errno.ENOENT):
                raise unittest.SkipTest("controlling PTY unavailable") from None
            raise
        if self.pid == 0:
            os.close(gate_write)
            os.read(gate_read, 1)
            os.close(gate_read)
            for fd, connected in ((0, stdin_tty), (1, stdout_tty)):
                if not connected:
                    replacement = os.open(os.devnull, os.O_RDONLY if fd == 0 else os.O_WRONLY)
                    os.dup2(replacement, fd)
                    os.close(replacement)
            os.execve(case.binary, [case.binary, *args], case.env)
        os.close(gate_read)
        os.set_blocking(self.fd, False)
        self.output = bytearray()
        # Capture the initial mode before the child can enter hidden raw input.
        self.state = termios.tcgetattr(self.fd)
        os.close(gate_write)
        self.status = None
        case.addCleanup(self.close)

    def read(self, marker):
        deadline = time.monotonic() + 15
        while marker not in self.output:
            if time.monotonic() >= deadline:
                self.case.fail("terminal prompt timed out")
            self.drain(0.1)
            if self.status is not None and marker not in self.output:
                self.case.fail("command exited before terminal prompt")
        return bytes(self.output)

    def drain(self, timeout):
        if select.select([self.fd], [], [], timeout)[0]:
            try:
                chunk = os.read(self.fd, 8192)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            self.output.extend(chunk)
            self.case.assertLess(len(self.output), 1 << 20, "terminal output exceeded test bound")
        if self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)

    def send(self, data):
        deadline = time.monotonic() + 15
        while data:
            if time.monotonic() >= deadline:
                self.case.fail("terminal input timed out")
            if select.select([], [self.fd], [], 0.1)[1]:
                try:
                    count = os.write(self.fd, data[:4096])
                    data = data[count:]
                except BlockingIOError:
                    pass

    def confirm(self, challenge):
        self.read(b"> ")
        self.case.assertIn(challenge + b"\r\n> ", self.output)
        self.send(challenge + b"\n")

    def finish(self, expected=0):
        deadline = time.monotonic() + 20
        while self.status is None:
            if time.monotonic() >= deadline:
                self.case.fail("terminal command timed out")
            self.drain(0.1)
        # Drain bytes queued just before exit as well.
        self.drain(0)
        self.case.assertEqual(self.status, expected, "unexpected terminal exit status")
        self.case.assertEqual(termios.tcgetattr(self.fd), self.state, "terminal mode not restored")
        return bytes(self.output)

    def close(self):
        if self.status is None:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        os.close(self.fd)


class OperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if pty is None or os.name != "posix":
            raise unittest.SkipTest("Unix PTY support unavailable")
        try:
            master, slave = pty.openpty()
        except OSError as error:
            if error.errno in (errno.ENOSYS, errno.ENODEV, errno.EACCES, errno.EPERM, errno.ENOENT):
                raise unittest.SkipTest("PTY unavailable") from None
            raise
        os.close(master)
        os.close(slave)
        cls.binary = str(Path(BINARY).resolve(strict=True))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="secret-operator-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.stores = self.root / "stores"
        self.stores.mkdir(mode=0o700)
        self.path = self.stores / "synthetic.secret"
        self.original = b"TOKEN=synthetic-plain-value\n[env=prod]\nTOKEN=synthetic-labelled-value\n"
        self.path.write_bytes(self.original)
        self.path.chmod(0o600)
        self.ref = "file:" + str(self.path)
        # Do not inherit host store, provider, audit or MCP configuration.
        self.env = {"PATH": os.environ["PATH"], "HOME": str(self.home),
                    "SECRETS_DIR": str(self.stores), "SECRETS_ENV": str(self.home / "absent"),
                    "LC_ALL": "C"}
        self.challenge = lambda action, keys: (action + " " + self.ref + " keys=" + keys).encode()

    def run_cli(self, *args, input=b"", expected=0):
        result = subprocess.run([self.binary, *args], input=input, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        self.assertEqual(result.returncode, expected, "unexpected CLI exit status")
        return result.stdout

    def test_nonterminal_refusal_before_access(self):
        absent = self.root / "not-created"
        self.env["SECRETS_DIR"] = str(absent)
        for action in ("import", "export", "rename", "rotate", "delete"):
            self.run_cli(action, "file:" + str(absent / "store"), "TOKEN",
                         "--audit-dir", str(absent / "audit"), input=b"yes\n", expected=1)
            self.assertFalse(absent.exists())
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_stdin_and_stdout_must_each_be_terminals(self):
        for stdin_tty, stdout_tty in ((False, True), (True, False)):
            terminal = Terminal(self, ["delete", self.ref, "TOKEN"], stdin_tty=stdin_tty, stdout_tty=stdout_tty)
            output = terminal.finish(1)
            self.assertNotIn(b"Type exactly", output)
            self.assertEqual(self.path.read_bytes(), self.original)

    def test_decline_and_cancel_do_not_mutate(self):
        for answer in (b"yes\n", b"\x03", b"\x04"):
            terminal = Terminal(self, ["delete", self.ref, "TOKEN"])
            terminal.read(b"> ")
            terminal.send(answer)
            terminal.finish(1)
            self.assertEqual(self.path.read_bytes(), self.original)

    def test_hidden_rotation_exact_labels_and_lifecycle(self):
        audit = self.root / "audit"
        terminal = Terminal(self, ["rotate", self.ref, "TOKEN", "--env", "prod", "--audit-dir", str(audit)])
        challenge = self.challenge("rotate", "TOKEN") + b" labels=env=prod"
        terminal.confirm(challenge)
        terminal.read(b"New value (hidden): ")
        value = b"synthetic-rotated-hidden-value"
        terminal.send(value + b"\n")
        output = terminal.finish()
        self.assertNotIn(value, output)
        self.assertEqual(output.count(challenge), 1, "confirmation was echoed")
        self.assertEqual(self.path.read_bytes(), self.original.replace(b"synthetic-labelled-value", value))
        terminal = Terminal(self, ["rename", self.ref, "TOKEN", "RENAMED", "--env", "prod"])
        terminal.confirm(self.challenge("rename", "TOKEN,RENAMED") + b" labels=env=prod")
        terminal.finish()
        terminal = Terminal(self, ["delete", self.ref, "RENAMED", "--env", "prod"])
        terminal.confirm(self.challenge("delete", "RENAMED") + b" labels=env=prod")
        terminal.finish()
        self.assertIn(b"TOKEN=synthetic-plain-value\n", self.path.read_bytes())
        self.assertNotIn(value, self.path.read_bytes())
        events = self.run_cli("audit", "--directory", str(audit), "--format=json")
        self.assertNotIn(value, events)
        self.assertEqual(len(json.loads(events)["events"]), 1)

    def test_hidden_input_rejection_and_restoration(self):
        for value in (b"", b" bad", b"synthetic-overflow-" + b"x" * (64 << 10), b"\x03"):
            terminal = Terminal(self, ["rotate", self.ref, "TOKEN"])
            terminal.confirm(self.challenge("rotate", "TOKEN"))
            terminal.read(b"New value (hidden): ")
            terminal.send(value + (b"" if value == b"\x03" else b"\n"))
            output = terminal.finish(1)
            self.assertNotIn(b"synthetic-overflow-", output)
            self.assertEqual(self.path.read_bytes(), self.original)

    def test_import_confirmation_and_metadata(self):
        source = self.root / "import.env"
        source.write_bytes(b"SOURCE=synthetic-import-hidden-value\n")
        source.chmod(0o600)
        terminal = Terminal(self, ["import", "--from", "dotenv:" + str(source), "--into", self.ref,
                                   "--map", "SOURCE=IMPORTED"])
        challenge = self.challenge("import", "IMPORTED") + (" from=dotenv:" + str(source)).encode()
        terminal.confirm(challenge)
        output = terminal.finish()
        self.assertNotIn(b"synthetic-import-hidden-value", output)
        metadata = self.run_cli("show", "--format=json", self.ref)
        self.assertNotIn(b"synthetic-import-hidden-value", metadata)
        records = json.loads(metadata)["stores"][0]["records"]
        self.assertIn("IMPORTED", [record["key"] for record in records])
        diff = json.loads(self.run_cli("diff", "--format=json", "--env", "dev", "--env", "prod", self.ref))
        self.assertEqual(diff["version"], 1)

    def test_mcp_allowlist_and_forbidden_methods(self):
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "synthetic", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "show", "arguments": {"reference": self.ref}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "show", "arguments": {"reference": "file:" + str(self.root / "outside")}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get", "arguments": {}}},
        ]
        output = self.run_cli("mcp", "--store", self.ref,
                              input=b"".join(json.dumps(frame).encode() + b"\n" for frame in frames))
        replies = [json.loads(line) for line in output.splitlines()]
        self.assertIn("result", replies[1])
        self.assertIn("error", replies[2])
        self.assertIn("error", replies[3])
        self.assertNotIn(b"synthetic-plain-value", output)
        self.assertNotIn(b"synthetic-labelled-value", output)

    def test_template_cleanup_normal_and_signal(self):
        python = shutil.which("python3")
        self.assertIsNotNone(python)
        template = self.root / "template"
        template.write_bytes(b"token={{TOKEN}}")
        for interrupted in (False, True):
            code = ("import os,pathlib,time; p=pathlib.Path(os.environ['SECRET_TEMPLATE_FILE']); "
                    "print(str(p), flush=True); print(p.read_text(), flush=True); "
                    + ("time.sleep(60)" if interrupted else "pass"))
            terminal = Terminal(self, ["run", "-f", self.ref, "--key", "TOKEN", "--template-file", str(template),
                                       "--", python, "-I", "-c", code])
            terminal.read(b"token=<redacted>")
            rendered = self.home / ".secrets" / ".rendered"
            payloads = list(rendered.glob("*/payload"))
            if interrupted:
                self.assertEqual(len(payloads), 1)
                self.assertEqual(payloads[0].stat().st_mode & 0o777, 0o600)
                self.assertEqual(payloads[0].parent.stat().st_mode & 0o777, 0o700)
                os.kill(terminal.pid, signal.SIGTERM)
            output = terminal.finish(143 if interrupted else 0)
            self.assertNotIn(b"synthetic-plain-value", output)
            self.assertEqual(list(rendered.iterdir()), [])
            self.assertFalse((self.stores / ".rendered").exists())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: python3 -I tests/test-operator.py ABSOLUTE_GO_BINARY")
    BINARY = sys.argv.pop(1)
    if not os.path.isabs(BINARY):
        raise SystemExit("Go binary path must be absolute")
    unittest.main(verbosity=2)
