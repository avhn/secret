#!/usr/bin/env python3
"""Synthetic age PTY, ciphertext-persistence and killed-writer checks.

The fixture generator writes fresh keys directly into each disposable HOME.
No identities are embedded in source, printed, or passed as command arguments.
"""

import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("operator_terminal", ROOT / "tests/test-operator.py")
terminal_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal_module)
Terminal = terminal_module.Terminal


@unittest.skipUnless(os.name == "posix" and terminal_module.pty is not None, "Unix PTYs required")
class AgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = str(Path(sys.argv[1]).resolve())
        cls.build_root = tempfile.mkdtemp(prefix="secret-age-build-")
        cls.helper = str(Path(cls.build_root) / "age-fixture")
        result = subprocess.run(
            ["go", "build", "-tags", "agefixture", "-o", cls.helper, "tests/age-fixture.go"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode:
            shutil.rmtree(cls.build_root)
            raise RuntimeError("synthetic age fixture build failed")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build_root)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="secret-age-")).resolve()
        self.addCleanup(shutil.rmtree, self.root)
        self.env = dict(os.environ, HOME=str(self.root), SECRETS_DIR=str(self.root / ".secrets"),
                        SECRETS_ENV=str(self.root / "missing.env"))
        # Remove ambient provider selection and use only this test's namespace.
        self.env.pop("SECRET_KEYCHAIN", None)
        for name in ("primary", "rotated"):
            subprocess.run([self.helper, str(self.root), name], env=self.env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.keys = self.root / ".secrets/.age-keys"
        self.identity = str(self.keys / "primary.identity")
        self.recipients = str(self.keys / "primary.recipients")
        self.rotated_identity = str(self.keys / "rotated.identity")
        self.rotated_recipients = str(self.keys / "rotated.recipients")
        self.store = self.root / ".secrets/test.secret.age"

    def run_cli(self, args, data=None, expected=0, env=None):
        result = subprocess.run([self.binary, *args], input=data, env=env or self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, expected, "unexpected CLI status")
        return result

    def initialize(self, reference="age:test"):
        terminal = Terminal(self, ["age-init", reference, "--age-identity", self.identity,
                                   "--age-recipients", self.recipients])
        terminal.confirm(("age-init " + reference).encode())
        terminal.finish()

    def stash(self, key, value, labels=()):
        return self.run_cli(["stash", "--age-identity", self.identity, *labels, "age:test", key], value)

    def assert_ciphertext_only(self, sentinel):
        # Key material is not read by the Python harness. Check every store,
        # lock and scratch file, including leftovers from failed operations.
        for directory, _, files in os.walk(self.root / ".secrets"):
            if self.keys == Path(directory) or self.keys in Path(directory).parents:
                continue
            for name in files:
                path = Path(directory) / name
                self.assertNotIn(sentinel, path.read_bytes(), "plaintext persisted")

    def test_init_rekey_and_names_without_identity(self):
        self.initialize()
        sentinel = b"SYNTHETIC-AGE-PTY-VALUE"
        self.stash("TOKEN", sentinel)
        self.assert_ciphertext_only(sentinel)
        old = self.store.read_bytes()
        terminal = Terminal(self, ["age-rekey", "age:test", "--age-identity", self.identity,
                                   "--age-recipients", self.rotated_recipients,
                                   "--age-new-identity", self.rotated_identity])
        terminal.confirm(b"age-rekey age:test")
        terminal.finish()
        self.assertNotEqual(old, self.store.read_bytes())
        # Wrong identity must abort before spawning, with no library diagnostics.
        marker = self.root / "spawned"
        result = self.run_cli(["run", "--age-identity", self.identity, "-f", "age:test", "--",
                               sys.executable, "-I", "-c", "from pathlib import Path;Path('" + str(marker) + "').touch()"],
                              expected=1)
        self.assertFalse(marker.exists())
        self.assertEqual(result.stderr, b"secret: invalid or unauthenticated age store\n")
        result = self.run_cli(["run", "--age-identity", self.rotated_identity, "-f", "age:test", "--",
                               sys.executable, "-I", "-c", "import os;print(os.environ['TOKEN'])"])
        self.assertNotIn(sentinel, result.stdout)
        self.assertIn(b"<redacted>", result.stdout)
        os.remove(self.identity)
        os.remove(self.rotated_identity)
        for args in (["show", "age:test"], ["show", "--format=json", "age:test"],
                     ["list", "--backend=age", "--format=json"],
                     ["diff", "--format=json", "age:test"],
                     ["completion", "--command", "run", "--flag=--key", "-f", "age:test"]):
            result = self.run_cli(args)
            self.assertNotIn(sentinel, result.stdout)
        self.assert_ciphertext_only(sentinel)

    def test_confirmation_and_create_only(self):
        terminal = Terminal(self, ["age-init", "age:test", "--age-identity", self.identity,
                                   "--age-recipients", self.recipients])
        terminal.read(b"> ")
        terminal.send(b"no\n")
        terminal.finish(1)
        self.assertFalse(self.store.exists())
        self.initialize()
        old = self.store.read_bytes()
        terminal = Terminal(self, ["age-init", "age:test", "--age-identity", self.identity,
                                   "--age-recipients", self.recipients])
        terminal.confirm(b"age-init age:test")
        terminal.finish(1)
        self.assertEqual(old, self.store.read_bytes())

    def test_lifecycle_and_import_export(self):
        self.initialize()
        self.initialize("age:destination")
        sentinel = b"SYNTHETIC-AGE-LIFECYCLE"
        self.stash("TOKEN", sentinel)
        terminal = Terminal(self, ["export", "--from", "age:test", "--to", "age:destination",
                                   "--on-conflict=fail", "--age-identity", self.identity])
        terminal.confirm(b"export age:destination keys=TOKEN from=age:test")
        terminal.finish()
        terminal = Terminal(self, ["rename", "age:test", "TOKEN", "RENAMED", "--age-identity", self.identity])
        terminal.confirm(b"rename age:test keys=TOKEN,RENAMED")
        terminal.finish()
        terminal = Terminal(self, ["rotate", "age:test", "RENAMED", "--age-identity", self.identity])
        terminal.confirm(b"rotate age:test keys=RENAMED")
        terminal.read(b"New value (hidden): ")
        terminal.send(b"SYNTHETIC-ROTATED\n")
        terminal.finish()
        source = self.root / "source.env"
        source.write_bytes(b"IMPORTED=SYNTHETIC-IMPORTED\n")
        terminal = Terminal(self, ["import", "--from", "dotenv:" + str(source), "--into", "age:test",
                                   "--age-identity", self.identity])
        terminal.confirm(("import age:test keys=IMPORTED from=dotenv:" + str(source)).encode())
        terminal.finish()
        terminal = Terminal(self, ["delete", "age:test", "RENAMED", "--age-identity", self.identity])
        terminal.confirm(b"delete age:test keys=RENAMED")
        terminal.finish()
        self.assert_ciphertext_only(sentinel)
        self.assert_ciphertext_only(b"SYNTHETIC-ROTATED")
        self.assert_ciphertext_only(b"SYNTHETIC-IMPORTED")

    def test_mixed_redaction_template_and_permissions(self):
        self.initialize()
        selected, hidden = b"SYNTHETIC-SELECTED-AGE", b"SYNTHETIC-HIDDEN-AGE"
        self.stash("TOKEN", selected)
        self.stash("HIDDEN", hidden, ("--env", "prod"))
        plain = self.root / "plain.secret"
        plain.write_bytes(b"PLAIN=SYNTHETIC-PLAIN\n")
        env = dict(self.env, HIDDEN="ambient-must-be-removed")
        program = "import os;print(os.environ['TOKEN']);print(os.environ['PLAIN']);print('HIDDEN' in os.environ)"
        result = self.run_cli(["run", "--age-identity", self.identity, "-f", str(plain), "-f", "age:test",
                               "--", sys.executable, "-I", "-c", program], env=env)
        self.assertNotIn(selected, result.stdout)
        self.assertNotIn(b"SYNTHETIC-PLAIN", result.stdout)
        self.assertIn(b"False", result.stdout)
        self.run_cli(["run", "-f", "age:test", "--template-file", str(self.root / "missing"),
                      "--", "never-spawn"], expected=1)
        os.chmod(self.identity, 0o644)
        self.run_cli(["run", "--age-identity", self.identity, "-f", "age:test", "--", "never-spawn"], expected=1)
        os.chmod(self.identity, 0o600)
        alias = self.keys / "alias"
        alias.symlink_to(self.identity)
        self.run_cli(["run", "--age-identity", str(alias), "-f", "age:test", "--", "never-spawn"], expected=1)
        self.assert_ciphertext_only(selected)
        self.assert_ciphertext_only(hidden)

    def test_killed_writer_requires_manual_lock_recovery(self):
        self.initialize()
        before = self.store.read_bytes()
        sentinel = b"SYNTHETIC-KILLED-WRITER"
        process = subprocess.Popen([self.binary, "stash", "--age-identity", self.identity,
                                    "age:test", "LARGE"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        # A large, valid value gives the watcher time to kill after lock creation,
        # during in-memory crypto, without any production fault-injection switch.
        process.stdin.write(sentinel * 350000)
        process.stdin.close()
        lock = self.root / ".secrets/.write-lock"
        deadline = time.monotonic() + 15
        while not (lock / "token").exists():
            if process.poll() is not None or time.monotonic() > deadline:
                self.fail("writer did not reach tokened transaction lock")
            time.sleep(0.0001)
        process.kill()
        process.wait(timeout=10)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(before, self.store.read_bytes(), "kill occurred after publication")
        self.assertTrue((lock / "token").exists())
        self.assert_ciphertext_only(sentinel)
        self.run_cli(["stash", "--age-identity", self.identity, "age:test", "NEXT"],
                     b"synthetic-next", expected=1)
        self.assertEqual(before, self.store.read_bytes())
        # Synthetic human recovery: never let the production writer steal a lock.
        shutil.rmtree(lock)
        scratch = self.root / ".secrets/.secret-stash.synthetic-killed"
        scratch.mkdir(mode=0o700)
        (scratch / "owner").write_bytes(b"secret-stash-v1\n")
        (scratch / "replacement").write_bytes(b"synthetic-ciphertext-only")
        self.stash("NEXT", b"synthetic-next")
        self.assertFalse(scratch.exists())
        self.assert_ciphertext_only(sentinel)
        process.stdout.close()
        process.stderr.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test-age.py ABSOLUTE_BINARY")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
