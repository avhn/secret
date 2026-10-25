#!/usr/bin/env python3
"""Native pass/GPG fixture, GitHub runners only. All keys and stores are disposable."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]


def call(args, env, data=None, expected=0, timeout=120, safe_diagnostics=False):
    result = subprocess.run(args, input=data, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False, cwd=REPO)
    if result.returncode != expected:
        if safe_diagnostics:
            sys.stderr.buffer.write(result.stdout + result.stderr)
        raise RuntimeError("isolated pass fixture command failed (output withheld)")
    return result.stdout


def fingerprint(env, uid):
    data = call(["gpg", "--batch", "--with-colons", "--list-keys", uid], env)
    for line in data.splitlines():
        fields = line.split(b":")
        if fields[0] == b"fpr":
            return fields[9].decode("ascii")
    raise RuntimeError("synthetic fingerprint missing")


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("native pass tests require an isolated GitHub runner; not run locally")
    if len(sys.argv) != 2:
        raise RuntimeError("absolute staged Go binary required")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    prefix = Path(os.environ["SECRET_PASS_PREFIX"]).resolve(strict=True)
    actual_pass = Path(shutil.which("pass") or "missing").resolve(strict=True)
    if actual_pass != prefix / "bin/pass":
        raise RuntimeError("pass executable is not the staged immutable provider")
    # Resolve tools before changing HOME/PATH. Never read ambient provider stores.
    go = shutil.which("go")
    actual_gpg = shutil.which("gpg")
    if Path(shutil.which("bash") or "missing").resolve() != Path(os.environ["SECRET_PASS_BASH"]).resolve():
        raise RuntimeError("native Bash selection mismatch")
    gpgconf = shutil.which("gpgconf")
    if not all((go, actual_gpg, gpgconf)):
        raise RuntimeError("required native tools missing")
    with tempfile.TemporaryDirectory(prefix="secret-pass-", dir=os.environ["RUNNER_TEMP"]) as temp:
        root = Path(temp).resolve()
        os.chmod(root, 0o700)
        for name in ("home", "gpg", "public-gpg", "passwords", "stores", "tmp", "tools", "go-cache", "go-mod-cache"):
            (root / name).mkdir(mode=0o700)
        env = {"HOME": str(root / "home"), "GNUPGHOME": str(root / "gpg"),
               "PASSWORD_STORE_DIR": str(root / "passwords"), "SECRETS_DIR": str(root / "stores"),
               "SECRETS_ENV": str(root / "home/absent"), "TMPDIR": str(root / "tmp"),
               "PATH": os.environ["PATH"], "LC_ALL": "C", "GOTOOLCHAIN": "local",
               "GOCACHE": str(root / "go-cache"), "GOMODCACHE": str(root / "go-mod-cache"), "GITHUB_ACTIONS": "true"}
        env["GOROOT"] = call([go, "env", "GOROOT"], env).decode().strip()
        homes = [root / "gpg", root / "public-gpg"]
        try:
            version = call([str(actual_pass), "version"], env)
            if b"=                  v1.7.4                  =" not in version.splitlines():
                raise RuntimeError("staged pass version mismatch")
            if sys.platform == "darwin":
                platform = prefix / "lib/password-store/platform.sh"
                if ('source "' + str(platform) + '"').encode() not in actual_pass.read_bytes():
                    raise RuntimeError("Darwin pass platform file was not installed")
                getopt = Path(os.environ["SECRET_PASS_GETOPT"]).resolve(strict=True)
                # Prove the installed platform's actual GETOPT choice, not merely presence.
                call(["bash", "-c", 'source "$1"; test "$GETOPT" -ef "$2"; "$GETOPT" -o m -l multiline -- --multiline -- synthetic',
                      "fixture", str(platform), str(getopt)], env)
            # Version output is public tool metadata, never provider output.
            print(call([actual_gpg, "--version"], env).splitlines()[0].decode())
            print(call(["bash", "--version"], env).splitlines()[0].decode())
            print("pass 1.7.4, immutable staged provider verified")
            for uid, password in (("secret-pass-ci@example.invalid", b"\n"),
                                  ("secret-pass-locked@example.invalid", b"synthetic-locked-passphrase\n")):
                call([actual_gpg, "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                      "--quick-generate-key", uid, "default", "default", "0"], env, password)
            recipient = fingerprint(env, "secret-pass-ci@example.invalid")
            locked = fingerprint(env, "secret-pass-locked@example.invalid")
            call([str(actual_pass), "init", recipient], env)
            policy = root / "passwords/.gpg-id"
            call([actual_gpg, "--batch", "--yes", "--local-user", recipient, "--detach-sign",
                  "--output", str(root / "recipient.sig"), str(policy)], env)
            public = call([actual_gpg, "--batch", "--export", recipient], env)
            public_env = dict(env, GNUPGHOME=str(root / "public-gpg"))
            call([actual_gpg, "--batch", "--import"], public_env, public)
            # No protected-key cache from key generation may survive into tests.
            call([gpgconf, "--homedir", str(root / "gpg"), "--kill", "gpg-agent"], env)
            marker = root / "pinentry-launched"
            pinentry = root / "tools/pinentry"
            pinentry.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 1\n")
            pinentry.chmod(0o700)
            (root / "gpg/gpg-agent.conf").write_text("pinentry-program " + str(pinentry) + "\n")
            (root / "gpg/gpg-agent.conf").chmod(0o600)
            argv_log = root / "argv"
            for tool, actual in (("pass", str(actual_pass)), ("gpg", actual_gpg), ("gpg2", actual_gpg)):
                wrapper = root / "tools" / tool
                wrapper.write_text("#!/bin/sh\numask 077\nprintf '%s\\n' \"$@\" >> " +
                                   shlex.quote(str(argv_log)) + "\nexec " + shlex.quote(actual) + ' "$@"\n')
                wrapper.chmod(0o700)
            env["PATH"] = str(root / "tools") + os.pathsep + env["PATH"]
            env.update(SECRET_REQUIRE_PASS="1", SECRET_PASS_TEST_ROOT=str(root),
                       SECRET_PASS_TEST_RECIPIENT=recipient, SECRET_PASS_TEST_LOCKED_RECIPIENT=locked)
            # Gate only isolated children, never the caller's environment.
            test_output = call([go, "test", "-v", "-count=1", "-timeout=5m", "./internal/backend", "./internal/feature", "-run",
                  "^(TestPassIntegration|TestOperatorPassIntegration)$"], env, timeout=600, safe_diagnostics=True)
            if b"--- SKIP:" in test_output:
                raise RuntimeError("required native pass test skipped")
            sys.stdout.buffer.write(test_output)
            # Reuse the repository's trusted PTY helper, never downloaded Python.
            spec = importlib.util.spec_from_file_location("operator_fixture", REPO / "tests/test-operator.py")
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)

            class PassCLI(unittest.TestCase):
                def runTest(self):
                    self.binary, self.env = binary, env
                    ref = "pass:cli-native"
                    value = b"synthetic-native-cli-value"
                    call([binary, "stash", ref, "TOKEN"], env, value + b"\n")
                    output = call([binary, "run", "-f", ref, "--", "/bin/sh", "-c",
                                   'printf "%s" "$TOKEN"; printf "%s" "$TOKEN" >&2'], env)
                    self.assertEqual(output, b"<redacted>", "native run did not redact")
                    document = json.loads(call([binary, "show", "--format=json", ref], env))
                    self.assertEqual(document["stores"][0]["backend"], "pass")
                    refusal = helper.Terminal(self, ["delete", ref, "TOKEN"])
                    refusal.read(b"> ")
                    refusal.send(b"decline\n")
                    refusal.finish(expected=1)
                    terminal = helper.Terminal(self, ["rotate", ref, "TOKEN"])
                    terminal.confirm(("rotate " + ref + " keys=TOKEN").encode())
                    terminal.read(b"New value (hidden): ")
                    terminal.send(b"synthetic-native-cli-rotated\n")
                    self.assertNotIn(b"synthetic-native-cli-rotated", terminal.finish())
                    for args, challenge in ((["rename", ref, "TOKEN", "RENAMED"], "rename " + ref + " keys=TOKEN,RENAMED"),
                                            (["delete", ref, "RENAMED"], "delete " + ref + " keys=RENAMED")):
                        terminal = helper.Terminal(self, args)
                        terminal.confirm(challenge.encode())
                        terminal.finish()

            result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite([PassCLI()]))
            if not result.wasSuccessful():
                raise RuntimeError("native pass CLI integration failed")
            sampled = argv_log.read_bytes()
            for value in (b"synthetic-native-cli-value", b"synthetic-native-cli-rotated",
                          b"synthetic-native-value", b"synthetic-native-operator", b"synthetic-native-rotated"):
                if any(form in sampled for form in (value, value.hex().encode(), base64.b64encode(value))):
                    raise RuntimeError("synthetic value reached sampled provider argv")
            if marker.exists() or (root / "plaintext-artifact").exists():
                raise RuntimeError("GPG configuration or pinentry escaped capture")
            print("PASS: isolated native backend, operator, PTY, config, signing and argv checks")
        finally:
            for home in homes:
                subprocess.run([gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=20, check=False, cwd=REPO)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired, KeyError):
        print("FAIL: isolated pass fixture failed (provider output withheld)", file=sys.stderr)
        sys.exit(1)
