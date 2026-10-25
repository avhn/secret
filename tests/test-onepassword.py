#!/usr/bin/env python3
"""Offline fake-op orchestration. No installed op, account or network is used."""

import errno
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def main():
    root = Path(__file__).resolve().parent.parent
    go = shutil.which("go")
    if not go:
        raise SystemExit("FAIL: Go executable missing")
    with tempfile.TemporaryDirectory(prefix="secret-onepassword-") as directory:
        # Allowlist only build configuration, never ambient OP variables or tokens.
        environment = {
            name: os.environ[name]
            for name in ("PATH", "GOROOT", "GOTOOLCHAIN", "TMPDIR", "GOCACHE", "GOPATH")
            if name in os.environ
        }
        environment["HOME"] = directory
        environment["GOTOOLCHAIN"] = "local"
        subprocess.run(
            [go, "test", "-count=1", "./internal/store", "./internal/backend",
             "./internal/feature", "./internal/cli", "-run", "ManifestV2|OnePassword"],
            cwd=root, env=environment, check=True,
        )
        if os.name != "posix":
            print("SKIP: controlling-terminal case requires Unix PTYs")
            return
        import pty

        environment["SECRET_ONEPASSWORD_PTY_PARENT"] = "1"
        pid, master = pty.fork()
        if pid == 0:
            os.chdir(root)
            os.execve(go, [go, "test", "-count=1", "./internal/backend", "-run",
                           "^TestOnePasswordFakeTTY$"], environment)
        output = bytearray()
        deadline = time.monotonic() + 180
        status = None
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(master, 8192)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > 1 << 20:
                        raise RuntimeError("PTY test output exceeded bound")
                child, candidate = os.waitpid(pid, os.WNOHANG)
                if child:
                    status = candidate
                    break
            else:
                raise RuntimeError("PTY test deadline exceeded")
            if status is None:
                _, status = os.waitpid(pid, 0)
            sys.stdout.buffer.write(output)
            if os.waitstatus_to_exitcode(status) != 0:
                raise RuntimeError("PTY no-controlling-terminal assertion failed")
        finally:
            os.close(master)
            if status is None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
        print("PASS: fake-op matrix and detached provider under a PTY parent")


if __name__ == "__main__":
    main()
