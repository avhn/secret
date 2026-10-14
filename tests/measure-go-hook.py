#!/usr/bin/env python3
"""Time one synthetic hook decision and pass its bytes through unchanged."""
import pathlib
import subprocess
import sys
import time

binary, host, timing_path = sys.argv[1:]
payload = sys.stdin.buffer.read()
start = time.monotonic_ns()
result = subprocess.run([binary, "hook", host], input=payload, capture_output=True, check=False)
end = time.monotonic_ns()
with pathlib.Path(timing_path).open("a", encoding="ascii") as timing:
    timing.write(f"{(end - start) / 1_000_000:.3f}\n")
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
