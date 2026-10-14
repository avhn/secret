#!/usr/bin/env python3
"""Classify synthetic Go-hook differences without changing the checked inventory."""
import collections
import os
import pathlib
import re
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
suite, binary, host = sys.argv[1:]
if (suite, host) not in (("guard", "claude"), ("codex", "codex")):
    raise SystemExit("usage: trial-go-hook.py guard|codex ABSOLUTE_BINARY claude|codex")
if not pathlib.Path(binary).is_absolute():
    raise SystemExit("absolute binary required")
with tempfile.TemporaryDirectory(prefix="go-hook-trial-") as tmp:
    tmp = pathlib.Path(tmp)
    results, times = tmp / "results", tmp / "times"
    env = os.environ.copy()
    env.update(SECRET_GUARD=f"python3 -I {root}/tests/measure-go-hook.py {binary} {host} {times}",
               SECRET_TEST_RESULTS=str(results))
    run = subprocess.run(["bash", str(root / "tests" / f"test-{suite}.sh")],
                         cwd=root, env=env, capture_output=True, text=True, check=False)
    inventory = root / "testdata" / "inventory" / f"{suite}.tsv"
    if sys.platform == "darwin" and inventory.with_name(f"{suite}.darwin.tsv").exists():
        inventory = inventory.with_name(f"{suite}.darwin.tsv")
    expected = {}
    seen = collections.Counter()
    for line in inventory.read_text().splitlines():
        item, name, role, decision = line.split("\t")
        if item == suite:
            seen[name] += 1
            key = name if seen[name] == 1 else f"{name}#{seen[name]}"
            expected[key] = decision
    groups = collections.defaultdict(collections.Counter)
    false_allows = []
    false_denies = []
    actual = {}
    seen.clear()
    for line in results.read_text().splitlines():
        item, name, status = line.split("\t")
        if item != suite:
            continue
        seen[name] += 1
        key = name if seen[name] == 1 else f"{name}#{seen[name]}"
        actual[key] = status
        if status == "fail":
            group = re.split(r"[_#]", name)[0]
            groups[group]["false_allow" if expected.get(key) == "deny" else "false_deny"] += 1
            if expected.get(key) == "deny":
                false_allows.append(key)
            else:
                false_denies.append(key)
    samples = [float(n) for n in times.read_text().splitlines()] if times.exists() else []
    samples.sort()
    if samples:
        p99 = samples[max(0, (99 * len(samples) + 99) // 100 - 1)]
        print(f"{suite}: {len(samples)} timed decisions, p99 {p99:.3f} ms")
    print(f"{suite}: false_allow={sum(c['false_allow'] for c in groups.values())} "
          f"false_deny={sum(c['false_deny'] for c in groups.values())}")
    for group, counts in sorted(groups.items(), key=lambda pair: (-pair[1]["false_allow"], pair[0])):
        print(f"  {group}: allow={counts['false_allow']} deny={counts['false_deny']}")
    if os.environ.get("TRIAL_DETAILS"):
        print("  false-allow cases: " + ", ".join(false_allows))
        print("  false-deny cases: " + ", ".join(false_denies))
    if set(expected) != set(actual):
        print("suite inventory mismatch", file=sys.stderr)
        raise SystemExit(1)
    if not re.search(r"(?m)^\d+ passed, \d+ failed", run.stdout):
        print(run.stdout[-1000:], file=sys.stderr)
        raise SystemExit(1)
    if run.returncode and not groups:
        print("suite failed without classified cases", file=sys.stderr)
        raise SystemExit(1)
