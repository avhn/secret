#!/usr/bin/env python3
"""Require exact inventory and known Go failures; print case names, never values."""
import collections
import pathlib
import sys

suite, inventory_path, results_path, divergence_path = sys.argv[1:]

def rows(path, columns):
    result = []
    for line in pathlib.Path(path).read_text().splitlines():
        fields = line.split("\t")
        if len(fields) != columns:
            raise ValueError(f"invalid row in {path}")
        result.append(fields)
    return result

try:
    inventory = {name for item, name, _, _ in rows(inventory_path, 4) if item == suite}
    expected = {}
    for item, name, category in rows(divergence_path, 3):
        if category not in ("no-pty", "windows", "pending-M2", "deliberate"):
            raise ValueError(f"invalid reason category: {item}/{name}")
        if item == suite:
            if name in expected:
                raise ValueError(f"duplicate divergence: {item}/{name}")
            expected[name] = category
    counts = collections.Counter()
    actual = {}
    for item, name, status in rows(results_path, 3):
        if item != suite or status not in ("pass", "fail"):
            raise ValueError(f"invalid result: {item}/{name}")
        counts[name] += 1
        numbered = name if counts[name] == 1 else f"{name}#{counts[name]}"
        actual[numbered] = status
    failures = []
    for name in sorted(inventory | set(actual) | set(expected)):
        if name not in inventory or name not in actual:
            failures.append(f"missing or extra case: {suite}/{name}")
        elif name in expected and actual[name] == "pass":
            failures.append(f"listed divergence now passes: {suite}/{name}")
        elif name not in expected and actual[name] == "fail":
            failures.append(f"unlisted divergence: {suite}/{name}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        sys.exit(1)
    print(f"{suite}: {len(inventory) - len(expected)} passed, {len(expected)} divergent")
except (OSError, ValueError) as error:
    print(error, file=sys.stderr)
    sys.exit(1)
