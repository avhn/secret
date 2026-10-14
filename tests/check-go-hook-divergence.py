#!/usr/bin/env python3
"""Check exact per-case Go hook divergences and suite totals, without value text."""
import collections
import pathlib
import re
import sys

suite, inventory_path, results_path, divergence_path, log_path = sys.argv[1:]


def rows(path, columns):
    """Read a fixed-width tabular inventory without interpreting fields."""
    result = []
    for line in pathlib.Path(path).read_text().splitlines():
        fields = line.split("\t")
        if len(fields) != columns:
            raise ValueError(f"invalid row in {path}")
        result.append(fields)
    return result


def check():
    """Require every assertion and every expected failure to match once."""
    inventory = {name for item, name, _, _ in rows(inventory_path, 4) if item == suite}
    expected = {}
    for item, name, category in rows(divergence_path, 3):
        if category not in ("pending-M2-ast", "pending-M2-search", "pending-M2-paths", "tightening", "deliberate-tightening"):
            raise ValueError(f"invalid category: {item}/{name}")
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
    summary = re.search(r"(?m)^(\d+) passed, (\d+) failed", pathlib.Path(log_path).read_text())
    if not summary or (int(summary[1]), int(summary[2])) != (
        sum(v == "pass" for v in actual.values()), sum(v == "fail" for v in actual.values())
    ):
        failures.append(f"suite totals do not match recorded cases: {suite}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"{suite}: {len(inventory) - len(expected)} passed, {len(expected)} divergent")
    return 0


try:
    sys.exit(check())
except (OSError, ValueError) as error:
    print(error, file=sys.stderr)
    sys.exit(1)
