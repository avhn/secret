#!/usr/bin/env python3
"""Extract synthetic Bash-deny commands without changing the retained suite.

The disposable suite copy replaces only its secrets() assertion function. Setup
still constructs the same fixtures; inspected command strings are never run.
"""
import collections
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def capture(row=None):
    """Record deny metadata and bounded synthetic config and gitfile contents."""
    tmp, output = map(pathlib.Path, sys.argv[2:4])
    if row is None:
        row = json.load(sys.stdin)
    if row["want"] != "deny" or row["tool"] != "Bash":
        return
    fixtures = []
    for directory, dirs, files in os.walk(tmp, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            item = pathlib.Path(directory) / name
            relative = item.relative_to(tmp).as_posix()
            if item.is_symlink():
                target = os.readlink(item)
                # Tool shims point outside the synthetic tree, never follow them.
                if target.startswith("/") and not target.startswith(str(tmp)):
                    continue
                fixtures.append([relative, "link", target.replace(str(tmp), "@TMP@")])
            elif item.is_dir():
                fixtures.append([relative, "dir" if item.stat().st_mode & 0o500 else "unreadable-dir", ""])
            else:
                data = ""
                if ("config" in name or name == ".git") and item.stat().st_size <= 9000:
                    try:
                        data = item.read_bytes().decode()
                    except PermissionError:
                        fixtures.append([relative, "unreadable", ""])
                        continue
                fixtures.append([relative, "file", data])
    row["fixtures"] = fixtures
    row["home"] = "@TMP@/home"
    text = json.dumps(row, sort_keys=True)
    text = text.replace(str(tmp), "@TMP@").replace(str(ROOT), "@ROOT@")
    # Only HOME's pathname is normalized; no environment values are collected.
    text = text.replace(os.path.expanduser("~"), "@TMP@/home")
    with output.open("a") as stream:
        stream.write(text + "\n")


def generate():
    """Run synthetic setup and emit a deterministic, deduplicated corpus."""
    output = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "testdata/hook/denied-commands.json")
    source = (ROOT / "tests/test-guard.sh").read_text()
    source = re.sub(r'^REPO_ROOT=.*$', 'REPO_ROOT=' + str(ROOT), source, count=1, flags=re.M)
    first = source.index("invoke_guard() {")
    last = source.index("\n}", first) + 2
    source = source[:first] + '''invoke_guard() {
    "$VARIANT_PYTHON" -I "$VARIANT_GENERATOR" --direct "$TMP" "$VARIANT_ROWS"
}''' + source[last:]
    start = source.index("secrets() {")
    end = source.index("\n}", start) + 2
    replacement = '''secrets() {
    local name="$1" want="$2" tool="$3" value="$4" extra="${5:-}"
    [[ -n "$extra" ]] || extra='{}'
    printf '%s' "$value" | jq -csR --arg name "$name" --arg want "$want" --arg tool "$tool" \\
        --arg cwd "$TMP/search" --arg config "${RIPGREP_CONFIG_PATH:-}" --argjson extra "$extra" \\
        '{name:$name,want:$want,tool:$tool,cwd:$cwd,config:$config,command:.,extra:$extra}' |
        "$VARIANT_PYTHON" -I "$VARIANT_GENERATOR" --capture "$TMP" "$VARIANT_ROWS"
    return 0
}'''
    source = source[:start] + replacement + source[end:]
    with tempfile.TemporaryDirectory(prefix="hook-variant-extract-") as directory:
        tmp = pathlib.Path(directory)
        script, rows = tmp / "suite.sh", tmp / "rows.jsonl"
        script.write_text(source)
        env = os.environ.copy()
        env.update(VARIANT_PYTHON=sys.executable, VARIANT_GENERATOR=str(pathlib.Path(__file__).resolve()), VARIANT_ROWS=str(rows))
        run = subprocess.run(["bash", str(script)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
        if run.returncode or not rows.exists():
            raise SystemExit(run.stderr + run.stdout[-2000:])
        cases, snapshots, indices = [], [], {}
        seen = collections.Counter()
        for line in rows.read_text().splitlines():
            row = json.loads(line)
            seen[row["name"]] += 1
            if seen[row["name"]] > 1:
                row["name"] += f"#{seen[row['name']]}"
            fixtures = row.pop("fixtures")
            key = json.dumps(fixtures, sort_keys=True)
            if key not in indices:
                indices[key] = len(snapshots)
                snapshots.append(fixtures)
            row["snapshot"] = indices[key]
            row.pop("want")
            row.pop("tool")
            cases.append(row)
        audit = json.loads((ROOT / "testdata/hook/audit-cases.json").read_text())
        audit_index = len(snapshots)
        snapshots.append(audit["fixtures"])
        for row in audit["cases"]:
            if row["tool"] != "Bash":
                continue
            command = row["fields"]["command"]
            if not isinstance(command, str):
                continue  # argv forms are covered through the JSON audit test
            cases.append(dict(name=row["name"], command=command, cwd=row["cwd"],
                              home="@TMP@/home", config="@ROOT@/examples/ripgreprc",
                              extra={}, snapshot=audit_index))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"cases": cases, "snapshots": snapshots}, indent=2, sort_keys=True) + "\n")
        print(f"extracted {len(cases)} Bash-deny cases, {len(snapshots)} fixture snapshots")


def direct():
    """Extract direct JSON assertions omitted by the suite's secrets() helper."""
    raw = sys.stdin.read()
    if not raw:
        return
    try:
        envelope = json.loads(raw)
    except (ValueError, TypeError):
        envelope = {}
    command = envelope.get("tool_input", {}).get("command")
    if envelope.get("tool_name") == "Bash" and isinstance(command, str):
        name = "fixed_complexity_reason" if command == "cat .env '" else "control_byte_" + json.dumps(command, separators=(",", ":"))
        capture(dict(name=name, want="deny", tool="Bash", command=command,
                     cwd=envelope.get("cwd", str(pathlib.Path(sys.argv[2]) / "search")),
                     config=os.environ.get("RIPGREP_CONFIG_PATH", ""), extra={}))
    reason = "command too complex to analyse for secret access; split it or use secret run"
    if isinstance(command, str) and len(command) > 8192:
        reason = "command too complex to analyse for secret access; split the command or use secret run"
    print(json.dumps({"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": reason}}))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--capture":
        capture()
    elif len(sys.argv) > 1 and sys.argv[1] == "--direct":
        direct()
    else:
        generate()
