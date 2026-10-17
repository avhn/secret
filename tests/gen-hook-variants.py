#!/usr/bin/env python3
"""Extract synthetic Bash-deny commands without changing the retained suite.

The disposable suite copy captures secrets() assertions and direct envelopes.
Direct envelopes still run the real guard, including dependency-fault wrappers;
inspected command strings are never run.
"""
import collections
import json
import os
import pathlib
import re
import shutil
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
            if name.startswith(".variant-direct."):
                continue  # ephemeral envelope capture is not a fixture
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
    row.setdefault("home", "@TMP@/home")
    text = json.dumps(row, sort_keys=True)
    text = text.replace(str(tmp), "@TMP@").replace(str(ROOT), "@ROOT@")
    # Normalize only configured path metadata, never credential contents.
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
    local input_file capture_expected=deny status=0
    input_file="$("$VARIANT_MKTEMP" "$TMP/.variant-direct.XXXXXX")" || return 1
    "$VARIANT_CAT" >"$input_file" || return 1
    if [[ "${FUNCNAME[1]:-}" == audit20_raw ]]; then capture_expected="$expected"; fi
    "$VARIANT_PYTHON" -I "$VARIANT_GENERATOR" --direct "$TMP" "$VARIANT_ROWS" "$capture_expected" <"$input_file" || return 1
    if [[ "$SECRETS_GUARD" != "$REPO_ROOT/hooks/guard-secrets" ]]; then
        "$BASH" "$SECRETS_GUARD" <"$input_file" || status=$?
    else
        "${GUARD_ARGS[@]}" <"$input_file" || status=$?
    fi
    "$VARIANT_RM" -f "$input_file"
    return "$status"
}''' + source[last:]
    start = source.index("secrets() {")
    end = source.index("\n}", start) + 2
    replacement = '''secrets() {
    local name="$1" want="$2" tool="$3" value="$4" extra="${5:-}"
    [[ -n "$extra" ]] || extra='{}'
    printf '%s' "$value" | jq -csR --arg name "$name" --arg want "$want" --arg tool "$tool" \\
        --arg cwd "$TMP/search" --arg config "${RIPGREP_CONFIG_PATH:-}" \\
        --arg home "$HOME" --arg kubeconfig "${KUBECONFIG:-}" --argjson extra "$extra" \\
        '{name:$name,want:$want,tool:$tool,cwd:$cwd,config:$config,home:$home,kubeconfig:$kubeconfig,command:.,extra:$extra}' |
        "$VARIANT_PYTHON" -I "$VARIANT_GENERATOR" --capture "$TMP" "$VARIANT_ROWS"
    return 0
}'''
    source = source[:start] + replacement + source[end:]
    with tempfile.TemporaryDirectory(prefix="hook-variant-extract-") as directory:
        tmp = pathlib.Path(directory)
        script, rows = tmp / "suite.sh", tmp / "rows.jsonl"
        script.write_text(source)
        env = os.environ.copy()
        env.update(VARIANT_PYTHON=sys.executable, VARIANT_GENERATOR=str(pathlib.Path(__file__).resolve()), VARIANT_ROWS=str(rows),
                   VARIANT_CAT=shutil.which("cat"), VARIANT_MKTEMP=shutil.which("mktemp"),
                   VARIANT_RM=shutil.which("rm"))
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
    raw = sys.stdin.buffer.read()
    if not raw or b"\0" in raw:
        return
    try:
        text = raw.decode("utf-8", errors="strict")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        envelope = json.loads(text, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError, TypeError):
        return
    if not isinstance(envelope, dict) or (len(sys.argv) > 4 and sys.argv[4] == "allow"):
        return
    fields = envelope.get("tool_input")
    if not isinstance(fields, dict):
        return
    command = fields.get("command")
    if envelope.get("tool_name") == "Bash" and isinstance(command, str):
        name = "fixed_complexity_reason" if command == "cat .env '" else "control_byte_" + json.dumps(command, separators=(",", ":"))
        capture(dict(name=name, want="deny", tool="Bash", command=command,
                     cwd=envelope.get("cwd", str(pathlib.Path(sys.argv[2]) / "search")),
                     config=os.environ.get("RIPGREP_CONFIG_PATH", ""),
                     home=os.environ.get("HOME", ""), kubeconfig=os.environ.get("KUBECONFIG", ""),
                     extra={key: value for key, value in fields.items() if key != "command"}))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--capture":
        capture()
    elif len(sys.argv) > 1 and sys.argv[1] == "--direct":
        direct()
    else:
        generate()
