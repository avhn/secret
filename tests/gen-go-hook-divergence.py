#!/usr/bin/env python3
"""Regenerate exact default-hook differences, refusing unreviewed categories.

Both retained shell suites run unchanged. Audit envelopes also compare the
retained Bash guard and the supplied Go binary over disposable synthetic files.
Every output row must name a case in the checked tightening table.
"""
import collections
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIND_SHIMS = {"grep_find_exit", "grep_find_exit_count", "rg_find_exit", "grep_timeout", "grep_timeout_count", "rg_timeout", "git_grep_timeout"}
# This preprocessing fault is exercised by both host suites; Go never runs jq.
PREPROCESS_SHIMS = {"audit27_s4_preanalysis_deadline"}
# M2.1 rejects empty updates (including the body-free project Yarn fixture)
# and native patch-header controls. Valid implicit first chunks need no exception.
CODEX_TIGHTENING = {"cwd_safe", "audit19_allow#14", "audit19_allow#15", "audit19_allow#16", "audit19_allow#17",
                    "audit27_s22_move", "audit27_s22_crlf", "audit19_yarn_project_patch"}
# Existing Go path-field controls remain stricter than Bash's valid LF paths.
ENVELOPE_TIGHTENING = {"audit23_o8_workdir_newline", "audit23_o8_cwd_newline"}
# Audit 28 retains Go's conservative arithmetic and function/time framing denials.
# These exact public controls are stricter than Bash, never exceptions for allows.
AUDIT28_TIGHTENING = {"audit28_t13_compound_time_end_public"} | {
    "audit28_t13_review_" + name + "_public" + suffix
    for name in ("function", "function_index", "quoted_number", "single_quoted_number",
                 "quoted_index", "quoted_loop", "quoted_child")
    for suffix in ("", "_argv")
}
# Exact harmless controls retained by Bash, reviewed in hook-tightening.md.
# These are not protected-read, malformed-shell or budget exceptions.
AUDIT29_BASH_OVER_DENIAL = {
    "audit29_u22_" + name + suffix
    for name in ("unknown_type", "metadata_write") for suffix in ("", "_argv")
}
AUDIT29_TIGHTENING = {"audit29_u22_fd_type_attached", "audit29_u22_fd_type_attached_argv"}
TIGHTENING = {"malformed_json", "malformed_sensitive", "active_safe_command", "unresolved_file_safe", "unresolved_positional_safe", "unresolved_listing_safe", "unresolved_wc_safe", "unresolved_redirect_safe", "unresolved_xargs_safe", "unresolved_literal_safe", "unresolved_no_eval", "unknown_timeout_safe", "unknown_nice_safe", "unknown_stdbuf_safe", "unknown_caffeinate_safe", "unknown_xargs_safe", "unknown_exec_safe", "sudo_unknown_safe", "audit6_sed_comment", "audit6_sed_text_line", "audit6_sed_insert_line", "audit6_sed_change_line", "policy_v2_sed_script_clean", "no_file", "env_chdir_empty", "audit15_r7_success", "audit15_r1_data#12", "audit15_r1_data#13"}


def suite_rows(suite, binary, host, tmp):
    """Classify measured suite failures against an explicit reviewed allowlist."""
    results = tmp / f"{suite}.tsv"
    env = os.environ.copy()
    env.update(SECRET_GUARD=f"{binary} hook {host}", SECRET_TEST_RESULTS=str(results))
    # Bound the entire synthetic suite separately from each hook's budgets;
    # concurrent worker checkouts can exceed four minutes of suite wall time.
    run = subprocess.run(["bash", str(ROOT / "tests" / f"test-{suite}.sh")], cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
    if not re.search(r"(?m)^\d+ passed, \d+ failed", run.stdout):
        raise ValueError(f"{suite}: suite did not finish")
    inventory = ROOT / "testdata/inventory" / f"{suite}.tsv"
    if platform.system() == "Darwin" and inventory.with_name(f"{suite}.darwin.tsv").exists():
        inventory = inventory.with_name(f"{suite}.darwin.tsv")
    expected = {name: decision for item, name, _, decision in (line.split("\t") for line in inventory.read_text().splitlines()) if item == suite}
    seen, actual, rows = collections.Counter(), set(), []
    for line in results.read_text().splitlines():
        item, name, status = line.split("\t")
        seen[name] += 1
        key = name if seen[name] == 1 else f"{name}#{seen[name]}"
        if item != suite or key not in expected or status not in ("pass", "fail"):
            raise ValueError(f"invalid result: {item}/{key}")
        actual.add(key)
        if status == "fail":
            if expected[key] == "deny" and (key in PREPROCESS_SHIMS or suite == "guard" and key in FIND_SHIMS):
                category = "deliberate-find-shim"
            elif expected[key] == "deny" and key in AUDIT29_BASH_OVER_DENIAL:
                category = "reviewed-bash-over-denial"
            elif expected[key] == "allow" and (key in ENVELOPE_TIGHTENING or key in AUDIT28_TIGHTENING or key in AUDIT29_TIGHTENING or
                                                (suite == "guard" and key in TIGHTENING) or
                                                (suite == "codex" and key in CODEX_TIGHTENING)):
                category = "deliberate-tightening"
            else:
                raise ValueError(f"unreviewed difference: {suite}/{key}")
            rows.append((suite, key, category))
    if actual != set(expected):
        raise ValueError(f"{suite}: inventory mismatch")
    print(f"{suite}: {len(actual)} assertions, {len(rows)} reviewed differences")
    return rows


def decision(argv, payload, env):
    """Require an empty allow or valid denial JSON without logging inputs."""
    run = subprocess.run(argv, cwd=ROOT, input=json.dumps(payload), env=env, capture_output=True, text=True, timeout=5)
    if run.returncode:
        raise ValueError("audit hook failed")
    if not run.stdout.strip():
        return "allow"
    result = json.loads(run.stdout)
    if result.get("hookSpecificOutput", {}).get("permissionDecision") != "deny":
        raise ValueError("invalid audit hook output")
    return "deny"


def audit_rows(binary, tmp):
    """Measure all audit reproducers using metadata-only synthetic fixtures."""
    corpus = json.loads((ROOT / "testdata/hook/audit-cases.json").read_text())
    for name, kind, value in corpus["fixtures"]:
        target = tmp / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if kind == "dir":
            target.mkdir(exist_ok=True)
        elif kind == "link":
            target.symlink_to(value)
        else:
            target.write_text(value)
    env = os.environ.copy()
    env.update(HOME=str(tmp / "home"), RIPGREP_CONFIG_PATH=str(ROOT / "examples/ripgreprc"))
    rows = []
    for row in corpus["cases"]:
        payload = dict(tool_name=row["tool"], cwd=row["cwd"].replace("@TMP@", str(tmp)), tool_input=row["fields"])
        go = decision([binary, "hook", "claude"], payload, env)
        bash = decision([str(ROOT / "hooks/guard-secrets")], payload, env)
        if go != "deny":
            raise ValueError(f"audit false allow: {row['name']}")
        if bash != go:
            rows.append(("audit", row["name"], "deliberate-tightening"))
    print(f"audit: {len(corpus['cases'])} denied by Go, {len(rows)} stricter than Bash")
    return rows


def audit19_rows(binary, tmp):
    """Check mixed audit 19 outcomes and reject every Go-looser decision."""
    text = (ROOT / "testdata/hook/audit19.json").read_text()
    corpus = json.loads(text.replace("@TMP@", tmp.as_posix()))
    for name, kind, value in corpus["fixtures"]:
        target = tmp / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if kind == "dir":
            target.mkdir(exist_ok=True)
        else:
            target.write_text(value)
    rows = []
    for row in corpus["cases"]:
        env = os.environ.copy()
        env.update(HOME=str(tmp / "home"), RIPGREP_CONFIG_PATH="", KUBECONFIG="")
        settings = row.get("env", {})
        env["KUBECONFIG"] = settings.get("KUBECONFIG", "")
        if "KUBECONFIG_LIST" in settings:
            env["KUBECONFIG"] = os.pathsep.join(settings["KUBECONFIG_LIST"])
        payload = dict(tool_name=row["tool"], cwd=row["cwd"], tool_input=row["fields"])
        go = decision([binary, "hook", "claude"], payload, env)
        bash = decision([str(ROOT / "hooks/guard-secrets")], payload, env)
        expected = "deny" if row["deny"] else "allow"
        if go != expected:
            raise ValueError(f"audit19 unexpected Go outcome: {row['name']}")
        if go == "allow" and bash == "deny":
            raise ValueError(f"audit19 Go-looser outcome: {row['name']}")
        if go != bash:
            rows.append(("audit", "audit19_" + row["name"], "deliberate-tightening"))
    print(f"audit19: {len(corpus['cases'])} expected Go outcomes, {len(rows)} stricter than Bash")
    return rows


def m21_u2_u3_rows(binary, tmp):
    """Retain exact malformed coprocess and uncertified patch-stream denials."""
    corpus = json.loads((ROOT / "testdata/hook/m21-u2-u3.json").read_text())
    (tmp / "home").mkdir(parents=True)
    (tmp / ".env").write_text("synthetic\n")
    env = os.environ.copy()
    env.update(HOME=str(tmp / "home"), RIPGREP_CONFIG_PATH="", KUBECONFIG="")
    rows = []
    for case in corpus:
        for suffix, command in (("", case["source"]), ("_argv", ["bash", "-c", case["source"]])):
            payload = dict(tool_name="Bash", cwd=str(tmp), tool_input=dict(command=command))
            for host in ("claude", "codex"):
                if decision([binary, "hook", host], payload, env) != "deny":
                    raise ValueError(f"m21 false allow: {case['name']}{suffix}/{host}")
            bash = decision([str(ROOT / "hooks/guard-secrets")], payload, env)
            if bash != "deny":
                rows.append(("audit", case["name"] + suffix, "deliberate-tightening"))
    print(f"m21 U2/U3: {len(corpus) * 4} denied Go envelopes, {len(rows)} stricter than Bash")
    return rows


def main():
    """Write the inventory only after every measured row is reviewed in docs."""
    if len(sys.argv) != 2 or not pathlib.Path(sys.argv[1]).is_absolute():
        raise ValueError("usage: gen-go-hook-divergence.py ABSOLUTE_BINARY")
    with tempfile.TemporaryDirectory(prefix="hook-divergence-") as directory:
        tmp = pathlib.Path(directory)
        rows = suite_rows("guard", sys.argv[1], "claude", tmp)
        rows += suite_rows("codex", sys.argv[1], "codex", tmp)
        rows += audit_rows(sys.argv[1], tmp / "audit")
        rows += audit19_rows(sys.argv[1], tmp / "audit19")
        rows += m21_u2_u3_rows(sys.argv[1], tmp / "m21-u2-u3")
    table = (ROOT / "docs/design/hook-tightening.md").read_text()
    missing = [f"{suite}/{name}" for suite, name, _ in rows if f"`{name}`" not in table]
    if missing:
        raise ValueError("tightening-table rows required: " + ", ".join(missing))
    output = "".join("\t".join(row) + "\n" for row in sorted(rows))
    (ROOT / "testdata/inventory/go-hook-divergence.tsv").write_text(output)
    print(f"wrote {len(rows)} exact reviewed divergence rows")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from error
