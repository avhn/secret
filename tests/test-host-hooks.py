#!/usr/bin/env python3
"""Deferred real-host gate and offline classification tests. Never print raw sessions.

No arguments runs synthetic unit tests only. --hosted requires a GitHub-hosted
runner and a fresh disposable root; it never authenticates or installs on a host
machine. Unknown stream shapes, missing controls and trust failures are incomplete.
"""

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

FIXTURE_BINARY = None

CLAUDE_VERSION = "2.1.295"
CODEX_VERSION = "0.163.0"
PLUGIN_NAME = "secret-host-fixture"
CASES = ("missing-launcher", "failed-launcher", "nonexecutable-launcher",
         "missing-binary", "exec-format", "exit1", "fatal", "signal",
         "malformed", "schema", "timeout", "deny", "neutral", "empty", "retained")
FAILURES = set(CASES) - {"neutral", "empty", "retained"}
STARTUP_FAILURES = {"missing-launcher", "failed-launcher", "nonexecutable-launcher",
                    "missing-binary", "exec-format"}
ROOT = Path(__file__).resolve().parents[1]
HOOK_FAILURE = re.compile(
    r"(?:hook.*(?:error|fail|block|timed out|invalid|denied)|"
    r"secret: synthetic host fixture denial)", re.I | re.S)
MAX_STREAM = 4 * 1024 * 1024


def decode_stream(raw):
    """Strict JSONL parsing, with no content included in errors or evidence."""
    if len(raw) > MAX_STREAM:
        raise ValueError("stream exceeded bound")
    events = []
    for line in raw.splitlines():
        if line.strip():
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("non-object event")
            events.append(event)
    return events


def summarize(host, events, target):
    """Normalize only host-authored tool events, never assistant narrative claims."""
    facts = {"loaded": False, "attempted": False, "success": False,
             "hook_failure": False, "finished": False, "outage": False}
    if host == "claude":
        ids = set()
        for event in events:
            if event.get("type") == "system" and event.get("subtype") == "init":
                facts["loaded"] = any(p.get("name") == PLUGIN_NAME
                                      for p in event.get("plugins", []) if isinstance(p, dict))
                if event.get("plugin_errors"):
                    facts["outage"] = True
            if event.get("type") == "system" and event.get("subtype") == "api_retry":
                facts["outage"] = True
            if event.get("type") == "result":
                facts["finished"] = not event.get("is_error", False) and event.get("subtype") == "success"
                facts["outage"] |= bool(event.get("is_error", False))
            # A subagent or a model's final text cannot supply tool evidence.
            if event.get("parent_tool_use_id") is not None:
                continue
            content = event.get("message", {}).get("content", [])
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if event.get("type") == "assistant" and block.get("type") == "tool_use":
                    if block.get("name") == target["tool"] and block.get("input") == target["input"]:
                        if isinstance(block.get("id"), str):
                            ids.add(block["id"])
                            facts["attempted"] = True
                if (event.get("type") == "user" and block.get("type") == "tool_result"
                        and block.get("tool_use_id") in ids):
                    failed = block.get("is_error") is True
                    facts["success"] |= not failed or (target["tool"] == "Read" and
                        "synthetic-read-witness-4821" in json.dumps(block.get("content", "")))
                    facts["hook_failure"] |= failed and bool(HOOK_FAILURE.search(
                        json.dumps(block.get("content", ""))))
    else:
        # Codex exec does not guarantee attempted-but-blocked tools are emitted.
        # A missing item must remain incomplete, not be inferred from prose.
        for event in events:
            kind = event.get("type")
            if kind in ("error", "turn.failed"):
                facts["outage"] = True
            if kind == "turn.completed":
                facts["finished"] = True
            item = event.get("item", {})
            if kind not in ("item.started", "item.completed") or not isinstance(item, dict):
                continue
            if item.get("type") == "command_execution" and target["tool"] == "Bash":
                if item.get("command") == target["input"]["command"]:
                    facts["attempted"] = True
                    facts["success"] |= kind == "item.completed" and item.get("exit_code") == 0
                    facts["hook_failure"] |= bool(HOOK_FAILURE.search(item.get("aggregated_output", "")))
            if item.get("type") == "file_change" and target["tool"] == "apply_patch":
                if any(c.get("path") == target["path"] for c in item.get("changes", [])):
                    facts["attempted"] = True
                    facts["success"] |= item.get("status") == "completed"
                    facts["hook_failure"] |= bool(HOOK_FAILURE.search(item.get("error", "")))
    return facts


def classify(host, events, target, case, observed, control_ok):
    """Fail on execution, incomplete on absent proof, pass only positive evidence."""
    if case in FAILURES and observed.get("executed", False):
        return "FAIL", "tool executed after hook fault"
    facts = summarize(host, events, target)
    # A startup fault cannot record its envelope, so witness the hook shell
    # before attempting the launcher. Neither witness establishes Codex trust.
    dispatched = observed.get("dispatch", False) or (
        case in STARTUP_FAILURES and observed.get("pre_exec_dispatch", False))
    loaded = facts["loaded"] if host == "claude" else dispatched
    executed = facts["success"] or observed.get("executed", False)
    if case in FAILURES and executed:
        return "FAIL", "tool executed after hook fault"
    if not control_ok:
        return "INCOMPLETE", "identical healthy control missing"
    if observed.get("timeout") or observed.get("returncode") != 0 or facts["outage"]:
        return "INCOMPLETE", "host session or authentication unavailable"
    if (not loaded or not observed.get("probe")
            or (case not in STARTUP_FAILURES and not observed.get("dispatch"))):
        return "INCOMPLETE", "plugin or hook dispatch not established"
    if not facts["attempted"] or not facts["finished"]:
        return "INCOMPLETE", "matching tool attempt or completed session missing"
    if case in FAILURES:
        if facts["hook_failure"]:
            return "PASS", "hook failure reported; tool execution absent"
        return "INCOMPLETE", "host-authored hook failure evidence missing"
    if facts["success"] and (target["tool"] == "Read" or observed.get("executed", False)):
        return "PASS", "healthy request executed"
    return "INCOMPLETE", "healthy request did not execute"


def classify_stream(host, raw, target, case, observed, control_ok):
    """Malformed output cannot erase an independent execution witness."""
    events = []
    try:
        events = decode_stream(raw)
        status, reason = classify(host, events, target, case, observed, control_ok)
    except (ValueError, TypeError, AttributeError):
        if case in FAILURES and observed.get("executed", False):
            status, reason = "FAIL", "tool executed after hook fault"
        else:
            status, reason = "INCOMPLETE", "unrecognized or malformed structured stream"
    return events, status, reason


def private_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def bounded_process(args, cwd, env, timeout=90):
    """Keep raw output in disposable private scratch only, with a size ceiling."""
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        process = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=error, start_new_session=True)
        timed_out = False
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if (time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > MAX_STREAM
                        or os.fstat(error.fileno()).st_size > MAX_STREAM):
                    timed_out = True
                    break
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    continue
        finally:
            # Also reap background descendants after an ordinary host exit.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        output.seek(0)
        raw = output.read(MAX_STREAM + 1)
    return raw, process.returncode, timed_out


def shell_command(fixture, mode, record, binary):
    return " ".join(shlex.quote(str(x)) for x in (fixture, mode, record, binary))


def make_target(operation, work):
    witness = work / "witness.txt"
    if operation == "Bash":
        command = "printf '%s\\n' host-hook-witness > " + shlex.quote(str(witness))
        data = {"command": command}
    elif operation == "Read":
        data = {"file_path": str(witness)}
    elif operation == "Write":
        data = {"file_path": str(witness), "content": "host-hook-witness\n"}
    elif operation == "Edit":
        data = {"file_path": str(witness), "old_string": "before", "new_string": "after"}
    else:
        data = {"command": "*** Begin Patch\n*** Add File: " + str(witness)
                + "\n+host-hook-witness\n*** End Patch"}
    return {"tool": operation, "input": data, "path": str(witness)}


def reset_witness(target):
    path = Path(target["path"])
    path.unlink(missing_ok=True)
    if target["tool"] == "Read":
        path.write_text("synthetic-read-witness-4821\n", encoding="utf-8")
    if target["tool"] == "Edit":
        path.write_text("before\n", encoding="utf-8")


def execution_witness(target):
    path = Path(target["path"])
    if target["tool"] == "Read":
        return False  # Only a structured successful tool result proves a read.
    if target["tool"] == "Edit":
        return not path.exists() or path.read_bytes() != b"before\n"
    return path.exists()


def install_fixture_cache(root, plugin, checkout, fixture, env):
    """Use item 3's installer/launcher with an explicitly unshipped native asset."""
    for relative in ("hooks/guard-go", "scripts/install-release.sh"):
        source = checkout / relative
        destination = plugin / relative
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o700)
    marker = plugin / ".secret-release-test-fixture"
    marker.write_bytes(b"")
    marker.chmod(0o600)
    assets = plugin / "assets"
    assets.mkdir(mode=0o700)
    manifest_dir = plugin / "dist"
    manifest_dir.mkdir(mode=0o700)
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    os_name = {"Linux": "linux", "Darwin": "darwin"}[platform.system()]
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
    native = "secret-v0.3.3-" + os_name + "-" + arch
    shutil.copyfile(fixture, assets / native)
    (assets / native).chmod(0o700)
    # The compiled-in 0.3.3 grammar requires all eight sorted payload names.
    names = sorted(["secret-v0.3.3-" + system + "-" + machine
                    for system in ("linux", "darwin") for machine in ("amd64", "arm64")]
                   + ["secret-v0.3.3-windows-amd64.exe", "secret-v0.3.3-windows-arm64.exe",
                      "secret-v0.3.3-desktop.mcpb", "server.json"])
    manifest = manifest_dir / "checksums-v0.3.3.txt"
    manifest.write_text("".join((digest if name == native else "0" * 64)
                                + "  " + name + "\n" for name in names), encoding="utf-8")
    manifest.chmod(0o600)
    env["SECRET_RELEASE_TEST_ROOT"] = str(root / "fixture-cache")
    installed = subprocess.run([str(plugin / "scripts/install-release.sh"), "--offline", "--from-dir", str(assets)],
                               env=env, cwd=plugin, capture_output=True, timeout=30, check=False)
    if installed.returncode:
        raise ValueError("disposable verified fixture installation failed: " + installed.stderr.decode(errors="replace"))


def configure_fixture(root, checkout, fixture, binary, host, case, env=None):
    """Modify disposable plugin copies only, leaving checkout policy untouched."""
    plugin = root / "plugin"
    shutil.rmtree(plugin, ignore_errors=True)
    plugin.mkdir(mode=0o700)
    (plugin / ".claude-plugin").mkdir(mode=0o700)
    (plugin / "hooks").mkdir(mode=0o700)
    private_json(plugin / ".claude-plugin/plugin.json", {"name": PLUGIN_NAME, "version": "0.0.0"})
    config_path = checkout / ("hooks/hooks.json" if host == "claude" else ".codex-plugin/hooks.json")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    entries = config["hooks"]["PreToolUse"]
    if len(entries) != (2 if host == "claude" else 1):
        raise ValueError("unexpected installed hook groups")
    if host == "claude":
        for entry in entries:
            for hook in entry["hooks"]:
                if (hook.get("onFailure") != "block" or hook.get("timeout") != 5
                        or "hooks/guard-go" not in hook.get("command", "")):
                    raise ValueError("staged Claude plugin lacks verified launcher, timeout 5 or onFailure block")
    record, probe, shell = (root / name for name in ("dispatch.json", "probe.json", "shell.txt"))
    for path in (record, probe, shell):
        path.unlink(missing_ok=True)
    mode = {"retained": "go-hook" if host == "claude" else "bash-hook"}.get(case, case)
    launcher = root / "launcher"
    launcher.unlink(missing_ok=True)
    command = shell_command(fixture, mode, record, binary)
    if host == "claude" and env is not None:
        install_fixture_cache(root, plugin, checkout, fixture, env)
        env["SECRET_HOST_FIXTURE_MODE"] = mode
        env["SECRET_HOST_FIXTURE_RECORD"] = str(record)
        env["SECRET_HOST_FIXTURE_BINARY"] = str(binary)
        launcher = plugin / "hooks/guard-go"
        command = shlex.quote(str(launcher))
    if case in STARTUP_FAILURES:
        launcher.unlink(missing_ok=True)
        if case != "missing-launcher":
            body = "exit 1" if case == "failed-launcher" else "exec " + shlex.quote(str(root / "missing-binary"))
            if case == "exec-format":
                bad = root / "bad-binary"
                bad.write_bytes(b"\x7fELFsynthetic-not-an-executable\x00")
                bad.chmod(0o700)
                body = "exec " + shlex.quote(str(bad))
            launcher.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
            launcher.chmod(0o600 if case == "nonexecutable-launcher" else 0o700)
        command = shlex.quote(str(launcher))
    # The installed entries use shell form. Record that shell without consuming
    # stdin, including cases where the launcher itself cannot start.
    command = ("if [ -e /proc/$$/exe ]; then readlink /proc/$$/exe; "
               "else ps -p $$ -o comm=; fi > " + shlex.quote(str(shell)) + "; " + command)
    for entry in entries:
        for hook in entry["hooks"]:
            hook["command"] = command
    config["hooks"]["SessionStart"] = [{"hooks": [{"type": "command", "command":
        shell_command(fixture, "probe", probe, binary), "timeout": 5}]}]
    private_json(plugin / "hooks/hooks.json", config)
    return plugin, record, probe, shell, config


def hosted(args):
    # Never run real models, modify HOME or load hooks on a developer machine.
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("hosted mode requires a disposable GitHub-hosted runner")
    key_name = "ANTHROPIC_API_KEY" if args.host == "claude" else "OPENAI_API_KEY"
    if not os.environ.get(key_name):
        raise ValueError("credential not configured; gate incomplete")
    root = Path(args.root).resolve(strict=True)
    if any(root.iterdir()) or root == Path.home() or root == ROOT:
        raise ValueError("hosted root must be fresh, empty and disposable")
    root.chmod(0o700)
    checkout = Path(args.checkout).resolve(strict=True)
    fixture = Path(args.fixture).resolve(strict=True)
    binary = Path(args.binary).resolve(strict=True)
    evidence = Path(args.evidence).resolve()
    expected_version = CLAUDE_VERSION if args.host == "claude" else CODEX_VERSION
    executable = str(Path(args.executable).resolve(strict=True))
    # Use a minimal environment. Never inherit real stores, audit, MCP or auth
    # homes, and never persist API values in settings, argv, artifacts or errors.
    home, cache, work = root, root / "cache", root / "work"
    for path in (cache, work):
        path.mkdir(mode=0o700)
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_CACHE_HOME": str(cache),
           "XDG_CONFIG_HOME": str(home / ".config"), "TMPDIR": str(root), "LC_ALL": "C",
           "SECRETS_DIR": str(root / "synthetic-stores"), "SECRETS_ENV": str(root / "absent")}
    if args.host == "claude":
        env[key_name] = os.environ[key_name]
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    else:
        env["CODEX_API_KEY"] = os.environ[key_name]
        env["CODEX_HOME"] = str(home / ".codex")
        Path(env["CODEX_HOME"]).mkdir(mode=0o700)
    version = subprocess.run([executable, "--version"], env=env, cwd=work, capture_output=True,
                             timeout=20, check=False)
    if version.returncode or not re.search(r"(?<![\d.])" + re.escape(expected_version) + r"(?![\d.])",
                                          version.stdout.decode("utf-8", errors="replace")):
        raise ValueError("pinned host version mismatch; gate incomplete")
    settings = root / "settings.json"
    private_json(settings, {"permissions": {"allow": [], "deny": []}})
    results = []
    total_cost = 0.0
    total_tokens = 0
    usage_complete = True
    operations = ("Bash", "Read", "Edit", "Write") if args.host == "claude" else ("Bash", "apply_patch")
    metadata = {"host": args.host, "version": expected_version, "os": platform.system(),
                "arch": platform.machine(), "runner": os.environ.get("RUNNER_OS", "unknown"),
                "image": os.environ.get("ImageOS", "unknown"),
                "image_version": os.environ.get("ImageVersion", "unknown"),
                "commit": os.environ.get("GITHUB_SHA", "unknown"),
                "run_id": os.environ.get("GITHUB_RUN_ID", "unknown"), "cases": results}
    try:
        for operation in operations:
            target = make_target(operation, work)
            prompt = ("Synthetic hook integration test. Attempt exactly one call to " + operation
                      + " with exactly this JSON input: " + json.dumps(target["input"])
                      + ". Do not use other tools, retry, inspect hooks or work around a denial. "
                      "After the call, answer only TEST FINISHED.")
            if operation == "Bash":
                allow_rule = "Bash(" + target["input"]["command"] + ")"
            else:
                # Double slash anchors Claude file rules at filesystem root.
                allow_rule = operation + "(/" + target["path"] + ")"
            control_ok = False
            # Each fault uses the identical operation, input, cwd and prompt as
            # its healthy control. Fresh sessions prevent remembered refusals.
            for case in ("neutral",) + tuple(c for c in CASES if c != "neutral"):
                if total_cost >= 8.0 or total_tokens >= 120000:
                    results.append({"operation": operation, "case": case, "status": "INCOMPLETE",
                                    "reason": "job spend or token budget exhausted"})
                    break
                reset_witness(target)
                plugin, record, probe, shell, config = configure_fixture(
                    root, checkout, fixture, binary, args.host, case, env)
                if args.host == "claude":
                    command = [executable, "-p", prompt, "--plugin-dir", str(plugin),
                               "--settings", str(settings), "--setting-sources", "",
                               "--allowedTools", allow_rule, "--tools", operation,
                               "--permission-mode", "dontAsk", "--output-format", "stream-json",
                               "--verbose", "--max-turns", "2", "--max-budget-usd", "0.10",
                               "--model", args.model]
                else:
                    # Deliberately do not bypass hook trust. A fresh HOME without
                    # a supported trust flow blocks this gate, never skip-green.
                    private_json(Path(env["CODEX_HOME"]) / "hooks.json", config)
                    command = [executable, "exec", "--json", "--skip-git-repo-check",
                               "--sandbox", "workspace-write", "-C", str(work),
                               "--model", args.model, "-c", "features.hooks=true", prompt]
                raw, code, timed_out = bounded_process(command, work, env)
                observed = {"dispatch": record.exists(), "probe": probe.exists(),
                            "executed": execution_witness(target), "returncode": code,
                            "timeout": timed_out}
                events, status, reason = classify_stream(
                    args.host, raw, target, case, observed, True if case == "neutral" else control_ok)
                # Accounting must not erase independently proven execution. Stop
                # further sessions if usage cannot be established from the stream.
                try:
                    session_cost, session_tokens = 0.0, 0
                    usage_found = False
                    for event in events:
                        if args.host == "claude" and event.get("type") == "result":
                            cost = float(event["total_cost_usd"])
                            if not math.isfinite(cost) or cost < 0:
                                raise ValueError("invalid usage")
                            session_cost += cost
                            usage_found = True
                        if args.host == "codex" and event.get("type") == "turn.completed":
                            usage = event["usage"]
                            tokens = [int(usage[key]) for key in ("input_tokens", "output_tokens")]
                            if any(value < 0 for value in tokens):
                                raise ValueError("invalid usage")
                            session_tokens += sum(tokens)
                            usage_found = True
                    if not usage_found:
                        raise ValueError("usage unavailable")
                    total_cost += session_cost
                    total_tokens += session_tokens
                except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
                    usage_complete = False
                    if status == "PASS":
                        status, reason = "INCOMPLETE", "host usage accounting unavailable"
                row = {"operation": operation, "case": case, "status": status, "reason": reason}
                if record.exists():
                    row["envelope"] = json.loads(record.read_text(encoding="utf-8"))
                if shell.exists():
                    # Persist an allowlisted executable identity, not arbitrary output.
                    shell_name = shell.read_text(encoding="utf-8").strip()
                    allowed = {prefix + name for prefix in ("", "/bin/", "/usr/bin/")
                               for name in ("sh", "bash", "dash", "zsh")}
                    row["shell"] = shell_name if shell_name in allowed else "unrecognized"
                if row.get("shell", "unrecognized") == "unrecognized" and status != "FAIL":
                    status, reason = "INCOMPLETE", "actual hook shell evidence missing"
                    row.update(status=status, reason=reason)
                results.append(row)
                print(operation + " " + case + ": " + status + " (" + reason + ")", flush=True)
                if not usage_complete:
                    return 1
                if case == "neutral":
                    control_ok = status == "PASS"
                    if not control_ok:
                        break
        if args.host == "codex":
            # Modifying hooks per case exercises re-trust only if the host first
            # trusts and dispatches. An owner-operated run must supply explicit
            # trust review evidence, which exec JSONL alone does not establish.
            for case in ("plugin-dispatch", "trust", "re-trust", "omitted-workdir"):
                results.append({"operation": "host-contract", "case": case, "status": "INCOMPLETE",
                                "reason": "owner-operated disposable hosted trust evidence required"})
    finally:
        metadata["estimated_claude_cost_usd"] = round(total_cost, 6)
        metadata["codex_tokens"] = total_tokens
        metadata["usage_complete"] = usage_complete
        private_json(evidence, metadata)
    expected = len(operations) * len(CASES)
    return 0 if len(results) == expected and all(r["status"] == "PASS" for r in results) else 1


class ClassificationTests(unittest.TestCase):
    def test_recorded_streams(self):
        fixtures = json.loads((ROOT / "testdata/host-hooks/classification.json").read_text(encoding="utf-8"))
        for fixture in fixtures:
            with self.subTest(fixture=fixture["name"]):
                result = classify(fixture["host"], fixture["events"], fixture["target"], fixture["case"],
                                  fixture["observed"], fixture["control_ok"])
                self.assertEqual(result[0], fixture["expected"])

    def test_strict_jsonl(self):
        self.assertEqual(decode_stream(b'{"type":"result"}\n'), [{"type": "result"}])
        for raw in (b"not json\n", b"[]\n", b"x" * (MAX_STREAM + 1)):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError):
                decode_stream(raw)

    def test_no_narrative_or_unrelated_result_can_pass(self):
        fixtures = json.loads((ROOT / "testdata/host-hooks/classification.json").read_text(encoding="utf-8"))
        fixture = next(f for f in fixtures if f["name"] == "claude-blocked")
        for mutation in ("narrative", "unrelated", "subagent", "wrong-input", "no-probe", "no-dispatch", "nonzero"):
            f = copy.deepcopy(fixture)
            if mutation == "narrative":
                f["events"][2]["type"] = "assistant"
            elif mutation == "unrelated":
                f["events"][2]["message"]["content"][0]["tool_use_id"] = "other"
            elif mutation == "subagent":
                f["events"][1]["parent_tool_use_id"] = "parent"
            elif mutation == "wrong-input":
                f["events"][1]["message"]["content"][0]["input"] = {"command": "true"}
            elif mutation == "no-probe":
                f["observed"]["probe"] = False
            elif mutation == "no-dispatch":
                f["observed"]["dispatch"] = False
            else:
                f["observed"]["returncode"] = 1
            with self.subTest(mutation=mutation):
                self.assertEqual(classify(f["host"], f["events"], f["target"], f["case"],
                                          f["observed"], True)[0], "INCOMPLETE")

    def test_read_error_cannot_hide_a_result(self):
        fixtures = json.loads((ROOT / "testdata/host-hooks/classification.json").read_text(encoding="utf-8"))
        f = copy.deepcopy(next(f for f in fixtures if f["name"] == "read-blocked"))
        f["events"][2]["message"]["content"][0]["content"] += " synthetic-read-witness-4821"
        self.assertEqual(classify(f["host"], f["events"], f["target"], f["case"], f["observed"], True)[0], "FAIL")

    def test_healthy_writes_require_a_filesystem_witness(self):
        fixtures = json.loads((ROOT / "testdata/host-hooks/classification.json").read_text(encoding="utf-8"))
        f = copy.deepcopy(next(f for f in fixtures if f["name"] == "neutral-control"))
        f["observed"]["executed"] = False
        self.assertEqual(classify(f["host"], f["events"], f["target"], f["case"], f["observed"], True)[0], "INCOMPLETE")

    def test_hosted_classification_preserves_execution_witness(self):
        fixtures = json.loads((ROOT / "testdata/host-hooks/classification.json").read_text(encoding="utf-8"))
        control = next(f for f in fixtures if f["name"] == "neutral-control")
        blocked = next(f for f in fixtures if f["name"] == "claude-blocked")
        for fault in ("malformed-stream", "malformed-usage", "structured-success-invalid-usage"):
            for executed in (False, True):
                with self.subTest(fault=fault, executed=executed), tempfile.TemporaryDirectory(
                        prefix="host-hook-classification-") as directory:
                    root = Path(directory)
                    session = root / "session"
                    session.mkdir(mode=0o700)
                    target = copy.deepcopy(control["target"])
                    target["path"] = str(session / "work/witness.txt")
                    state = {}

                    def configure(*args):
                        state["case"] = args[5]
                        record, probe, shell = (session / name for name in ("dispatch.json", "probe.json", "shell.txt"))
                        private_json(record, {})
                        private_json(probe, {})
                        shell.write_text("/bin/sh\n", encoding="utf-8")
                        return session, record, probe, shell, {}

                    def process(*args):
                        healthy = state["case"] == "neutral"
                        if healthy or executed:
                            Path(target["path"]).write_text("host-hook-witness\n", encoding="utf-8")
                        if not healthy and fault == "malformed-stream":
                            return b"not json\n", 0, False
                        events = copy.deepcopy(control["events"] if healthy else blocked["events"])
                        if not healthy:
                            events[-1]["total_cost_usd"] = "not a number"
                            if fault == "structured-success-invalid-usage":
                                events[2]["message"]["content"][0]["is_error"] = False
                        return "\n".join(json.dumps(event) for event in events).encode(), 0, False

                    args = argparse.Namespace(host="claude", root=str(session), checkout=str(ROOT),
                        fixture=sys.executable, binary=sys.executable, executable=sys.executable,
                        evidence=str(root / "evidence.json"), model="synthetic")
                    module = sys.modules[__name__]
                    # All host calls and credentials are synthetic; exercise the
                    # real hosted loop, filesystem witnesses and evidence output.
                    with (mock.patch.dict(os.environ, {"PATH": os.defpath, "GITHUB_ACTIONS": "true",
                              "RUNNER_ENVIRONMENT": "github-hosted", "ANTHROPIC_API_KEY": "synthetic-not-a-key"},
                              clear=True),
                          mock.patch.object(module, "CASES", ("neutral", "exit1")),
                          mock.patch.object(module, "make_target", return_value=target),
                          mock.patch.object(module, "configure_fixture", side_effect=configure),
                          mock.patch.object(module, "bounded_process", side_effect=process) as calls,
                          mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(
                              [], 0, stdout=(CLAUDE_VERSION + "\n").encode())),
                          mock.patch("builtins.print")):
                        self.assertEqual(hosted(args), 1)
                    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
                    rows = evidence["cases"]
                    self.assertEqual(rows[0]["status"], "PASS")
                    self.assertEqual(rows[1]["case"], "exit1")
                    expected = "FAIL" if executed or fault == "structured-success-invalid-usage" else "INCOMPLETE"
                    self.assertEqual(rows[1]["status"], expected)
                    self.assertFalse(evidence["usage_complete"])
                    self.assertEqual(calls.call_count, 2)  # No more spend with unknown usage.

    def test_generated_launcher_shell_syntax(self):
        with tempfile.TemporaryDirectory(prefix="host-hook-syntax-") as directory:
            root = Path(directory)
            checkout = root / "checkout"
            (checkout / "hooks").mkdir(parents=True)
            private_json(checkout / "hooks/hooks.json", {"hooks": {"PreToolUse": [
                {"matcher": matcher, "hooks": [{"type": "command", "command": "hooks/guard-go",
                  "timeout": 5, "onFailure": "block"}]}
                for matcher in ("Bash", "Read|Edit|Write")]}})
            for case in CASES:
                with self.subTest(case=case):
                    _, _, _, _, config = configure_fixture(
                        root, checkout, Path("/synthetic/fixture"), Path("/synthetic/binary"), "claude", case)
                    for entry in config["hooks"]["PreToolUse"]:
                        command = entry["hooks"][0]["command"]
                        checked = subprocess.run(["/bin/sh", "-n"], input=command.encode(),
                                                 capture_output=True, check=False)
                        self.assertEqual(checked.returncode, 0)
                        if shutil.which("shellcheck"):
                            checked = subprocess.run(["shellcheck", "-s", "sh", "-"], input=command.encode(),
                                                     capture_output=True, check=False)
                            self.assertEqual(checked.returncode, 0, checked.stdout.decode())
                    launcher = root / "launcher"
                    if launcher.exists():
                        checked = subprocess.run(["/bin/sh", "-n", str(launcher)], capture_output=True, check=False)
                        self.assertEqual(checked.returncode, 0)
                        if shutil.which("shellcheck"):
                            checked = subprocess.run(["shellcheck", str(launcher)], capture_output=True, check=False)
                            self.assertEqual(checked.returncode, 0, checked.stdout.decode())

    def test_subprocess_timeout_is_incomplete(self):
        raw, code, timed_out = bounded_process(
            ["/bin/sh", "-c", "while :; do :; done"], str(ROOT), {"PATH": os.defpath}, timeout=0.1)
        self.assertEqual(raw, b"")
        self.assertEqual(code, -signal.SIGKILL)
        self.assertTrue(timed_out)

    def test_fixture_executable(self):
        if FIXTURE_BINARY is None:
            self.skipTest("pass --fixture ABSOLUTE_BINARY to test compiled faults")
        with tempfile.TemporaryDirectory(prefix="host-hook-executable-") as directory:
            record = Path(directory) / "dispatch.json"
            # Go's physical cwd must match even under macOS /var -> /private/var.
            envelope = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                   "cwd": os.path.realpath(directory),
                                   "tool_input": {"command": "synthetic"}}).encode()
            for case in ("probe", "neutral", "empty", "deny", "exit1", "fatal", "signal", "malformed", "schema"):
                with self.subTest(case=case):
                    record.unlink(missing_ok=True)
                    result = subprocess.run([FIXTURE_BINARY, case, str(record), "/synthetic/binary"],
                                            input=envelope, capture_output=True, timeout=5,
                                            cwd=directory, env={"PATH": os.defpath}, check=False)
                    self.assertTrue(record.exists())
                    facts = json.loads(record.read_text(encoding="utf-8"))
                    self.assertEqual(facts, {"event": "PreToolUse", "tool": "Bash", "cwd_matches": True,
                                             "cwd_absolute": True, "workdir_present": False})
                    if case == "fatal":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b"fatal error: all goroutines are asleep", result.stderr)
                    elif case == "signal":
                        self.assertEqual(result.returncode, -signal.SIGKILL)
                    elif case == "exit1":
                        self.assertEqual(result.returncode, 1)
                    else:
                        self.assertEqual(result.returncode, 0)
                    if case == "malformed":
                        with self.assertRaises(ValueError):
                            json.loads(result.stdout)
                    elif case in ("neutral", "deny", "schema"):
                        self.assertIsInstance(json.loads(result.stdout), dict)
            with self.assertRaises(subprocess.TimeoutExpired):
                subprocess.run([FIXTURE_BINARY, "timeout", str(record), "/synthetic/binary"],
                               input=envelope, capture_output=True, timeout=0.1, cwd=directory,
                               env={"PATH": os.defpath}, check=False)
            # Verify the verified launcher's real argv contract as well.
            result = subprocess.run([FIXTURE_BINARY, "hook", "claude"], input=envelope,
                                    capture_output=True, timeout=5, cwd=directory, check=False,
                                    env={"PATH": os.defpath, "SECRET_HOST_FIXTURE_MODE": "neutral",
                                         "SECRET_HOST_FIXTURE_RECORD": str(record),
                                         "SECRET_HOST_FIXTURE_BINARY": "/synthetic/binary"})
            self.assertEqual(result.returncode, 0)
            self.assertNotIn("permissionDecision", json.loads(result.stdout)["hookSpecificOutput"])

    def test_fixture_cwd_alias_and_mismatch(self):
        if FIXTURE_BINARY is None:
            self.skipTest("pass --fixture ABSOLUTE_BINARY to test compiled cwd facts")
        with tempfile.TemporaryDirectory(prefix="host-hook-cwd-") as directory:
            root = Path(directory)
            actual = root / "actual"
            actual.mkdir()
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            record = root / "dispatch.json"
            for cwd, matches in ((alias, True), (root, False)):
                with self.subTest(cwd=cwd):
                    envelope = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                           "cwd": os.path.realpath(cwd), "tool_input": {}}).encode()
                    result = subprocess.run([FIXTURE_BINARY, "probe", str(record), "/synthetic/binary"],
                                            input=envelope, capture_output=True, timeout=5,
                                            cwd=alias, env={"PATH": os.defpath}, check=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
                    facts = json.loads(record.read_text(encoding="utf-8"))
                    self.assertEqual(facts["cwd_matches"], matches)
                    self.assertTrue(facts["cwd_absolute"])

    def test_verified_fixture_launcher_offline(self):
        if FIXTURE_BINARY is None:
            self.skipTest("pass --fixture ABSOLUTE_BINARY to test verified launcher integration")
        with tempfile.TemporaryDirectory(prefix="host-hook-cache-") as directory:
            # The installer correctly forbids aliases in its private cache path.
            root = Path(directory).resolve()
            checkout = root / "checkout"
            (checkout / "hooks").mkdir(parents=True)
            (checkout / "scripts").mkdir()
            for relative in ("hooks/guard-go", "scripts/install-release.sh"):
                shutil.copyfile(ROOT / relative, checkout / relative)
            private_json(checkout / "hooks/hooks.json", {"hooks": {"PreToolUse": [
                {"matcher": matcher, "hooks": [{"type": "command", "command": "hooks/guard-go",
                  "timeout": 5, "onFailure": "block"}]}
                for matcher in ("Bash", "Read|Edit|Write")]}})
            home = root / "home"
            home.mkdir(mode=0o700)
            env = {"PATH": os.environ["PATH"], "HOME": str(root), "XDG_CACHE_HOME": str(root / "cache"),
                   "TMPDIR": directory, "LC_ALL": "C"}
            plugin, record, _, _, config = configure_fixture(
                root, checkout, Path(FIXTURE_BINARY), Path("/synthetic/binary"), "claude", "neutral", env)
            envelope = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(root),
                                   "tool_input": {"command": "synthetic"}}).encode()
            result = subprocess.run(["/bin/sh", "-c", config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]],
                                    input=envelope, capture_output=True, env=env, cwd=directory, timeout=10, check=False)
            self.assertEqual(result.returncode, 0)
            output = json.loads(result.stdout)
            self.assertNotIn("permissionDecision", output["hookSpecificOutput"])
            self.assertTrue(record.exists())
            self.assertTrue(json.loads(record.read_text(encoding="utf-8"))["cwd_matches"])
            self.assertEqual((root / "fixture-cache/secret/v0.3.3/secret").stat().st_mode & 0o777, 0o500)
            self.assertTrue((plugin / ".secret-release-test-fixture").exists())

    def test_hosted_mode_refuses_local_execution(self):
        result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--hosted",
                                 "--host", "claude", "--root", "/synthetic/root", "--checkout", "/synthetic/checkout",
                                 "--fixture", "/synthetic/fixture", "--binary", "/synthetic/binary",
                                 "--executable", "/synthetic/host", "--evidence", "/synthetic/evidence", "--model", "synthetic"],
                                capture_output=True, env={"PATH": os.defpath}, check=False, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"host harness setup failed; gate incomplete\n")

    def test_workflow_is_inactive_by_default(self):
        workflow = (ROOT / ".github/workflows/host-hooks.yml").read_text(encoding="utf-8")
        triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(triggers.strip(), "workflow_dispatch:")
        jobs = re.findall(r"^  (?:claude|codex)-host-(?:linux|macos):\n([^\n]+)", workflow, re.M)
        self.assertEqual(len(jobs), 4)
        self.assertTrue(all(line.strip() == "if: vars.SECRET_HOST_TESTS == 'enabled'" for line in jobs))

    def test_workflow_missing_credentials_fail(self):
        workflow = (ROOT / ".github/workflows/host-hooks.yml").read_text(encoding="utf-8")
        guard = workflow.split("      - name: Require protected model credential\n", 1)[1]
        guard = guard.split("        run: |\n", 1)[1].split("      - uses:", 1)[0]
        guard = "\n".join(line[10:] for line in guard.splitlines())
        for host in ("claude", "codex"):
            with self.subTest(host=host):
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", guard],
                                        env={"PATH": os.defpath, "HOST_KIND": host}, capture_output=True,
                                        check=False, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"credential not configured; gate incomplete\n")

    def test_fault_inventory(self):
        inventory = json.loads((ROOT / "testdata/host-hooks/cases.json").read_text(encoding="utf-8"))
        self.assertEqual(set(inventory["cases"]), set(CASES))
        self.assertEqual(inventory["claude_version"], CLAUDE_VERSION)
        self.assertEqual(inventory["codex_version"], CODEX_VERSION)


def main():
    global FIXTURE_BINARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosted", action="store_true")
    parser.add_argument("--host", choices=("claude", "codex"))
    for name in ("root", "checkout", "fixture", "binary", "executable", "evidence", "model"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    if not args.hosted:
        if args.fixture:
            FIXTURE_BINARY = str(Path(args.fixture).resolve(strict=True))
        unittest.main(argv=[sys.argv[0]])
        return 0
    if not all(vars(args).values()):
        parser.error("hosted mode requires all path, host and model arguments")
    try:
        return hosted(args)
    except (ValueError, OSError, subprocess.TimeoutExpired):
        # Never echo exception text: host errors can contain credential material.
        print("host harness setup failed; gate incomplete", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
