#!/usr/bin/env python3
"""Exercise variant extraction with synthetic commands, including oversized argv."""
import importlib.util
import io
import json
import pathlib
import shlex
import sys
import tempfile
import unittest
from unittest import mock


GENERATOR = pathlib.Path(__file__).with_name("gen-hook-variants.py")
spec = importlib.util.spec_from_file_location("hook_variants", GENERATOR)
assert spec is not None and spec.loader is not None
variants = importlib.util.module_from_spec(spec)
with mock.patch.object(sys, "dont_write_bytecode", True):
    spec.loader.exec_module(variants)


class VariantExtractionTests(unittest.TestCase):
    def test_direct_responses_keep_extraction_suite_running(self):
        envelope = dict(tool_name="Bash", tool_input=dict(command="true"))
        for payload, phrase in [
            ("", None),
            ("malformed", "split it"),
            (json.dumps(envelope) + "\n" + json.dumps(envelope), "split it"),
            (json.dumps(dict(tool_name="Bash", tool_input=dict(command="x" * 8200))), "split the command"),
            (json.dumps(dict(tool_name="Bash", tool_input=dict(command="cat .env '"))), "split it"),
        ]:
            with self.subTest(phrase=phrase, length=len(payload)):
                output = io.StringIO()
                with mock.patch.object(sys, "argv", [str(GENERATOR), "--direct", "/synthetic", "/synthetic/rows"]):
                    with mock.patch.object(sys, "stdin", io.StringIO(payload)), mock.patch.object(sys, "stdout", output), mock.patch.object(variants, "capture"):
                        variants.direct()
                if phrase is None:
                    self.assertEqual(output.getvalue(), "")
                else:
                    response = json.loads(output.getvalue())["hookSpecificOutput"]
                    self.assertEqual(response["permissionDecision"], "deny")
                    self.assertIn(phrase, response["permissionDecisionReason"])

    def test_capture_preserves_only_bounded_synthetic_metadata_contents(self):
        with tempfile.TemporaryDirectory(prefix="hook-variant-test-") as directory:
            root = pathlib.Path(directory)
            fixtures = root / "fixtures"
            fixtures.mkdir()
            contents = {
                "linked/.git": f"gitdir: {fixtures}/metadata\n",
                "bounded/.git": "g" * 9000,
                "oversized/.git": "g" * 9001,
                "repository/.git/config": "[core]\n\tbare = false\n",
                "ordinary": "synthetic payload not captured",
                "not.git": "not a gitfile",
            }
            for name, data in contents.items():
                path = fixtures / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
            rows = root / "rows.jsonl"
            row = dict(name="gitfile", want="deny", tool="Bash", command="true",
                       cwd=str(fixtures), config="", extra={"command": ["cat", 1]})
            with mock.patch.object(sys, "argv", [str(GENERATOR), "--capture", str(fixtures), str(rows)]):
                variants.capture(row)
            captured = json.loads(rows.read_text())
            files = {name: data for name, kind, data in captured["fixtures"] if kind == "file"}
            self.assertEqual(files, {
                "linked/.git": "gitdir: @TMP@/metadata\n",
                "bounded/.git": "g" * 9000,
                "oversized/.git": "",
                "repository/.git/config": contents["repository/.git/config"],
                "ordinary": "",
                "not.git": "",
            })
            self.assertEqual(captured["extra"]["command"], ["cat", 1])

    def test_direct_preserves_literal_credential_metadata(self):
        envelope = dict(tool_name="Bash", tool_input=dict(command="cat custom.cfg"))
        env = dict(HOME="/synthetic/home-alias", RIPGREP_CONFIG_PATH="/synthetic/rg-config",
                   KUBECONFIG="/synthetic/custom.cfg:/synthetic/second.cfg")
        with mock.patch.object(sys, "argv", [str(GENERATOR), "--direct", "/synthetic", "/synthetic/rows"]):
            with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(envelope))), mock.patch.object(sys, "stdout", io.StringIO()):
                with mock.patch.dict(variants.os.environ, env), mock.patch.object(variants, "capture") as capture:
                    variants.direct()
        row = capture.call_args.args[0]
        self.assertEqual(row["home"], env["HOME"])
        self.assertEqual(row["config"], env["RIPGREP_CONFIG_PATH"])
        self.assertEqual(row["kubeconfig"], env["KUBECONFIG"])

    def test_command_bytes_survive_stdin_extraction(self):
        commands = ["", "cat '.env'\\\"\t\n\n", "printf 'synthetic café'", "x" * (1024 * 1024)]
        with tempfile.TemporaryDirectory(prefix="hook-variant-test-") as directory:
            root = pathlib.Path(directory)
            (root / "tests").mkdir()
            (root / "testdata/hook").mkdir(parents=True)
            (root / "testdata/hook/audit-cases.json").write_text('{"fixtures": [], "cases": []}')
            # The generator replaces these two functions exactly as in the suite.
            source = '''set -euo pipefail
REPO_ROOT=unused
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
invoke_guard() {
    return 1
}
secrets() {
    return 1
}
export HOME="$TMP/home-alias"
export RIPGREP_CONFIG_PATH="$TMP/rg-config"
export KUBECONFIG="$TMP/custom.cfg:$TMP/second.cfg"
'''
            for index, command in enumerate(commands[:-1]):
                source += f"secrets case_{index} deny Bash {shlex.quote(command)}\n"
            source += '''large="$(printf '%1048576s' '' | tr ' ' x)"
secrets case_3 deny Bash "$large"
'''
            (root / "tests/test-guard.sh").write_text(source)
            output = root / "output.json"
            with mock.patch.object(variants, "ROOT", root), mock.patch.object(sys, "argv", [str(GENERATOR), str(output)]):
                variants.generate()
            corpus = json.loads(output.read_text())
            self.assertEqual(corpus["snapshots"], [[], []])
            self.assertEqual(corpus["cases"], [
                dict(name=f"case_{index}", command=command, cwd="@TMP@/search",
                     home="@TMP@/home-alias", config="@TMP@/rg-config",
                     kubeconfig="@TMP@/custom.cfg:@TMP@/second.cfg", extra={}, snapshot=0)
                for index, command in enumerate(commands)
            ])


if __name__ == "__main__":
    unittest.main()
