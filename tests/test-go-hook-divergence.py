#!/usr/bin/env python3
"""Keep reviewed path tightenings directional and exact using synthetic rows."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


GENERATOR = pathlib.Path(__file__).with_name("gen-go-hook-divergence.py")
spec = importlib.util.spec_from_file_location("go_hook_divergence", GENERATOR)
assert spec is not None and spec.loader is not None
divergence = importlib.util.module_from_spec(spec)
with mock.patch.object(sys, "dont_write_bytecode", True):
    spec.loader.exec_module(divergence)


class EnvelopeTighteningTests(unittest.TestCase):
    def measure(self, suite, name, expected):
        with tempfile.TemporaryDirectory(prefix="hook-divergence-test-") as directory:
            root = pathlib.Path(directory)
            inventory = root / "testdata/inventory"
            inventory.mkdir(parents=True)
            (inventory / f"{suite}.tsv").write_text(f"{suite}\t{name}\tdecision\t{expected}\n")
            (root / f"{suite}.tsv").write_text(f"{suite}\t{name}\tfail\n")
            result = mock.Mock(stdout="0 passed, 1 failed\n")
            with mock.patch.object(divergence, "ROOT", root), mock.patch.object(divergence.subprocess, "run", return_value=result):
                return divergence.suite_rows(suite, "/synthetic/secret", "claude" if suite == "guard" else "codex", root)

    def test_retained_newline_path_tightenings(self):
        for suite in ["guard", "codex"]:
            for name in ["audit23_o8_workdir_newline", "audit23_o8_cwd_newline"]:
                with self.subTest(suite=suite, name=name):
                    self.assertEqual(self.measure(suite, name, "allow"), [(suite, name, "deliberate-tightening")])

    def test_named_tightening_never_permits_a_go_allow(self):
        for suite in ["guard", "codex"]:
            for name in ["audit23_o8_workdir_newline", "audit23_o8_cwd_newline"]:
                with self.subTest(suite=suite, name=name):
                    with self.assertRaisesRegex(ValueError, "unreviewed difference"):
                        self.measure(suite, name, "deny")

    def test_audit28_tightenings_are_exact_and_directional(self):
        self.assertEqual(len(divergence.AUDIT28_TIGHTENING), 15)
        for suite in ["guard", "codex"]:
            for name in sorted(divergence.AUDIT28_TIGHTENING):
                with self.subTest(suite=suite, name=name):
                    self.assertEqual(self.measure(suite, name, "allow"), [(suite, name, "deliberate-tightening")])
                    with self.assertRaisesRegex(ValueError, "unreviewed difference"):
                        self.measure(suite, name, "deny")
            for name in ["audit28_t13_review_unknown_public", "audit28_t19_depth_65_deadline"]:
                with self.assertRaisesRegex(ValueError, "unreviewed difference"):
                    self.measure(suite, name, "allow")

    def test_audit29_categories_are_exact_and_directional(self):
        self.assertEqual(len(divergence.AUDIT29_BASH_OVER_DENIAL), 4)
        for suite in ("guard", "codex"):
            for name in divergence.AUDIT29_BASH_OVER_DENIAL:
                self.assertEqual(self.measure(suite, name, "deny"), [(suite, name, "reviewed-bash-over-denial")])
                with self.assertRaisesRegex(ValueError, "unreviewed difference"):
                    self.measure(suite, name, "allow")
            for name in divergence.AUDIT29_TIGHTENING:
                self.assertEqual(self.measure(suite, name, "allow"), [(suite, name, "deliberate-tightening")])
                with self.assertRaisesRegex(ValueError, "unreviewed difference"):
                    self.measure(suite, name, "deny")
            for name in ("audit29_u22_protected_fd", "audit29_u22_unknown_type_other", "audit29_u22_metadata_template"):
                with self.assertRaisesRegex(ValueError, "unreviewed difference"):
                    self.measure(suite, name, "deny")

    def test_checker_rejects_unreviewed_allow_categories(self):
        checker = GENERATOR.with_name("check-go-hook-divergence.py")
        for suite in ("guard", "codex"):
            for name, decision, valid in (("audit29_u22_unknown_type", "deny", True),
                                          ("audit29_u22_metadata_write_argv", "deny", True),
                                          ("audit29_u22_protected_fd", "deny", False),
                                          ("audit29_u22_unknown_type_extra", "deny", False),
                                          ("audit29_u22_unknown_type", "allow", False)):
                with self.subTest(suite=suite, name=name, decision=decision), tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    (root / "inventory").write_text(f"{suite}\t{name}\tdecision\t{decision}\n")
                    (root / "results").write_text(f"{suite}\t{name}\tfail\n")
                    (root / "divergences").write_text(f"{suite}\t{name}\treviewed-bash-over-denial\n")
                    (root / "log").write_text("0 passed, 1 failed\n")
                    run = subprocess.run([sys.executable, "-I", str(checker), suite,
                                          str(root / "inventory"), str(root / "results"),
                                          str(root / "divergences"), str(root / "log")], capture_output=True, text=True)
                    self.assertEqual(run.returncode == 0, valid, run.stderr)

    def test_unknown_newline_case_stays_unreviewed(self):
        with self.assertRaisesRegex(ValueError, "unreviewed difference"):
            self.measure("guard", "audit23_o8_unknown_newline", "allow")


if __name__ == "__main__":
    unittest.main()
