#!/usr/bin/env python3
"""Check exact runtime-conditional inventory keys with disposable shell stubs."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONDITIONAL = ["audit28_t13_compound_" + name + "_public" for name in ("time_end", "coproc", "named_coproc")] + [
    "audit28_t13_review_" + name + "_public" + suffix
    for name in ("function", "function_index") for suffix in ("", "_argv")
]


class RuntimeInventoryTests(unittest.TestCase):
    def measure(self, major, mode="--check", changed_deny=False, omit_required=False):
        with tempfile.TemporaryDirectory(prefix="inventory-test-") as directory:
            root = pathlib.Path(directory)
            tests = root / "tests"
            tests.mkdir()
            inventory = root / "testdata/inventory"
            inventory.mkdir(parents=True)
            shutil.copyfile(ROOT / "tests/inventory.sh", tests / "inventory.sh")
            rows = ["guard\trequired\tdecision\tallow\n"] + [
                "guard\t" + name + "\tdecision\t" + ("deny" if changed_deny else "allow") + "\n"
                for name in CONDITIONAL
            ]
            (inventory / "guard.tsv").write_text("".join(sorted(rows, key=lambda line: line.split("\t")[1])))
            # No guard is invoked. The runtime stub reports a major version and
            # emits the same synthetic inventory rows a conditional suite would.
            runtime = root / "bash-stub"
            runtime.write_text("#!/bin/bash\nif [[ $1 == -c ]]; then printf '%s' " + str(major) + "; exit; fi\n"
                               + (": >\"$SECRET_TEST_INVENTORY\"\n" if omit_required else
                                  "printf 'guard\\trequired\\tdecision\\tallow\\n' >\"$SECRET_TEST_INVENTORY\"\n")
                               + ("" if major < 4 else "cat <<'ROWS' >>\"$SECRET_TEST_INVENTORY\"\n" + "".join(rows[1:]) + "ROWS\n"))
            runtime.chmod(0o700)
            env = os.environ.copy()
            env.update(BASH_BIN=str(runtime), HOME=str(root / "home"))
            return subprocess.run(["bash", str(tests / "inventory.sh"), mode, "--suite", "guard"],
                                  env=env, capture_output=True, text=True, timeout=10)

    def test_only_exact_bash32_public_controls_are_optional(self):
        for major, count in [(3, 1), (5, 8)]:
            result = self.measure(major)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"{count} cases match", result.stdout)

    def test_bash32_never_omits_denials_or_other_keys(self):
        for options in [dict(changed_deny=True), dict(omit_required=True)]:
            result = self.measure(3, **options)
            self.assertNotEqual(result.returncode, 0)

    def test_bash32_cannot_overwrite_canonical_inventory(self):
        result = self.measure(3, "--write")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regenerate the canonical inventory with Bash 4+", result.stderr)


if __name__ == "__main__":
    unittest.main()
