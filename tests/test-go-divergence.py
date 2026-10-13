#!/usr/bin/env python3
"""Synthetic exact-divergence regression cases."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

CHECKER = pathlib.Path(__file__).with_name("check-go-divergence.py")

class DivergenceTest(unittest.TestCase):
    def check(self, result, divergence):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "inventory").write_text("secret\tcase\tcheck\t0\n")
            (root / "results").write_text(f"secret\tcase\t{result}\n")
            (root / "divergence").write_text(divergence)
            return subprocess.run([sys.executable, "-I", str(CHECKER), "secret",
                                   str(root / "inventory"), str(root / "results"),
                                   str(root / "divergence")], capture_output=True, text=True)

    def test_exact_failure(self):
        self.assertEqual(self.check("fail", "secret\tcase\tdeliberate\n").returncode, 0)
        self.assertEqual(self.check("pass", "").returncode, 0)

    def test_unlisted_failure(self):
        self.assertIn("unlisted divergence", self.check("fail", "").stderr)

    def test_recovered_failure(self):
        self.assertIn("listed divergence now passes",
                      self.check("pass", "secret\tcase\tdeliberate\n").stderr)

    def test_invalid_reason(self):
        self.assertIn("invalid reason category",
                      self.check("fail", "secret\tcase\tunknown\n").stderr)

if __name__ == "__main__":
    unittest.main()
