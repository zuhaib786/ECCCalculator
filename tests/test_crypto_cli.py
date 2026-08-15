from __future__ import annotations

import contextlib
import io
import json
import unittest

from crypto_lab.cli import main


class CryptoCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_encoding_lesson(self) -> None:
        status, stdout, stderr = self.run_cli(
            "encode", "Hi", "--block-size", "1", "--json"
        )
        self.assertEqual(status, 0)
        result = json.loads(stdout)
        self.assertEqual(result["hex"], "4869")
        self.assertEqual(len(result["blocks"]), 2)
        self.assertEqual(stderr, "")

    def test_modpow_verbose_steps(self) -> None:
        status, stdout, stderr = self.run_cli("modpow", "4", "13", "497", "-vv")
        self.assertEqual(status, 0)
        self.assertIn("= 445", stdout)
        self.assertIn("[modpow.bit]", stderr)

    def test_rsa_demo_round_trip_and_warning(self) -> None:
        status, stdout, stderr = self.run_cli(
            "rsa-demo",
            "Hi",
            "--p",
            "61",
            "--q",
            "53",
            "-e",
            "17",
            "--json",
        )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout)["recovered"], "Hi")
        self.assertIn("Educational implementation only", stderr)

    def test_feistel_demo_round_trip(self) -> None:
        status, stdout, stderr = self.run_cli("feistel-demo", "hello", "--json")
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout)["recovered"], "hello")
        self.assertIn("Educational implementation only", stderr)

    def test_factor_command(self) -> None:
        status, stdout, stderr = self.run_cli("factor", "91", "--quiet")
        self.assertEqual((status, stdout, stderr), (0, "7 13\n", ""))

    def test_continued_fraction_factor_command(self) -> None:
        status, stdout, stderr = self.run_cli(
            "factor", str(1_009 * 1_013), "-m", "cfrac", "--quiet"
        )
        self.assertEqual((status, stdout, stderr), (0, "1009 1013\n", ""))

    def test_fermat_carmichael_lesson(self) -> None:
        status, stdout, stderr = self.run_cli(
            "prime", "561", "--test", "fermat", "--base", "2", "--json"
        )
        result = json.loads(stdout)
        self.assertEqual(status, 0)
        self.assertTrue(result["probably_prime"])
        self.assertFalse(result["deterministic"])
        self.assertEqual(stderr, "")

    def test_miller_rabin_finds_carmichael_witness(self) -> None:
        status, stdout, stderr = self.run_cli(
            "prime", "561", "--test", "miller-rabin", "--base", "2", "-vv"
        )
        self.assertEqual(status, 0)
        self.assertIn("composite", stdout)
        self.assertIn("witness: 2", stdout)
        self.assertIn("[primality.miller_rabin_round]", stderr)


if __name__ == "__main__":
    unittest.main()
