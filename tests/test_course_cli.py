import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

import crypto_lab
from crypto_lab.cli import main


class CourseCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main([*arguments, "--json"])
        self.assertEqual(status, 0, stderr.getvalue())
        return json.loads(stdout.getvalue()), stderr.getvalue()

    def test_catalog_and_classical_command(self):
        lessons, _ = self.run_cli("lessons")
        self.assertGreaterEqual(len(lessons), 25)
        result, trace = self.run_cli(
            "classical", "caesar", "HELLO", "--shift", "3", "-v"
        )
        self.assertEqual(result["result"], "KHOOR")
        self.assertIn("classical.caesar", trace)

    def test_aes_security_game_and_discrete_log_commands(self):
        aes, _ = self.run_cli(
            "aes-demo", "00112233445566778899aabbccddeeff"
        )
        self.assertEqual(aes["result"], "69c4e0d86a7b0430d8cdb78070b4c55a")
        game, _ = self.run_cli(
            "security-game", "--scheme", "deterministic", "--trials", "40"
        )
        self.assertEqual(game["wins"], game["trials"])
        for algorithm in ("bsgs", "pohlig-hellman", "rho"):
            result, _ = self.run_cli(
                "dlog", "5", "8", "23", "--algorithm", algorithm
            )
            self.assertEqual(result["discrete_log"], 6)

    def test_key_exchange_sharing_hash_and_mac_commands(self):
        dh, _ = self.run_cli("dh-demo")
        self.assertEqual(dh["shared_secret"], 2)
        sharing, _ = self.run_cli("shamir-demo", "42")
        self.assertEqual(sharing["recovered"], 42)
        self.assertEqual(len(sharing["shares"]), 5)
        forged, _ = self.run_cli("hash-demo", "hello")
        self.assertTrue(forged["verified"])
        authentication, _ = self.run_cli("auth-demo", "hello")
        self.assertTrue(authentication["verified"])

    def test_every_signature_command(self):
        for scheme in ("rsa", "lamport", "dsa", "ecdsa"):
            result, _ = self.run_cli(
                "signature-demo", "classroom message", "--scheme", scheme
            )
            self.assertTrue(result["verified"], scheme)

    def test_attack_advanced_and_protocol_commands(self):
        timing, _ = self.run_cli("attack-demo", "timing", "--secret", "ABC")
        self.assertEqual(timing["recovered"], "ABC")
        padding, _ = self.run_cli("attack-demo", "padding-oracle")
        self.assertGreater(padding["queries"], 0)
        for topic in ("zk", "lwe", "mpc", "bb84"):
            result, _ = self.run_cli("advanced-demo", topic)
            self.assertTrue(result)
        transcript, _ = self.run_cli("tls-demo")
        self.assertEqual(transcript["shared_secret"], 2)


class PublicSdkTests(unittest.TestCase):
    def test_course_level_namespace_is_importable(self):
        expected = (
            "AES128",
            "caesar_encrypt",
            "baby_step_giant_step",
            "diffie_hellman",
            "hmac_sha256",
            "rsa_sign",
            "shamir_split",
            "simulate_bb84",
            "TraceCollector",
        )
        for symbol in expected:
            self.assertTrue(hasattr(crypto_lab, symbol), symbol)

    def test_version(self):
        self.assertEqual(crypto_lab.__version__, "0.4.0")


if __name__ == "__main__":
    unittest.main()
