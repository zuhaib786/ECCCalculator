from __future__ import annotations

import contextlib
import io
import json
import unittest

from ecc_factor.cli import main


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_default_output_is_concise(self) -> None:
        status, stdout, stderr = self.run_cli("360")
        self.assertEqual(status, 0)
        self.assertEqual(stdout, "360 = 2^3 * 3^2 * 5\n")
        self.assertEqual(stderr, "")

    def test_quiet_output(self) -> None:
        _, stdout, stderr = self.run_cli("91", "--quiet")
        self.assertEqual(stdout, "7 13\n")
        self.assertEqual(stderr, "")

    def test_verbose_progress_goes_to_stderr(self) -> None:
        _, stdout, stderr = self.run_cli("10403", "--verbose", "--seed", "1")
        self.assertEqual(stdout, "10403 = 101 * 103\n")
        self.assertIn("[factor.start]", stderr)

    def test_json_remains_machine_readable(self) -> None:
        _, stdout, _ = self.run_cli("45", "--json", "--verbose")
        self.assertEqual(json.loads(stdout)["factors"], [3, 3, 5])


if __name__ == "__main__":
    unittest.main()

