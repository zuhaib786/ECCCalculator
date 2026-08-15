from __future__ import annotations

import unittest

from crypto_lab.randomness import (
    derive_password_key,
    hkdf,
    insecure_prng_bytes,
    min_entropy,
    shannon_entropy,
)
from crypto_lab.security_games import (
    DeterministicXorScheme,
    RandomNonceXorScheme,
    run_ind_cpa_equality_game,
)


class RandomnessTests(unittest.TestCase):
    def test_seeded_prng_is_predictable(self) -> None:
        self.assertEqual(insecure_prng_bytes(7, 32), insecure_prng_bytes(7, 32))

    def test_entropy_metrics(self) -> None:
        self.assertEqual(shannon_entropy({"heads": 1, "tails": 1}), 1.0)
        self.assertEqual(min_entropy({"heads": 1, "tails": 1}), 1.0)
        self.assertLess(min_entropy({"common": 7, "rare": 1}), 1.0)

    def test_rfc5869_sha256_vector(self) -> None:
        result = hkdf(
            bytes.fromhex("0b" * 22),
            42,
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        )
        self.assertEqual(
            result.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_password_salts_change_keys(self) -> None:
        first = derive_password_key("password", b"salt-one", iterations=10)
        second = derive_password_key("password", b"salt-two", iterations=10)
        self.assertNotEqual(first, second)


class SecurityGameTests(unittest.TestCase):
    def test_deterministic_encryption_loses_ind_cpa_game(self) -> None:
        result = run_ind_cpa_equality_game(
            DeterministicXorScheme(b"class key"), b"message zero", b"message one!"
        )
        self.assertEqual(result.success_rate, 1.0)
        self.assertEqual(result.distinguishing_advantage, 1.0)

    def test_randomized_scheme_hides_equality_pattern(self) -> None:
        result = run_ind_cpa_equality_game(
            RandomNonceXorScheme(b"class key"),
            b"message zero",
            b"message one!",
            trials=2_000,
            seed=11,
        )
        self.assertLess(result.distinguishing_advantage, 0.08)


if __name__ == "__main__":
    unittest.main()

