"""Unit tests for the classical-cipher and perfect-secrecy lessons."""

from __future__ import annotations

import unittest

from crypto_lab.classical import (
    affine_decrypt,
    affine_encrypt,
    caesar_decrypt,
    caesar_encrypt,
    hill_decrypt,
    hill_encrypt,
    kasiski_examination,
    letter_counts,
    letter_frequency_analysis,
    substitution_decrypt,
    substitution_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)
from crypto_lab.perfect_secrecy import (
    analyze_otp_key_reuse,
    enumerate_perfect_secrecy,
    is_perfectly_secret,
    otp_decrypt,
    otp_encrypt,
    otp_key_reuse_attack,
)


class CaesarTests(unittest.TestCase):
    def test_known_vector_and_round_trip(self) -> None:
        encrypted = caesar_encrypt("Attack at Dawn!", 3)
        self.assertEqual(encrypted, "Dwwdfn dw Gdzq!")
        self.assertEqual(caesar_decrypt(encrypted, 3), "Attack at Dawn!")

    def test_shift_wraps_and_can_require_letters_only(self) -> None:
        self.assertEqual(caesar_encrypt("xyz", 3), "abc")
        with self.assertRaises(ValueError):
            caesar_encrypt("abc!", 1, preserve_nonletters=False)


class AffineTests(unittest.TestCase):
    def test_standard_affine_example(self) -> None:
        encrypted = affine_encrypt("AFFINE CIPHER", 5, 8)
        self.assertEqual(encrypted, "IHHWVC SWFRCP")
        self.assertEqual(affine_decrypt(encrypted, 5, 8), "AFFINE CIPHER")

    def test_noninvertible_multiplier_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            affine_encrypt("test", 2, 3)
        with self.assertRaises(ValueError):
            affine_decrypt("test", 13, 3)


class SubstitutionTests(unittest.TestCase):
    KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"

    def test_key_permutation_and_inverse(self) -> None:
        encrypted = substitution_encrypt("Hello, World!", self.KEY)
        self.assertEqual(encrypted, "Itssg, Vgksr!")
        self.assertEqual(substitution_decrypt(encrypted, self.KEY), "Hello, World!")

    def test_invalid_key_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            substitution_encrypt("hello", "ABC")
        with self.assertRaises(ValueError):
            substitution_encrypt("hello", "A" * 26)


class VigenereTests(unittest.TestCase):
    def test_classic_known_vector(self) -> None:
        encrypted = vigenere_encrypt("ATTACKATDAWN", "LEMON")
        self.assertEqual(encrypted, "LXFOPVEFRNHR")
        self.assertEqual(vigenere_decrypt(encrypted, "LEMON"), "ATTACKATDAWN")

    def test_punctuation_does_not_advance_key(self) -> None:
        self.assertEqual(vigenere_encrypt("A B", "B"), "B C")
        with self.assertRaises(ValueError):
            vigenere_encrypt("hello", "")


class HillTests(unittest.TestCase):
    KEY = ((3, 3), (2, 5))

    def test_classic_two_by_two_vector(self) -> None:
        self.assertEqual(hill_encrypt("HELP", self.KEY), "HIAT")
        self.assertEqual(hill_decrypt("HIAT", self.KEY), "HELP")

    def test_odd_length_is_padded_and_removed_on_decryption(self) -> None:
        encrypted = hill_encrypt("HELLO", self.KEY)
        self.assertEqual(encrypted, "HIOZHN")
        self.assertEqual(hill_decrypt(encrypted, self.KEY), "HELLO")

    def test_noninvertible_matrix_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            hill_encrypt("HELLO", ((2, 4), (2, 4)))
        with self.assertRaises(ValueError):
            hill_decrypt("ABC", self.KEY, padding=None)


class AnalysisTests(unittest.TestCase):
    def test_letter_counts_and_normalized_frequency(self) -> None:
        self.assertEqual(letter_counts("Aa! Bbb"), {"A": 2, "B": 3})
        frequency = letter_frequency_analysis("Aa! Bbb", normalized=True)
        self.assertAlmostEqual(frequency["A"], 2 / 5)
        self.assertAlmostEqual(frequency["B"], 3 / 5)

    def test_kasiski_finds_repeated_distances_and_factors(self) -> None:
        result = kasiski_examination("ABCABCABC", min_sequence_length=3, max_sequence_length=3)
        self.assertEqual(result.repeated_sequences[0].sequence, "ABC")
        self.assertIn(3, result.distances)
        self.assertEqual(result.candidate_key_lengths[0], 3)
        self.assertEqual(result.factor_counts[3], 5)

    def test_kasiski_validates_lengths(self) -> None:
        with self.assertRaises(ValueError):
            kasiski_examination("ABC", min_sequence_length=1)
        with self.assertRaises(ValueError):
            kasiski_examination("ABC", min_sequence_length=4, max_sequence_length=3)


class OneTimePadTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        plaintext = b"attack at dawn"
        key = bytes(range(len(plaintext)))
        ciphertext = otp_encrypt(plaintext, key)
        self.assertEqual(otp_decrypt(ciphertext, key), plaintext)

    def test_key_must_match_message_length(self) -> None:
        with self.assertRaises(ValueError):
            otp_encrypt(b"abc", b"xy")
        with self.assertRaises(ValueError):
            otp_decrypt(b"abc", b"xy")

    def test_reused_key_reveals_plaintext_xor_and_known_plaintext_recovery(self) -> None:
        key = b"0123456789"
        first = b"attack!"
        second = b"defend!"
        first_ciphertext = otp_encrypt(first, key[: len(first)])
        second_ciphertext = otp_encrypt(second, key[: len(second)])
        analysis = analyze_otp_key_reuse(first_ciphertext, second_ciphertext)
        self.assertEqual(analysis.ciphertext_xor, bytes(a ^ b for a, b in zip(first, second)))
        self.assertEqual(
            otp_key_reuse_attack(first_ciphertext, second_ciphertext, known_plaintext=first),
            second,
        )


class PerfectSecrecyTests(unittest.TestCase):
    def test_xor_toy_otp_is_perfectly_secret(self) -> None:
        report = enumerate_perfect_secrecy((0, 1), (0, 1), lambda message, key: message ^ key)
        self.assertTrue(report.is_perfectly_secret)
        self.assertEqual(report.posterior[0][0], report.prior[0])
        self.assertEqual(report.posterior[1][1], report.prior[1])
        self.assertTrue(is_perfectly_secret((0, 1), (0, 1), lambda message, key: message ^ key))

    def test_deterministic_cipher_is_not_perfectly_secret(self) -> None:
        report = enumerate_perfect_secrecy(("A", "B"), (0,), lambda message, key: message)
        self.assertFalse(report.is_perfectly_secret)
        self.assertGreater(len(report.violations), 0)

    def test_empty_spaces_and_unhashable_outputs_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            enumerate_perfect_secrecy((), (0,), lambda message, key: message)
        with self.assertRaises(TypeError):
            enumerate_perfect_secrecy((0,), (0,), lambda message, key: [])


if __name__ == "__main__":
    unittest.main()
