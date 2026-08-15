from __future__ import annotations

import unittest

from crypto_lab import (
    RSAKeyPair,
    bytes_to_int,
    extended_gcd,
    int_to_bytes,
    mod_inverse,
    mod_pow,
    pkcs7_pad,
    pkcs7_unpad,
)
from crypto_lab.feistel import FeistelMessage, ToyFeistelCipher


class EncodingTests(unittest.TestCase):
    def test_integer_encoding_round_trip(self) -> None:
        data = b"crypto"
        self.assertEqual(int_to_bytes(bytes_to_int(data), length=len(data)), data)

    def test_padding_round_trip(self) -> None:
        padded = pkcs7_pad(b"seven!!", 8)
        self.assertEqual(len(padded), 8)
        self.assertEqual(pkcs7_unpad(padded, 8), b"seven!!")

    def test_invalid_padding_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"broken\x02", 8)


class NumberTheoryTests(unittest.TestCase):
    def test_extended_gcd_identity(self) -> None:
        divisor, x, y = extended_gcd(240, 46)
        self.assertEqual(divisor, 2)
        self.assertEqual(240 * x + 46 * y, divisor)

    def test_inverse_and_modular_power(self) -> None:
        self.assertEqual(mod_inverse(17, 3120), 2753)
        self.assertEqual(mod_pow(4, 13, 497), 445)

    def test_modular_power_trace(self) -> None:
        events = []
        mod_pow(4, 13, 497, trace=events.append)
        self.assertEqual(sum(event.code == "modpow.bit" for event in events), 4)
        self.assertEqual(events[-1].code, "modpow.complete")


class RSATests(unittest.TestCase):
    def test_classic_small_rsa_example(self) -> None:
        keys = RSAKeyPair.from_primes(61, 53, public_exponent=17)
        self.assertEqual(keys.public.modulus, 3233)
        self.assertEqual(keys.private.exponent, 2753)
        self.assertEqual(keys.public.encrypt_int(65), 2790)
        self.assertEqual(keys.private.decrypt_int(2790), 65)

    def test_text_round_trip_preserves_block_lengths(self) -> None:
        keys = RSAKeyPair.from_primes(61, 53, public_exponent=17)
        encrypted = keys.public.encrypt_bytes(b"\x00Hi")
        self.assertEqual(keys.private.decrypt_bytes(encrypted), b"\x00Hi")

    def test_non_prime_key_input_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RSAKeyPair.from_primes(15, 53, public_exponent=17)


class FeistelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cipher = ToyFeistelCipher(0x1334_5779_9BBC_DFF1)

    def test_ecb_round_trip(self) -> None:
        encrypted = self.cipher.encrypt(b"block cipher lesson", mode="ecb")
        self.assertEqual(self.cipher.decrypt(encrypted), b"block cipher lesson")

    def test_cbc_round_trip(self) -> None:
        encrypted = self.cipher.encrypt(
            b"block cipher lesson", mode="cbc", iv=bytes(8)
        )
        self.assertEqual(self.cipher.decrypt(encrypted), b"block cipher lesson")

    def test_ecb_reveals_repeated_blocks_but_cbc_does_not(self) -> None:
        plaintext = b"A" * 16
        ecb = self.cipher.encrypt(plaintext, mode="ecb").ciphertext
        cbc = self.cipher.encrypt(plaintext, mode="cbc", iv=bytes(8)).ciphertext
        self.assertEqual(ecb[:8], ecb[8:16])
        self.assertNotEqual(cbc[:8], cbc[8:16])

    def test_tampered_padding_is_rejected(self) -> None:
        encrypted = self.cipher.encrypt(b"lesson", mode="ecb")
        tampered = FeistelMessage(
            encrypted.ciphertext[:-1] + b"\x00", "ecb", None
        )
        with self.assertRaises(ValueError):
            self.cipher.decrypt(tampered)

    def test_round_trace_is_opt_in(self) -> None:
        events = []
        self.cipher.encrypt(b"hello", mode="ecb", trace=events.append)
        self.assertEqual(
            sum(event.code == "feistel.round" for event in events), self.cipher.rounds
        )


if __name__ == "__main__":
    unittest.main()
