from __future__ import annotations

import unittest

from crypto_lab.stream_ciphers import (
    LFSR,
    chacha_quarter_round,
    rc4_transform,
    reused_keystream_xor,
    sample_rc4_second_byte_bias,
)
from crypto_lab.symmetric import (
    AES128,
    GCMMessage,
    aes_ctr_transform,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hamming_distance,
)


class AESTests(unittest.TestCase):
    def test_fips_197_known_answer(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        cipher = AES128(key)
        self.assertEqual(cipher.encrypt_block(plaintext), expected)
        self.assertEqual(cipher.decrypt_block(expected), plaintext)

    def test_round_trace(self) -> None:
        events = []
        AES128(bytes(16)).encrypt_block(bytes(16), trace=events.append)
        self.assertEqual(sum(event.code == "aes.sub_bytes" for event in events), 10)
        self.assertEqual(events[-1].code, "aes.complete")

    def test_ctr_round_trip_and_nonce_sensitivity(self) -> None:
        data = b"CTR handles partial final blocks."
        key = bytes(range(16))
        encrypted = aes_ctr_transform(data, key, b"12345678")
        self.assertEqual(aes_ctr_transform(encrypted, key, b"12345678"), data)
        self.assertNotEqual(encrypted, aes_ctr_transform(data, key, b"87654321"))

    def test_hamming_distance(self) -> None:
        self.assertEqual(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)

    def test_nist_gcm_known_answer_and_tamper_rejection(self) -> None:
        message = aes_gcm_encrypt(bytes(16), bytes(16), bytes(12))
        self.assertEqual(message.ciphertext.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(message.tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")
        self.assertEqual(aes_gcm_decrypt(message, bytes(16)), bytes(16))
        tampered = GCMMessage(
            message.nonce,
            message.ciphertext[:-1] + bytes([message.ciphertext[-1] ^ 1]),
            message.tag,
        )
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(tampered, bytes(16))


class StreamCipherTests(unittest.TestCase):
    def test_lfsr_is_deterministic(self) -> None:
        first = LFSR(0b0001, 4, (0, 1)).bits(10)
        second = LFSR(0b0001, 4, (0, 1)).bits(10)
        self.assertEqual(first, second)
        self.assertGreater(len(set(first)), 1)

    def test_rc4_historical_known_answer(self) -> None:
        ciphertext = rc4_transform(b"Plaintext", b"Key")
        self.assertEqual(ciphertext.hex(), "bbf316e8d940af0ad3")
        self.assertEqual(rc4_transform(ciphertext, b"Key"), b"Plaintext")

    def test_chacha_quarter_round_vector(self) -> None:
        self.assertEqual(
            chacha_quarter_round(0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567),
            (0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB),
        )

    def test_reused_keystream_leaks_plaintext_xor(self) -> None:
        stream = b"reused secret stream"
        left = bytes(a ^ b for a, b in zip(b"attack at dawn!!!!!!", stream))
        right = bytes(a ^ b for a, b in zip(b"defend at dusk!!!!!!", stream))
        self.assertEqual(
            reused_keystream_xor(left, right),
            reused_keystream_xor(b"attack at dawn!!!!!!", b"defend at dusk!!!!!!"),
        )

    def test_rc4_second_byte_bias_is_observable(self) -> None:
        counts = sample_rc4_second_byte_bias(10_000, seed=5)
        self.assertGreater(counts[0], 60)


if __name__ == "__main__":
    unittest.main()
