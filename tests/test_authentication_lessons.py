from __future__ import annotations

import hmac
import unittest

from crypto_lab.authentication import (
    AuthenticationError,
    EncryptThenMAC,
    cbc_mac,
    cbc_mac_length_extension_forgery,
    hmac_sha256,
    verify_cbc_mac,
    verify_hmac,
)
from crypto_lab.feistel import FeistelMessage, ToyFeistelCipher
from crypto_lab.hashing import (
    birthday_collision_search,
    length_extension_attack,
    toy_hash,
    verify_length_extension,
)
from crypto_lab.rsa import RSAKeyPair
from crypto_lab.signatures import (
    DSAKeyPair,
    ECDSAKeyPair,
    dsa_recover_private_key_from_reused_nonce,
    dsa_sign,
    dsa_verify,
    ecdsa_recover_private_key_from_reused_nonce,
    ecdsa_sign,
    ecdsa_verify,
    lamport_keygen,
    lamport_sign,
    lamport_verify,
    rsa_sign,
    rsa_verify,
)


class HashLessonTests(unittest.TestCase):
    def test_merkle_damgard_length_extension(self) -> None:
        original = b"role=user"
        extension = b"&role=admin"
        forged = length_extension_attack(toy_hash(original), len(original), extension)
        self.assertTrue(verify_length_extension(original, forged))
        self.assertEqual(forged.forged_suffix, forged.glue_padding + extension)
        self.assertNotEqual(forged.digest, toy_hash(original + extension))

    def test_wrong_length_guess_does_not_verify(self) -> None:
        original = b"prefix=secret;role=user"
        forged = length_extension_attack(
            toy_hash(original), len(original) + 1, b";admin=1"
        )
        self.assertFalse(verify_length_extension(original, forged))

    def test_seeded_birthday_search_is_reproducible(self) -> None:
        first = birthday_collision_search(seed=17, digest_bits=12)
        second = birthday_collision_search(seed=17, digest_bits=12)
        self.assertEqual(first, second)
        self.assertEqual(
            int.from_bytes(toy_hash(first.message1), "big") & 0x0FFF,
            int.from_bytes(toy_hash(first.message2), "big") & 0x0FFF,
        )


class AuthenticationLessonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cipher = ToyFeistelCipher(0x1334_5779_9BBC_DFF1)

    def test_hmac_sha256_known_answer(self) -> None:
        key = b"\x0b" * 20
        message = b"Hi There"
        expected = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7"
        )
        self.assertEqual(hmac_sha256(key, message), expected)
        self.assertEqual(hmac_sha256(key, message), hmac.new(key, message, "sha256").digest())
        self.assertTrue(verify_hmac(key, message, expected))
        self.assertFalse(verify_hmac(key, message + b"!", expected))

    def test_cbc_mac_requires_full_blocks_and_forges_variable_length(self) -> None:
        original = b"amount=10".ljust(16, b" ")
        extension = b";admin=true".ljust(16, b" ")
        original_tag = cbc_mac(original, self.cipher)
        extension_tag = cbc_mac(extension, self.cipher)
        forgery = cbc_mac_length_extension_forgery(
            original,
            original_tag,
            extension,
            self.cipher,
            extension_tag=extension_tag,
        )
        self.assertTrue(verify_cbc_mac(forgery.message, forgery.tag, self.cipher))
        with self.assertRaises(ValueError):
            cbc_mac(b"short", self.cipher)

    def test_encrypt_then_mac_rejects_ciphertext_and_iv_tampering(self) -> None:
        etm = EncryptThenMAC(self.cipher, b"classroom mac key")
        message = etm.encrypt(b"authenticated message", iv=bytes(8))
        self.assertEqual(etm.decrypt(message), b"authenticated message")
        tampered = FeistelMessage(
            message.encrypted.ciphertext[:-1] + bytes([message.encrypted.ciphertext[-1] ^ 1]),
            message.encrypted.mode,
            message.encrypted.iv,
        )
        with self.assertRaises(AuthenticationError):
            etm.decrypt(type(message)(tampered, message.tag))


class SignatureLessonTests(unittest.TestCase):
    def test_textbook_rsa_hash_and_sign(self) -> None:
        keys = RSAKeyPair.from_primes(61, 53, public_exponent=17)
        signature = rsa_sign(b"signed lesson", keys)
        self.assertTrue(rsa_verify(b"signed lesson", signature, keys))
        self.assertFalse(rsa_verify(b"tampered lesson", signature, keys))

    def test_lamport_signature_is_seeded_and_message_bound(self) -> None:
        first = lamport_keygen(seed=123)
        second = lamport_keygen(seed=123)
        self.assertEqual(first, second)
        signature = lamport_sign(first.private, b"one-time message")
        self.assertTrue(lamport_verify(first.public, b"one-time message", signature))
        self.assertFalse(lamport_verify(first.public, b"changed message", signature))
        self.assertEqual(len(signature.values), 256)

    def test_dsa_reused_nonce_recovers_private_key(self) -> None:
        keys = DSAKeyPair.generate(private_key=7)
        first = dsa_sign(b"a", keys, nonce=3)
        second = dsa_sign(b"b", keys, nonce=3)
        self.assertTrue(dsa_verify(b"a", first, keys))
        self.assertEqual(
            dsa_recover_private_key_from_reused_nonce(
                b"a", first, b"b", second, keys.parameters
            ),
            keys.private,
        )

    def test_ecdsa_reused_nonce_recovers_private_key(self) -> None:
        keys = ECDSAKeyPair.generate(private_key=5)
        first = ecdsa_sign(b"first", keys, nonce=3)
        second = ecdsa_sign(b"second", keys, nonce=3)
        self.assertTrue(ecdsa_verify(b"first", first, keys))
        self.assertEqual(
            ecdsa_recover_private_key_from_reused_nonce(
                b"first", first, b"second", second, keys.parameters
            ),
            keys.private,
        )


if __name__ == "__main__":
    unittest.main()
