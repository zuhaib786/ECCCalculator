from __future__ import annotations

import unittest

from crypto_lab.protocols import (
    ReplayCache,
    TeachingCertificateAuthority,
    hybrid_decrypt,
    hybrid_encrypt,
    simplified_tls_handshake,
)
from crypto_lab.rsa import RSAKeyPair


class ProtocolLessonsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = RSAKeyPair.from_primes(3557, 2579)

    def test_hybrid_kem_dem_round_trip(self) -> None:
        packet = hybrid_encrypt(b"hybrid encryption lesson", self.keys.public, seed=19)
        self.assertEqual(hybrid_decrypt(packet, self.keys.private), b"hybrid encryption lesson")

    def test_teaching_certificate_and_tamper_detection(self) -> None:
        authority = TeachingCertificateAuthority("Classroom CA", self.keys)
        subject_key = RSAKeyPair.from_primes(61, 53, public_exponent=17).public
        certificate = authority.issue("alice.example", subject_key)
        self.assertTrue(authority.verify(certificate))
        tampered = certificate.__class__(
            "mallory.example",
            certificate.modulus,
            certificate.exponent,
            certificate.issuer,
            certificate.signature,
        )
        self.assertFalse(authority.verify(tampered))

    def test_simplified_tls_transcript(self) -> None:
        events = []
        transcript = simplified_tls_handshake(
            prime=23,
            generator=5,
            client_private=6,
            server_private=15,
            client_nonce=b"client nonce",
            server_nonce=b"server nonce",
            trace=events.append,
        )
        self.assertEqual(transcript.client_public, 8)
        self.assertEqual(transcript.server_public, 19)
        self.assertEqual(transcript.shared_secret, 2)
        self.assertEqual(events[-1].code, "protocol.finished")

    def test_replay_cache(self) -> None:
        cache = ReplayCache()
        self.assertTrue(cache.accept(b"unique nonce"))
        self.assertFalse(cache.accept(b"unique nonce"))


if __name__ == "__main__":
    unittest.main()

