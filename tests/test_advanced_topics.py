from __future__ import annotations

import unittest

from crypto_lab.advanced_topics import (
    additive_share,
    lwe_decrypt_bit,
    lwe_encrypt_bit,
    lwe_keygen,
    mpc_secure_sum,
    reconstruct_additive,
    schnorr_prove,
    schnorr_public_key,
    schnorr_verify,
    simulate_bb84,
    simulate_schnorr_transcript,
)


class ZeroKnowledgeTests(unittest.TestCase):
    def test_real_and_simulated_schnorr_transcripts_verify(self) -> None:
        prime, order, generator, secret = 23, 11, 2, 7
        public = schnorr_public_key(secret, prime=prime, generator=generator)
        real = schnorr_prove(
            secret,
            nonce=4,
            challenge=3,
            prime=prime,
            subgroup_order=order,
            generator=generator,
        )
        simulated = simulate_schnorr_transcript(
            public,
            challenge=3,
            response=5,
            prime=prime,
            generator=generator,
        )
        self.assertTrue(schnorr_verify(public, real, prime=prime, generator=generator))
        self.assertTrue(schnorr_verify(public, simulated, prime=prime, generator=generator))


class PostQuantumAndMpcTests(unittest.TestCase):
    def test_toy_lwe_bit_round_trip(self) -> None:
        keys = lwe_keygen(seed=9)
        for bit in (0, 1):
            ciphertext = lwe_encrypt_bit(bit, keys.public, seed=20 + bit)
            self.assertEqual(lwe_decrypt_bit(ciphertext, keys), bit)

    def test_additive_sharing_and_secure_sum(self) -> None:
        shares = additive_share(42, 4, 101, seed=3)
        self.assertEqual(reconstruct_additive(shares, 101), 42)
        self.assertEqual(mpc_secure_sum((10, 20, 30), 101, seed=4), 60)


class QuantumKeyDistributionTests(unittest.TestCase):
    def test_clean_channel_has_no_sifted_errors(self) -> None:
        clean = simulate_bb84(500, seed=7)
        self.assertEqual(clean.error_rate, 0.0)

    def test_intercept_resend_introduces_detectable_errors(self) -> None:
        attacked = simulate_bb84(1_000, seed=7, intercept_probability=1.0)
        self.assertGreater(attacked.error_rate, 0.15)
        self.assertLess(attacked.error_rate, 0.35)


if __name__ == "__main__":
    unittest.main()

