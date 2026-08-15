from __future__ import annotations

import unittest

from crypto_lab.algebra import (
    chinese_remainder_theorem,
    euler_phi,
    gf256_inverse,
    gf256_multiply,
    is_primitive_root,
    multiplicative_order,
    primitive_root,
)
from crypto_lab.discrete_log import (
    baby_step_giant_step,
    pohlig_hellman,
    pollard_rho_discrete_log,
)
from crypto_lab.elliptic import Curve, Point
from crypto_lab.key_exchange import (
    DHParameters,
    ECDHParameters,
    demonstrate_small_subgroup_attack,
    dh_shared_secret,
    diffie_hellman,
    ecdh_shared_secret,
    elgamal_decrypt,
    elgamal_encrypt,
    generate_dh_keypair,
    generate_ecdh_keypair,
    generate_elgamal_keypair,
    validate_dh_public_key,
)
from crypto_lab.secret_sharing import Share, shamir_recover, shamir_split


class AlgebraTests(unittest.TestCase):
    def test_crt_and_totient(self) -> None:
        self.assertEqual(chinese_remainder_theorem(((2, 3), (3, 5), (2, 7))), (23, 105))
        self.assertEqual(euler_phi(36), 12)
        self.assertEqual(euler_phi(2**4 * 13**2, {2: 4, 13: 2}), 2**3 * 12 * 13)

    def test_orders_and_primitive_roots(self) -> None:
        self.assertEqual(multiplicative_order(2, 7), 3)
        self.assertTrue(is_primitive_root(3, 7))
        self.assertFalse(is_primitive_root(2, 7))
        self.assertEqual(primitive_root(7), 3)

    def test_aes_field_known_products_and_inverse(self) -> None:
        self.assertEqual(gf256_multiply(0x57, 0x83), 0xC1)
        self.assertEqual(gf256_multiply(0x53, gf256_inverse(0x53)), 1)
        with self.assertRaises(ZeroDivisionError):
            gf256_inverse(0)


class DiscreteLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.p = 23
        self.g = 5
        self.target = pow(self.g, 6, self.p)

    def test_three_discrete_logorithms_recover_same_exponent(self) -> None:
        self.assertEqual(baby_step_giant_step(self.g, self.target, self.p), 6)
        self.assertEqual(pohlig_hellman(self.g, self.target, self.p), 6)
        self.assertEqual(
            pollard_rho_discrete_log(self.g, self.target, self.p, seed=4),
            6,
        )

    def test_discrete_log_outside_subgroup_is_none(self) -> None:
        # 4 has order 11 modulo 23; 5 generates the order-22 group.
        self.assertIsNone(baby_step_giant_step(4, 5, self.p))


class KeyExchangeTests(unittest.TestCase):
    def test_finite_field_dh(self) -> None:
        self.assertEqual(diffie_hellman(23, 5, 6, 15), 2)
        parameters = DHParameters(23, 5)
        alice = generate_dh_keypair(parameters, 6)
        bob = generate_dh_keypair(parameters, 15)
        self.assertEqual(dh_shared_secret(parameters, alice.private, bob.public), 2)
        self.assertEqual(dh_shared_secret(parameters, bob.private, alice.public), 2)
        with self.assertRaises(ValueError):
            validate_dh_public_key(parameters, 1)

    def test_ecdh_with_explicit_point_order(self) -> None:
        curve = Curve(2, 2, 17)
        base = Point(5, 1)
        parameters = ECDHParameters(curve, base, base_order=19, curve_order=19)
        alice = generate_ecdh_keypair(parameters, 5)
        bob = generate_ecdh_keypair(parameters, 7)
        self.assertEqual(ecdh_shared_secret(parameters, alice.private, bob.public), Point(10, 11))
        self.assertEqual(ecdh_shared_secret(parameters, bob.private, alice.public), Point(10, 11))

    def test_elgamal_round_trip_and_small_subgroup_lesson(self) -> None:
        keys = generate_elgamal_keypair(23, 5, 6)
        ciphertext = elgamal_encrypt(keys.public, 7, 9)
        self.assertEqual(elgamal_decrypt(keys.private, ciphertext), 7)
        attack = demonstrate_small_subgroup_attack(23, 7, 22, 2)
        self.assertEqual(attack.recovered_residue, 1)


class ShamirTests(unittest.TestCase):
    def test_seeded_split_is_reproducible_and_recovers(self) -> None:
        first = shamir_split(123, 3, 5, 257, seed=9)
        second = shamir_split(123, 3, 5, 257, seed=9)
        self.assertEqual(first, second)
        self.assertEqual(shamir_recover(first[:3], 257), 123)
        self.assertEqual(shamir_recover((Share(x, y) for x, y in first[1:4]), 257), 123)

    def test_insufficient_or_duplicate_shares_rejected(self) -> None:
        shares = shamir_split(42, 3, 4, 257, seed=1)
        with self.assertRaises(ValueError):
            shamir_recover((), 257)
        with self.assertRaises(ValueError):
            shamir_recover((shares[0], shares[0]), 257)


if __name__ == "__main__":
    unittest.main()
