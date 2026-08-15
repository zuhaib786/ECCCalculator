from __future__ import annotations

import unittest

from ecc_factor import factor_counts, factorize, is_probable_prime
from ecc_factor.elliptic import Curve, NonInvertibleError, Point


class FactorizationTests(unittest.TestCase):
    def test_primality(self) -> None:
        self.assertTrue(is_probable_prime(2**61 - 1))
        self.assertFalse(is_probable_prime(3 * (2**61 - 1)))

    def test_trial_division(self) -> None:
        self.assertEqual(factorize(2 * 2 * 3 * 17, method="trial"), (2, 2, 3, 17))

    def test_pollard_rho(self) -> None:
        self.assertEqual(
            factorize(1_000_003 * 1_000_033, method="rho", seed=7),
            (1_000_003, 1_000_033),
        )

    def test_ecm(self) -> None:
        self.assertEqual(
            factorize(1_009 * 10_007, method="ecm", seed=11, ecm_bound=200),
            (1_009, 10_007),
        )

    def test_continued_fraction_factorization(self) -> None:
        events = []
        self.assertEqual(
            factorize(
                1_009 * 1_013,
                method="cfrac",
                cfrac_bound=50,
                progress=events.append,
            ),
            (1_009, 1_013),
        )
        codes = [event.code for event in events]
        self.assertIn("cfrac.convergent", codes)
        self.assertIn("cfrac.relation", codes)
        self.assertIn("cfrac.dependency", codes)
        self.assertIn("cfrac.gcd", codes)

    def test_factor_counts(self) -> None:
        self.assertEqual(factor_counts(2**4 * 13**2), {2: 4, 13: 2})

    def test_progress_is_opt_in_and_structured(self) -> None:
        events = []
        factorize(91, progress=events.append)
        self.assertEqual(events[0].code, "factor.start")
        self.assertEqual(events[-1].code, "factor.complete")

    def test_rejects_invalid_input(self) -> None:
        with self.assertRaises(ValueError):
            factorize(1)


class EllipticCurveTests(unittest.TestCase):
    def test_add_and_multiply(self) -> None:
        curve = Curve(2, 3, 97)
        point = Point(3, 6)
        self.assertTrue(curve.contains(point))
        self.assertEqual(curve.multiply(2, point), Point(80, 10))

    def test_coordinates_are_normalized(self) -> None:
        curve = Curve(2, 3, 97)
        self.assertEqual(curve.add(Point(100, 103), Point(3, 6)), Point(80, 10))

    def test_failed_inverse_exposes_factor(self) -> None:
        curve = Curve(1, 0, 15)
        with self.assertRaises(NonInvertibleError) as raised:
            curve.add(Point(0, 0), Point(5, 5))
        self.assertEqual(raised.exception.divisor, 5)


if __name__ == "__main__":
    unittest.main()
