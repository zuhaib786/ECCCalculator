from __future__ import annotations

import unittest

from examples.ecm_animation_data import (
    LARGE_PRIME,
    LONG_COMPOSITE,
    SMALL_FACTOR,
    build_ecm_story,
)


class ManimEcmStoryTests(unittest.TestCase):
    def test_story_uses_a_real_reproducible_ecm_trace(self) -> None:
        factors, events = build_ecm_story()
        codes = [event.code for event in events]

        self.assertGreaterEqual(len(str(LONG_COMPOSITE)), 40)
        self.assertEqual(LONG_COMPOSITE, SMALL_FACTOR * LARGE_PRIME)
        self.assertEqual(factors, (SMALL_FACTOR, LARGE_PRIME))
        self.assertIn("ecm.curve", codes)
        self.assertIn("ecm.multiply", codes)
        self.assertIn("ecm.inverse_failure", codes)
        self.assertIn("factor.split", codes)


if __name__ == "__main__":
    unittest.main()

