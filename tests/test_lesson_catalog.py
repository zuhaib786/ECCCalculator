"""Tests for the first-course curriculum catalogue."""

from __future__ import annotations

import json
import unittest

from crypto_lab.lessons import (
    LESSONS,
    Lesson,
    as_dict,
    get_lesson,
    list_lessons,
    topological_order,
    validate_prerequisites,
)


class LessonCatalogTests(unittest.TestCase):
    def test_slugs_are_unique_and_catalog_is_nontrivial(self) -> None:
        slugs = [lesson.slug for lesson in LESSONS]
        self.assertGreaterEqual(len(LESSONS), 25)
        self.assertEqual(len(slugs), len(set(slugs)))
        self.assertTrue(validate_prerequisites())

    def test_every_prerequisite_precedes_its_lesson(self) -> None:
        positions = {lesson.slug: index for index, lesson in enumerate(LESSONS)}
        for lesson in LESSONS:
            for prerequisite in lesson.prerequisites:
                self.assertLess(positions[prerequisite], positions[lesson.slug])
        self.assertEqual(tuple(lesson.slug for lesson in topological_order()), tuple(positions))

    def test_required_first_course_topics_are_present(self) -> None:
        text = " ".join(
            " ".join((lesson.slug, lesson.title, lesson.summary, *lesson.concepts))
            for lesson in LESSONS
        ).lower()
        for concept in (
            "representation",
            "classical",
            "perfect secrecy",
            "randomness",
            "symmetric",
            "aes",
            "stream",
            "hash",
            "mac",
            "aead",
            "number theory",
            "primality",
            "factoring",
            "discrete-log",
            "diffie-hellman",
            "elgamal",
            "ecc",
            "rsa",
            "signatures",
            "certificates",
            "tls",
            "secret sharing",
            "zero-knowledge",
            "mpc",
            "post-quantum",
            "bb84",
        ):
            self.assertIn(concept, text)

    def test_advanced_lessons_contain_academic_warning(self) -> None:
        advanced = [lesson for lesson in LESSONS if lesson.unit == "advanced topics"]
        self.assertEqual({lesson.slug for lesson in advanced}, {"zero-knowledge", "secure-mpc", "post-quantum", "bb84"})
        for lesson in advanced:
            summary = lesson.summary.lower()
            self.assertTrue("optional advanced" in summary)
            self.assertIn("educational only", summary)

    def test_lookup_and_unit_filter(self) -> None:
        self.assertIs(get_lesson("aes"), next(lesson for lesson in LESSONS if lesson.slug == "aes"))
        self.assertTrue(all(lesson.unit == "advanced topics" for lesson in list_lessons(unit="advanced topics")))
        with self.assertRaises(KeyError):
            get_lesson("does-not-exist")

    def test_lesson_is_immutable_and_serializable(self) -> None:
        lesson = get_lesson("representation")
        with self.assertRaises((AttributeError, TypeError)):
            lesson.title = "changed"  # type: ignore[misc]
        payload = as_dict()
        encoded = json.dumps(payload)
        self.assertIn('"slug": "representation"', encoded)
        self.assertIsInstance(payload[0]["concepts"], list)

    def test_invalid_graphs_are_rejected(self) -> None:
        first = Lesson("first", "First", "unit", "summary")
        second = Lesson("second", "Second", "unit", "summary", prerequisites=("missing",))
        with self.assertRaises(ValueError):
            validate_prerequisites((first, second))
        cycle_a = Lesson("a", "A", "unit", "summary", prerequisites=("b",))
        cycle_b = Lesson("b", "B", "unit", "summary", prerequisites=("a",))
        with self.assertRaises(ValueError):
            validate_prerequisites((cycle_a, cycle_b))


if __name__ == "__main__":
    unittest.main()
