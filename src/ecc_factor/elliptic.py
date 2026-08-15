"""Elliptic-curve arithmetic over integers modulo ``n``.

The modulus need not be prime. A failed modular inverse exposes a divisor of
``n``; ECM uses that failure to discover factors.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd


class NonInvertibleError(ArithmeticError):
    """Raised when a curve operation needs a non-invertible denominator."""

    def __init__(self, denominator: int, modulus: int, divisor: int) -> None:
        self.denominator = denominator
        self.modulus = modulus
        self.divisor = divisor
        super().__init__(
            f"{denominator} has no inverse modulo {modulus}; gcd={divisor}"
        )


@dataclass(frozen=True, slots=True)
class Point:
    x: int | None
    y: int | None

    def __post_init__(self) -> None:
        if (self.x is None) != (self.y is None):
            raise ValueError("a point must have both coordinates or be infinity")

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


INFINITY = Point(None, None)


@dataclass(frozen=True, slots=True)
class Curve:
    """The short Weierstrass curve ``y² = x³ + ax + b (mod n)``."""

    a: int
    b: int
    modulus: int

    def __post_init__(self) -> None:
        if self.modulus < 2:
            raise ValueError("modulus must be at least 2")
        object.__setattr__(self, "a", self.a % self.modulus)
        object.__setattr__(self, "b", self.b % self.modulus)

    @property
    def discriminant(self) -> int:
        return (-16 * (4 * self.a**3 + 27 * self.b**2)) % self.modulus

    def contains(self, point: Point) -> bool:
        if point.is_infinity:
            return True
        assert point.x is not None and point.y is not None
        return (
            point.y**2 - point.x**3 - self.a * point.x - self.b
        ) % self.modulus == 0

    def add(self, left: Point, right: Point) -> Point:
        if not self.contains(left) or not self.contains(right):
            raise ValueError("point is not on this curve")
        if left.is_infinity:
            return right
        if right.is_infinity:
            return left

        assert left.x is not None and left.y is not None
        assert right.x is not None and right.y is not None
        n = self.modulus
        left = Point(left.x % n, left.y % n)
        right = Point(right.x % n, right.y % n)

        if left.x == right.x and (left.y + right.y) % n == 0:
            return INFINITY
        if left == right:
            numerator = 3 * left.x**2 + self.a
            denominator = 2 * left.y
        else:
            numerator = right.y - left.y
            denominator = right.x - left.x

        divisor = gcd(denominator, n)
        if divisor != 1:
            raise NonInvertibleError(denominator, n, divisor)

        slope = numerator * pow(denominator, -1, n) % n
        x = (slope**2 - left.x - right.x) % n
        y = (slope * (left.x - x) - left.y) % n
        return Point(x, y)

    def multiply(self, scalar: int, point: Point) -> Point:
        """Return ``scalar * point`` using double-and-add."""

        if scalar < 0:
            if point.is_infinity:
                return point
            assert point.x is not None and point.y is not None
            return self.multiply(-scalar, Point(point.x, -point.y % self.modulus))

        result = INFINITY
        addend = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            scalar >>= 1
            if scalar:
                addend = self.add(addend, addend)
        return result


__all__ = ["Curve", "INFINITY", "NonInvertibleError", "Point"]
