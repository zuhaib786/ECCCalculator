"""Readable number-theory primitives used throughout a cryptography course."""

from __future__ import annotations

from .trace import TraceCallback, emit


def extended_gcd(left: int, right: int) -> tuple[int, int, int]:
    """Return ``(gcd, x, y)`` such that ``left*x + right*y == gcd``."""

    old_remainder, remainder = abs(left), abs(right)
    old_x, x = 1, 0
    old_y, y = 0, 1
    while remainder:
        quotient = old_remainder // remainder
        old_remainder, remainder = remainder, old_remainder - quotient * remainder
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return old_remainder, old_x if left >= 0 else -old_x, old_y if right >= 0 else -old_y


def mod_inverse(value: int, modulus: int) -> int:
    """Return the multiplicative inverse of ``value`` modulo ``modulus``."""

    if modulus < 2:
        raise ValueError("modulus must be at least 2")
    divisor, coefficient, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValueError(f"{value} has no inverse modulo {modulus}; gcd={divisor}")
    return coefficient % modulus


def mod_pow(
    base: int,
    exponent: int,
    modulus: int,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Compute modular exponentiation using visible square-and-multiply steps."""

    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    if modulus < 1:
        raise ValueError("modulus must be positive")

    result = 1 % modulus
    base %= modulus
    bit = 0
    while exponent:
        selected = bool(exponent & 1)
        if selected:
            result = result * base % modulus
        emit(
            trace,
            "modpow.bit",
            f"bit {bit}: {'multiply' if selected else 'skip'}; result={result}",
            level=2,
            bit=bit,
            selected=selected,
            result=result,
            base=base,
        )
        exponent >>= 1
        bit += 1
        if exponent:
            base = base * base % modulus
    emit(trace, "modpow.complete", f"modular power result: {result}", result=result)
    return result


__all__ = ["extended_gcd", "mod_inverse", "mod_pow"]

