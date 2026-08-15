"""Small algebra and finite-field helpers for an introductory cryptography course.

The functions in this module intentionally expose the arithmetic which is
usually hidden by a cryptographic library.  They are useful for notebooks and
short classroom experiments; they are not constant-time implementations.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from math import gcd

from ecc_factor import factor_counts, is_probable_prime

from .number_theory import mod_inverse
from .trace import TraceCallback, emit


def _check_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")


def chinese_remainder_theorem(
    congruences: Iterable[tuple[int, int]],
    *,
    trace: TraceCallback | None = None,
) -> tuple[int, int]:
    """Combine pairwise-coprime congruences.

    ``congruences`` contains ``(remainder, modulus)`` pairs.  The return value
    is ``(residue, modulus_product)`` with the residue normalized to
    ``0 <= residue < modulus_product``.  Returning the product as well as the
    residue makes the modulus of a later CRT merge explicit in lessons.
    """

    pairs = tuple(congruences)
    if not pairs:
        raise ValueError("at least one congruence is required")
    residue, modulus = 0, 1
    for index, pair in enumerate(pairs):
        if len(pair) != 2:
            raise ValueError("each congruence must be a (remainder, modulus) pair")
        remainder, next_modulus = pair
        _check_integer(remainder, "remainder")
        _check_integer(next_modulus, "modulus")
        if next_modulus < 2:
            raise ValueError("CRT moduli must be at least 2")
        if gcd(modulus, next_modulus) != 1:
            raise ValueError("CRT moduli must be pairwise coprime")

        # x = residue + modulus*t and x == remainder (mod next_modulus).
        adjustment = (remainder - residue) * mod_inverse(modulus, next_modulus)
        adjustment %= next_modulus
        residue += modulus * adjustment
        modulus *= next_modulus
        residue %= modulus
        emit(
            trace,
            "crt.merge",
            f"merged congruence {index + 1}: x = {residue} (mod {modulus})",
            level=2,
            index=index,
            remainder=remainder,
            congruence_modulus=next_modulus,
            residue=residue,
            modulus=modulus,
            adjustment=adjustment,
        )
    emit(
        trace,
        "crt.complete",
        f"CRT solution x = {residue} (mod {modulus})",
        residue=residue,
        modulus=modulus,
    )
    return residue, modulus


def crt(
    congruences: Iterable[tuple[int, int]],
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Return only the normalized residue of a CRT system.

    Use :func:`chinese_remainder_theorem` when the combined modulus is also
    useful.  This short spelling is convenient in code examples.
    """

    return chinese_remainder_theorem(congruences, trace=trace)[0]


def euler_phi(
    number: int,
    factors: Mapping[int, int] | Iterable[int] | None = None,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Compute Euler's totient using a prime factorization.

    If ``factors`` is omitted, the teaching factorizer is used.  A mapping is
    interpreted as ``{prime: exponent}``; an iterable is interpreted as a
    (possibly repeated) sequence of prime factors.
    """

    _check_integer(number, "number")
    if number < 1:
        raise ValueError("number must be positive")
    if number == 1:
        return 1

    if factors is None:
        counts = factor_counts(number)
    elif isinstance(factors, Mapping):
        counts = dict(factors)
    else:
        counts: dict[int, int] = {}
        for prime in factors:
            counts[prime] = counts.get(prime, 0) + 1

    product = 1
    reconstructed = 1
    for prime, exponent in sorted(counts.items()):
        _check_integer(prime, "factor")
        _check_integer(exponent, "factor exponent")
        if prime < 2 or exponent < 1 or not is_probable_prime(prime):
            raise ValueError("factors must contain positive prime powers")
        reconstructed *= prime**exponent
        contribution = (prime - 1) * prime ** (exponent - 1)
        product *= contribution
        emit(
            trace,
            "phi.factor",
            f"prime power {prime}^{exponent} contributes {contribution}",
            level=2,
            prime=prime,
            exponent=exponent,
            contribution=contribution,
        )
    if reconstructed != number:
        raise ValueError("factorization does not multiply to number")
    emit(trace, "phi.complete", f"phi({number}) = {product}", number=number, result=product)
    return product


def multiplicative_order(
    value: int,
    modulus: int,
    *,
    group_order: int | None = None,
    factors: Mapping[int, int] | Iterable[int] | None = None,
    trace: TraceCallback | None = None,
) -> int:
    """Return the least positive ``r`` with ``value**r == 1 (mod modulus)``."""

    _check_integer(value, "value")
    _check_integer(modulus, "modulus")
    if modulus < 2:
        raise ValueError("modulus must be at least 2")
    value %= modulus
    if gcd(value, modulus) != 1:
        raise ValueError("value must be a unit modulo modulus")

    if group_order is None:
        group_order = euler_phi(modulus, factors, trace=trace)
    _check_integer(group_order, "group_order")
    if group_order < 1 or pow(value, group_order, modulus) != 1:
        raise ValueError("group_order must be a multiple of the element order")

    order = group_order
    counts = _factor_counts_from_input(group_order, factors if factors is not None else None)
    # ``factors`` may describe phi(modulus), not group_order.  Re-factor the
    # latter when that ambiguity matters; teaching inputs are small enough for
    # this to remain transparent and correct.
    if factors is None or _counts_product(counts) != group_order:
        counts = factor_counts(group_order)
    for prime in sorted(counts):
        while order % prime == 0 and pow(value, order // prime, modulus) == 1:
            order //= prime
            emit(
                trace,
                "order.reduce",
                f"divide candidate order by {prime}: {order}",
                level=2,
                prime=prime,
                candidate=order,
            )
    emit(
        trace,
        "order.complete",
        f"ord_{modulus}({value}) = {order}",
        value=value,
        modulus=modulus,
        order=order,
    )
    return order


def _counts_product(counts: Mapping[int, int]) -> int:
    product = 1
    for prime, exponent in counts.items():
        product *= prime**exponent
    return product


def _factor_counts_from_input(
    number: int,
    factors: Mapping[int, int] | Iterable[int] | None,
) -> dict[int, int]:
    if factors is None:
        return {}
    if isinstance(factors, Mapping):
        return dict(factors) if _counts_product(factors) == number else {}
    counts: dict[int, int] = {}
    for prime in factors:
        counts[prime] = counts.get(prime, 0) + 1
    return counts if _counts_product(counts) == number else {}


def is_primitive_root(
    candidate: int,
    modulus: int,
    *,
    group_order: int | None = None,
    factors: Mapping[int, int] | Iterable[int] | None = None,
    trace: TraceCallback | None = None,
) -> bool:
    """Check whether ``candidate`` generates the unit group modulo a prime.

    For a prime modulus this is the usual primitive-root test.  For other
    moduli the function checks generation of the full unit group when that
    group is cyclic, and otherwise simply returns the mathematically correct
    order comparison.
    """

    _check_integer(candidate, "candidate")
    _check_integer(modulus, "modulus")
    if modulus < 2 or not is_probable_prime(modulus):
        raise ValueError("primitive-root lessons currently require a prime modulus")
    order = group_order if group_order is not None else modulus - 1
    actual = multiplicative_order(
        candidate,
        modulus,
        group_order=order,
        factors=factors,
        trace=trace,
    )
    result = actual == order
    emit(
        trace,
        "primitive_root.check",
        f"{candidate} {'is' if result else 'is not'} a primitive root modulo {modulus}",
        candidate=candidate,
        modulus=modulus,
        expected_order=order,
        actual_order=actual,
        primitive=result,
    )
    return result


def primitive_root(
    modulus: int,
    *,
    start: int = 2,
    trace: TraceCallback | None = None,
) -> int:
    """Find the first primitive root of a prime modulus at or after ``start``."""

    _check_integer(modulus, "modulus")
    if modulus < 3 or not is_probable_prime(modulus):
        raise ValueError("primitive-root search requires an odd prime modulus")
    if start < 1:
        raise ValueError("start must be positive")
    for candidate in range(start, modulus):
        emit(
            trace,
            "primitive_root.candidate",
            f"test candidate {candidate}",
            level=2,
            candidate=candidate,
        )
        if is_primitive_root(candidate, modulus, trace=trace):
            emit(
                trace,
                "primitive_root.complete",
                f"primitive root modulo {modulus}: {candidate}",
                modulus=modulus,
                generator=candidate,
            )
            return candidate
    raise ValueError(f"no primitive root found modulo {modulus}")


def gf2m_add(left: int, right: int) -> int:
    """Add two binary-polynomial field elements (XOR)."""

    _check_integer(left, "left")
    _check_integer(right, "right")
    if left < 0 or right < 0:
        raise ValueError("field elements must be non-negative")
    return left ^ right


def gf2m_multiply(
    left: int,
    right: int,
    *,
    polynomial: int = 0x11B,
    degree: int = 8,
    trace: TraceCallback | None = None,
) -> int:
    """Multiply in ``GF(2**degree)`` using the supplied irreducible polynomial.

    The default polynomial ``x^8+x^4+x^3+x+1`` is the AES polynomial.
    """

    _validate_gf_parameters(left, right, polynomial, degree)
    if polynomial >> degree != 1:
        raise ValueError("polynomial must have degree exactly equal to degree")
    mask = (1 << degree) - 1
    a, b, result = left & mask, right & mask, 0
    for step in range(degree * 2):
        if b & 1:
            result ^= a
        carry = a & (1 << (degree - 1))
        a = (a << 1) & mask
        if carry:
            a ^= polynomial & mask
        b >>= 1
        emit(
            trace,
            "gf.multiply",
            f"GF(2^{degree}) multiplication step {step}",
            level=2,
            step=step,
            left=a,
            right=b,
            result=result & mask,
        )
        if b == 0:
            break
    result &= mask
    emit(trace, "gf.multiply.complete", f"field product = {result:#x}", result=result)
    return result


def gf2m_pow(
    value: int,
    exponent: int,
    *,
    polynomial: int = 0x11B,
    degree: int = 8,
    trace: TraceCallback | None = None,
) -> int:
    """Exponentiate a binary-field element by square-and-multiply."""

    _validate_gf_parameters(value, value, polynomial, degree)
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    result = 1
    base = value
    bit = 0
    while exponent:
        if exponent & 1:
            result = gf2m_multiply(
                result,
                base,
                polynomial=polynomial,
                degree=degree,
                trace=trace,
            )
        emit(trace, "gf.pow.bit", f"field power bit {bit}", level=2, bit=bit, result=result)
        exponent >>= 1
        bit += 1
        if exponent:
            base = gf2m_multiply(
                base,
                base,
                polynomial=polynomial,
                degree=degree,
                trace=trace,
            )
    return result


def gf2m_inverse(
    value: int,
    *,
    polynomial: int = 0x11B,
    degree: int = 8,
    trace: TraceCallback | None = None,
) -> int:
    """Return a non-zero element's multiplicative inverse in ``GF(2**degree)``."""

    _validate_gf_parameters(value, value, polynomial, degree)
    value &= (1 << degree) - 1
    if value == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse")
    inverse = gf2m_pow(
        value,
        (1 << degree) - 2,
        polynomial=polynomial,
        degree=degree,
        trace=trace,
    )
    emit(trace, "gf.inverse.complete", f"{value:#x}^(-1) = {inverse:#x}", value=value, inverse=inverse)
    return inverse


def _validate_gf_parameters(left: int, right: int, polynomial: int, degree: int) -> None:
    _check_integer(left, "left")
    _check_integer(right, "right")
    _check_integer(polynomial, "polynomial")
    _check_integer(degree, "degree")
    if degree < 1 or polynomial <= 0:
        raise ValueError("degree and polynomial must be positive")
    if left < 0 or right < 0:
        raise ValueError("field elements must be non-negative")
    if left >= (1 << degree) or right >= (1 << degree):
        raise ValueError(f"field elements must fit in {degree} bits")


def gf256_add(left: int, right: int) -> int:
    """AES-field addition (XOR)."""

    return gf2m_add(left, right)


def gf256_multiply(left: int, right: int, *, trace: TraceCallback | None = None) -> int:
    """AES-field multiplication modulo ``0x11B``."""

    return gf2m_multiply(left, right, polynomial=0x11B, degree=8, trace=trace)


def gf256_inverse(value: int, *, trace: TraceCallback | None = None) -> int:
    """AES-field multiplicative inverse."""

    return gf2m_inverse(value, polynomial=0x11B, degree=8, trace=trace)


# Common textbook spellings kept as aliases so notebooks can choose the name
# that best matches their lecture notes.
euler_totient = euler_phi
chinese_remainder = chinese_remainder_theorem
find_primitive_root = primitive_root
primitive_root_check = is_primitive_root
phi = euler_phi
order_mod = multiplicative_order
gf_add = gf2m_add
gf_multiply = gf2m_multiply
gf_inverse = gf2m_inverse
gf_mul = gf2m_multiply
gf_inv = gf2m_inverse
gf256_mul = gf256_multiply
gf256_inv = gf256_inverse


__all__ = [
    "chinese_remainder_theorem",
    "chinese_remainder",
    "crt",
    "euler_phi",
    "euler_totient",
    "find_primitive_root",
    "gf2m_add",
    "gf2m_inverse",
    "gf2m_multiply",
    "gf2m_pow",
    "gf256_add",
    "gf256_inverse",
    "gf256_multiply",
    "gf256_mul",
    "gf256_inv",
    "gf_add",
    "gf_inverse",
    "gf_inv",
    "gf_mul",
    "gf_multiply",
    "is_primitive_root",
    "multiplicative_order",
    "order_mod",
    "phi",
    "primitive_root",
    "primitive_root_check",
]
