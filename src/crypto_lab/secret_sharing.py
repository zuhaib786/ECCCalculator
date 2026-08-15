"""Shamir threshold secret sharing over a prime field.

The implementation is intentionally small enough to follow on a whiteboard:
the secret is the constant term of a random polynomial and each share is one
point on that polynomial.  It is an educational implementation, not a secure
secret-storage service.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from random import Random, SystemRandom

from ecc_factor import is_probable_prime

from .number_theory import mod_inverse
from .trace import TraceCallback, emit


@dataclass(frozen=True, slots=True)
class Share:
    """One Shamir share ``(index, value)``."""

    index: int
    value: int

    @property
    def x(self) -> int:
        return self.index

    @property
    def y(self) -> int:
        return self.value

    def __iter__(self):
        yield self.index
        yield self.value


ShamirShare = Share


def polynomial_evaluate(
    coefficients: Iterable[int],
    x: int,
    prime: int,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Evaluate a polynomial in ascending coefficient order modulo ``prime``."""

    _validate_prime(prime)
    _integer(x, "x")
    selected = tuple(coefficient % prime for coefficient in coefficients)
    if not selected:
        raise ValueError("polynomial must have at least one coefficient")
    result = 0
    for degree, coefficient in reversed(tuple(enumerate(selected))):
        result = (result * x + coefficient) % prime
        emit(
            trace,
            "shamir.evaluate",
            f"Horner step degree {degree}: {result}",
            level=2,
            degree=degree,
            coefficient=coefficient,
            result=result,
        )
    return result


def shamir_split(
    secret: int,
    threshold: int,
    share_count: int,
    prime: int,
    *,
    seed: int | None = None,
    coefficients: Iterable[int] | None = None,
    trace: TraceCallback | None = None,
) -> tuple[Share, ...]:
    """Split ``secret`` into ``share_count`` shares, requiring ``threshold``.

    ``seed`` makes the randomly selected polynomial reproducible for lessons
    and tests.  Alternatively, pass all coefficients after the constant term
    explicitly; this is useful when walking through a known polynomial.
    """

    _integer(secret, "secret")
    _integer(threshold, "threshold")
    _integer(share_count, "share_count")
    _validate_prime(prime)
    if not 0 <= secret < prime:
        raise ValueError("secret must satisfy 0 <= secret < prime")
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if share_count < threshold:
        raise ValueError("share_count must be at least threshold")
    if share_count >= prime:
        raise ValueError("share_count must be less than the field prime")
    if seed is not None and coefficients is not None:
        raise ValueError("choose either seed or coefficients, not both")

    if coefficients is None:
        rng = Random(seed) if seed is not None else SystemRandom()
        if threshold == 1:
            selected_coefficients = (secret,)
        else:
            random_coefficients = [rng.randrange(prime) for _ in range(threshold - 2)]
            # The leading coefficient must be non-zero, otherwise the effective
            # threshold silently drops below the requested value.
            leading = rng.randrange(1, prime)
            selected_coefficients = (secret, *random_coefficients, leading)
    else:
        tail = tuple(coefficients)
        if len(tail) != threshold - 1:
            raise ValueError("coefficients must contain threshold - 1 entries")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in tail):
            raise TypeError("coefficients must be integers")
        if threshold > 1 and tail[-1] % prime == 0:
            raise ValueError("leading coefficient must be non-zero modulo prime")
        selected_coefficients = (secret, *(value % prime for value in tail))

    emit(
        trace,
        "shamir.polynomial",
        f"selected polynomial of degree {threshold - 1}",
        threshold=threshold,
        coefficients=tuple(selected_coefficients),
        prime=prime,
    )
    result: list[Share] = []
    for index in range(1, share_count + 1):
        value = polynomial_evaluate(selected_coefficients, index, prime)
        share = Share(index, value)
        result.append(share)
        emit(
            trace,
            "shamir.share",
            f"share {index}: ({index}, {value})",
            level=2,
            index=index,
            value=value,
        )
    emit(
        trace,
        "shamir.split.complete",
        f"created {share_count} Shamir shares",
        threshold=threshold,
        share_count=share_count,
    )
    return tuple(result)


def shamir_recover(
    shares: Iterable[Share | tuple[int, int]],
    prime: int,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Recover the polynomial's constant term with Lagrange interpolation."""

    _validate_prime(prime)
    selected = tuple(_coerce_share(share) for share in shares)
    if not selected:
        raise ValueError("at least one share is required")
    indices = [share.index for share in selected]
    if len(set(indices)) != len(indices):
        raise ValueError("share indices must be distinct")
    if any(index <= 0 or index >= prime for index in indices):
        raise ValueError("share indices must be non-zero field elements")
    if any(value < 0 or value >= prime for value in (share.value for share in selected)):
        raise ValueError("share values must lie in the field")

    secret = 0
    for position, share in enumerate(selected):
        numerator = 1
        denominator = 1
        for other_position, other in enumerate(selected):
            if position == other_position:
                continue
            numerator = numerator * (-other.index) % prime
            denominator = denominator * (share.index - other.index) % prime
        coefficient = numerator * mod_inverse(denominator, prime) % prime
        contribution = share.value * coefficient % prime
        secret = (secret + contribution) % prime
        emit(
            trace,
            "shamir.lagrange",
            f"share {share.index}: lambda={coefficient}, contribution={contribution}",
            level=2,
            index=share.index,
            numerator=numerator,
            denominator=denominator,
            coefficient=coefficient,
            contribution=contribution,
            partial=secret,
        )
    emit(trace, "shamir.recover.complete", f"recovered secret = {secret}", secret=secret, shares=len(selected))
    return secret


def lagrange_interpolate_zero(
    shares: Iterable[Share | tuple[int, int]],
    prime: int,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Alias emphasizing that recovery evaluates the interpolated polynomial at 0."""

    return shamir_recover(shares, prime, trace=trace)


def _coerce_share(value: Share | tuple[int, int]) -> Share:
    if isinstance(value, Share):
        return value
    try:
        index, share_value = value
    except (TypeError, ValueError) as error:
        raise TypeError("shares must be Share objects or (index, value) pairs") from error
    _integer(index, "share index")
    _integer(share_value, "share value")
    return Share(index, share_value)


def _integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")


def _validate_prime(prime: int) -> None:
    _integer(prime, "prime")
    if prime < 3 or not is_probable_prime(prime):
        raise ValueError("prime must be an odd prime")


split_secret = shamir_split
recover_secret = shamir_recover
split_shamir = shamir_split
recover_shamir = shamir_recover
shamir_secret_split = shamir_split
shamir_secret_recover = shamir_recover


__all__ = [
    "Share",
    "ShamirShare",
    "lagrange_interpolate_zero",
    "polynomial_evaluate",
    "recover_secret",
    "recover_shamir",
    "shamir_recover",
    "shamir_split",
    "shamir_secret_recover",
    "shamir_secret_split",
    "split_shamir",
    "split_secret",
]
