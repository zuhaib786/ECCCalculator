"""Integer factorization algorithms exposed by the public SDK."""

from __future__ import annotations

from collections import Counter
from math import gcd, isqrt
from random import Random, SystemRandom
from typing import Literal

from .elliptic import Curve, NonInvertibleError, Point
from .events import FactorizationEvent, ProgressCallback

Method = Literal["auto", "trial", "rho", "ecm", "cfrac"]


class FactorizationError(RuntimeError):
    """Raised when an algorithm exhausts its configured search budget."""


class _Reporter:
    def __init__(self, callback: ProgressCallback | None) -> None:
        self.callback = callback

    def emit(self, code: str, message: str, level: int = 1, **data: object) -> None:
        if self.callback is not None:
            self.callback(FactorizationEvent(code, message, level, data))


def is_probable_prime(number: int) -> bool:
    """Return whether ``number`` is prime (deterministic below ``2**64``)."""

    if number < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if number in small_primes:
        return True
    if any(number % prime == 0 for prime in small_primes):
        return False

    odd_part = number - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        powers_of_two += 1
        odd_part //= 2

    if number < 2**64:
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        bases = small_primes
    for base in bases:
        if base % number == 0:
            continue
        value = pow(base, odd_part, number)
        if value in (1, number - 1):
            continue
        for _ in range(powers_of_two - 1):
            value = value * value % number
            if value == number - 1:
                break
        else:
            return False
    return True


def _primes_up_to(limit: int) -> list[int]:
    if limit < 2:
        return []
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[:2] = b"\x00\x00"
    for value in range(2, isqrt(limit) + 1):
        if sieve[value]:
            start = value * value
            sieve[start : limit + 1 : value] = b"\x00" * (
                (limit - start) // value + 1
            )
    return [value for value, prime in enumerate(sieve) if prime]


def _trial_factor(number: int, reporter: _Reporter) -> int:
    if number % 2 == 0:
        return 2
    candidate = 3
    while candidate <= isqrt(number):
        if number % candidate == 0:
            return candidate
        if candidate % 10_000 == 1:
            reporter.emit(
                "trial.progress",
                f"trial division reached {candidate}",
                level=2,
                candidate=candidate,
            )
        candidate += 2
    return number


def _pollard_rho(
    number: int,
    rng: Random,
    reporter: _Reporter,
    *,
    attempts: int = 32,
) -> int:
    """Find a non-trivial factor using Brent's Pollard-rho variant."""

    for prime in (2, 3, 5):
        if number % prime == 0:
            return prime

    for attempt in range(1, attempts + 1):
        y = rng.randrange(1, number)
        constant = rng.randrange(1, number)
        batch_size = rng.randrange(32, 129)
        divisor = 1
        cycle_length = 1
        reporter.emit(
            "rho.attempt",
            f"Pollard rho attempt {attempt}",
            attempt=attempt,
            constant=constant,
        )

        while divisor == 1:
            x = y
            for _ in range(cycle_length):
                y = (y * y + constant) % number
            offset = 0
            while offset < cycle_length and divisor == 1:
                saved_y = y
                product = 1
                for _ in range(min(batch_size, cycle_length - offset)):
                    y = (y * y + constant) % number
                    product = product * abs(x - y) % number
                divisor = gcd(product, number)
                offset += batch_size
            reporter.emit(
                "rho.cycle",
                f"completed rho cycle of length {cycle_length}",
                level=2,
                cycle_length=cycle_length,
            )
            cycle_length *= 2

        if divisor == number:
            while True:
                saved_y = (saved_y * saved_y + constant) % number
                divisor = gcd(abs(x - saved_y), number)
                if divisor > 1:
                    break
        if divisor != number:
            return divisor

    raise FactorizationError(
        f"Pollard rho did not find a factor of {number} after {attempts} attempts"
    )


def _ecm(
    number: int,
    rng: Random,
    reporter: _Reporter,
    *,
    bound: int,
    curves: int,
) -> int:
    """Find a factor using stage-one Lenstra ECM."""

    prime_powers: list[int] = []
    for prime in _primes_up_to(bound):
        power = prime
        while power * prime <= bound:
            power *= prime
        prime_powers.append(power)

    for curve_number in range(1, curves + 1):
        x = rng.randrange(1, number)
        y = rng.randrange(1, number)
        a = rng.randrange(1, number)
        b = (y * y - x * x * x - a * x) % number
        curve = Curve(a, b, number)
        discriminant_gcd = gcd(curve.discriminant, number)
        reporter.emit(
            "ecm.curve",
            f"ECM curve {curve_number}/{curves}: y^2 = x^3 + {a}x + {b} (mod n)",
            curve=curve_number,
            bound=bound,
            a=a,
            b=b,
            start_x=x,
            start_y=y,
            discriminant_gcd=discriminant_gcd,
        )
        if 1 < discriminant_gcd < number:
            reporter.emit(
                "ecm.discriminant_factor",
                f"curve discriminant revealed gcd {discriminant_gcd}",
                factor=discriminant_gcd,
                curve=curve_number,
            )
            return discriminant_gcd
        if discriminant_gcd == number:
            continue

        point = Point(x, y)
        try:
            for index, power in enumerate(prime_powers, start=1):
                point = curve.multiply(power, point)
                reporter.emit(
                    "ecm.multiply",
                    f"multiply by prime power {power} ({index}/{len(prime_powers)})",
                    level=2,
                    curve=curve_number,
                    power=power,
                    completed=index,
                    total=len(prime_powers),
                    point_x=point.x,
                    point_y=point.y,
                )
                if index % 25 == 0:
                    reporter.emit(
                        "ecm.progress",
                        f"processed {index}/{len(prime_powers)} prime powers",
                        level=2,
                        curve=curve_number,
                        completed=index,
                        total=len(prime_powers),
                    )
        except NonInvertibleError as error:
            reporter.emit(
                "ecm.inverse_failure",
                f"inverse failed: gcd({error.denominator}, n) = {error.divisor}",
                curve=curve_number,
                denominator=error.denominator,
                factor=error.divisor,
                modulus=number,
            )
            if 1 < error.divisor < number:
                return error.divisor

    raise FactorizationError(
        f"ECM did not find a factor of {number} using {curves} curves "
        f"with bound {bound}"
    )


def _continued_fraction_factor(
    number: int,
    reporter: _Reporter,
    *,
    bound: int,
    max_steps: int,
) -> int:
    """Find a factor with the continued-fraction factorization method (CFRAC)."""

    root = isqrt(number)
    if root * root == number:
        return root

    factor_base = [2]
    for prime in _primes_up_to(bound):
        if prime == 2:
            continue
        if number % prime == 0:
            return prime
        # Euler's criterion selects primes for which n is a quadratic residue.
        if pow(number % prime, (prime - 1) // 2, prime) == 1:
            factor_base.append(prime)
    reporter.emit(
        "cfrac.factor_base",
        f"CFRAC factor base has {len(factor_base)} primes up to {bound}",
        bound=bound,
        factor_base=tuple(factor_base),
    )

    # Each relation stores (convergent numerator modulo n, signed exponents).
    relations: list[tuple[int, tuple[int, ...]]] = []
    # Gaussian-elimination rows map a pivot bit to (parity vector, relation mask).
    basis: dict[int, tuple[int, int]] = {}

    m, denominator, coefficient = 0, 1, root
    numerator_older, numerator_old = 0, 1
    denominator_older, denominator_old = 1, 0

    for step in range(max_steps):
        numerator = coefficient * numerator_old + numerator_older
        convergent_denominator = coefficient * denominator_old + denominator_older
        residue = numerator * numerator - number * convergent_denominator**2
        reporter.emit(
            "cfrac.convergent",
            f"convergent {step}: residue {residue}",
            level=2,
            step=step,
            numerator=numerator,
            denominator=convergent_denominator,
            residue=residue,
        )

        exponents = [1 if residue < 0 else 0]
        remainder = abs(residue)
        for prime in factor_base:
            exponent = 0
            while remainder and remainder % prime == 0:
                remainder //= prime
                exponent += 1
            exponents.append(exponent)

        if remainder == 1:
            relation_index = len(relations)
            relation_exponents = tuple(exponents)
            relations.append((numerator % number, relation_exponents))
            parity = 0
            for index, exponent in enumerate(relation_exponents):
                if exponent & 1:
                    parity |= 1 << index
            reporter.emit(
                "cfrac.relation",
                f"smooth relation {relation_index + 1}: residue {residue}",
                relation=relation_index,
                step=step,
                numerator=numerator % number,
                residue=residue,
                exponents=relation_exponents,
                parity=parity,
            )

            vector = parity
            combination = 1 << relation_index
            while vector:
                pivot = vector.bit_length() - 1
                if pivot not in basis:
                    basis[pivot] = (vector, combination)
                    break
                row, row_combination = basis[pivot]
                vector ^= row
                combination ^= row_combination

            if vector == 0:
                selected = tuple(
                    index
                    for index in range(len(relations))
                    if combination & (1 << index)
                )
                reporter.emit(
                    "cfrac.dependency",
                    f"parity dependency combines relations {selected}",
                    relations=selected,
                )
                x_value = 1
                exponent_totals = [0] * (len(factor_base) + 1)
                for index in selected:
                    relation_numerator, relation_powers = relations[index]
                    x_value = x_value * relation_numerator % number
                    exponent_totals = [
                        total + exponent
                        for total, exponent in zip(
                            exponent_totals, relation_powers, strict=True
                        )
                    ]
                y_value = 1
                for prime, exponent in zip(
                    factor_base, exponent_totals[1:], strict=True
                ):
                    y_value = y_value * pow(prime, exponent // 2, number) % number
                for difference in (x_value - y_value, x_value + y_value):
                    divisor = gcd(abs(difference), number)
                    reporter.emit(
                        "cfrac.gcd",
                        f"gcd({abs(difference)}, n) = {divisor}",
                        x=x_value,
                        y=y_value,
                        divisor=divisor,
                    )
                    if 1 < divisor < number:
                        return divisor

        numerator_older, numerator_old = numerator_old, numerator
        denominator_older, denominator_old = denominator_old, convergent_denominator
        m = denominator * coefficient - m
        denominator = (number - m * m) // denominator
        coefficient = (root + m) // denominator

    raise FactorizationError(
        f"CFRAC did not find a factor of {number} after {max_steps} convergents "
        f"with factor-base bound {bound}"
    )


def _strip_small_factors(
    number: int,
    factors: list[int],
    reporter: _Reporter,
    limit: int,
) -> int:
    for prime in _primes_up_to(limit):
        while number % prime == 0:
            factors.append(prime)
            number //= prime
            reporter.emit(
                "factor.found",
                f"found factor {prime}",
                factor=prime,
                remainder=number,
            )
    return number


def factorize(
    number: int,
    *,
    method: Method = "auto",
    seed: int | None = None,
    progress: ProgressCallback | None = None,
    trial_limit: int = 100,
    ecm_bound: int = 2_000,
    ecm_curves: int = 50,
    cfrac_bound: int = 100,
    cfrac_steps: int = 10_000,
) -> tuple[int, ...]:
    """Return the prime factors of ``number`` in ascending order.

    The SDK is silent by default. Pass a ``progress`` callback to receive
    structured events. ``seed`` makes randomized methods reproducible.

    Args:
        number: Integer to factor; must be at least 2.
        method: ``auto``, ``trial``, ``rho``, ``ecm``, or ``cfrac``.
        seed: Optional seed for Pollard rho and ECM.
        progress: Optional callback for :class:`FactorizationEvent` objects.
        trial_limit: Small-prime preprocessing limit (ignored by ``trial``).
        ecm_bound: Stage-one smoothness bound used by ECM.
        ecm_curves: Maximum number of random curves tried by ECM.
        cfrac_bound: Largest prime considered for CFRAC smooth relations.
        cfrac_steps: Maximum continued-fraction convergents considered by CFRAC.
    """

    if isinstance(number, bool) or not isinstance(number, int):
        raise TypeError("number must be an integer")
    if number < 2:
        raise ValueError("number must be at least 2")
    if method not in {"auto", "trial", "rho", "ecm", "cfrac"}:
        raise ValueError(f"unknown factorization method: {method}")
    if trial_limit < 2:
        raise ValueError("trial_limit must be at least 2")
    if ecm_bound < 2 or ecm_curves < 1:
        raise ValueError("ecm_bound must be >= 2 and ecm_curves must be >= 1")
    if cfrac_bound < 2 or cfrac_steps < 1:
        raise ValueError("cfrac_bound must be >= 2 and cfrac_steps must be >= 1")

    reporter = _Reporter(progress)
    rng: Random = Random(seed) if seed is not None else SystemRandom()
    factors: list[int] = []
    reporter.emit("factor.start", f"factoring {number} with {method}", number=number)

    if method == "trial":
        remainder = number
    else:
        remainder = _strip_small_factors(number, factors, reporter, trial_limit)

    pending = [remainder] if remainder > 1 else []
    while pending:
        current = pending.pop()
        if is_probable_prime(current):
            factors.append(current)
            reporter.emit(
                "factor.prime",
                f"confirmed prime factor {current}",
                factor=current,
            )
            continue

        selected = method
        if selected == "auto":
            selected = "ecm" if current.bit_length() >= 80 else "rho"
        reporter.emit(
            "algorithm.start",
            f"using {selected} on {current}",
            algorithm=selected,
            composite=current,
        )
        if selected == "trial":
            divisor = _trial_factor(current, reporter)
        elif selected == "rho":
            divisor = _pollard_rho(current, rng, reporter)
        elif selected == "ecm":
            try:
                divisor = _ecm(
                    current,
                    rng,
                    reporter,
                    bound=ecm_bound,
                    curves=ecm_curves,
                )
            except FactorizationError:
                if method != "auto":
                    raise
                reporter.emit(
                    "ecm.fallback",
                    "ECM budget exhausted; falling back to Pollard rho",
                )
                divisor = _pollard_rho(current, rng, reporter)
        else:
            divisor = _continued_fraction_factor(
                current,
                reporter,
                bound=cfrac_bound,
                max_steps=cfrac_steps,
            )

        reporter.emit(
            "factor.split",
            f"split {current} into {divisor} and {current // divisor}",
            composite=current,
            factor=divisor,
            cofactor=current // divisor,
        )
        pending.extend((divisor, current // divisor))

    factors.sort()
    reporter.emit("factor.complete", f"factorization complete: {factors}", factors=factors)
    return tuple(factors)


def factor_counts(number: int, **kwargs: object) -> dict[int, int]:
    """Return ``{prime: exponent}`` for ``number`` in ascending key order."""

    return dict(Counter(factorize(number, **kwargs)))


__all__ = [
    "FactorizationError",
    "Method",
    "factor_counts",
    "factorize",
    "is_probable_prime",
]
