"""Comparative primality tests commonly taught in cryptography courses."""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd, isqrt
from random import Random
from typing import Iterable, Literal

from .trace import TraceCallback, TraceEvent, emit

PrimalityMethod = Literal["trial", "fermat", "miller-rabin", "solovay-strassen"]


@dataclass(frozen=True, slots=True)
class PrimalityResult:
    number: int
    method: PrimalityMethod
    probably_prime: bool
    deterministic: bool
    bases: tuple[int, ...]
    witness: int | None = None


def jacobi_symbol(value: int, odd_modulus: int) -> int:
    """Return the Jacobi symbol ``(value / odd_modulus)``."""

    if odd_modulus <= 0 or odd_modulus % 2 == 0:
        raise ValueError("Jacobi modulus must be a positive odd integer")
    value %= odd_modulus
    result = 1
    while value:
        while value % 2 == 0:
            value //= 2
            if odd_modulus % 8 in (3, 5):
                result = -result
        value, odd_modulus = odd_modulus, value
        if value % 4 == odd_modulus % 4 == 3:
            result = -result
        value %= odd_modulus
    return result if odd_modulus == 1 else 0


def _validate_bases(number: int, bases: Iterable[int]) -> tuple[int, ...]:
    selected = tuple(bases)
    if number > 4 and any(not 2 <= base <= number - 2 for base in selected):
        raise ValueError(f"bases must satisfy 2 <= base <= {number - 2}")
    return selected


def trial_primality_test(number: int, *, trace: TraceCallback | None = None) -> bool:
    """Test primality exactly by searching through ``sqrt(n)``."""

    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0:
        emit(trace, "primality.witness", "2 divides the candidate", witness=2)
        return False
    for candidate in range(3, isqrt(number) + 1, 2):
        emit(
            trace,
            "primality.trial",
            f"try divisor {candidate}",
            level=2,
            candidate=candidate,
        )
        if number % candidate == 0:
            emit(
                trace,
                "primality.witness",
                f"{candidate} divides the candidate",
                witness=candidate,
            )
            return False
    return True


def fermat_test(
    number: int,
    bases: Iterable[int],
    *,
    trace: TraceCallback | None = None,
) -> bool:
    """Apply Fermat's congruence for each base."""

    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0:
        emit(trace, "primality.witness", "2 divides the candidate", witness=2)
        return False
    for base in _validate_bases(number, bases):
        remainder = pow(base, number - 1, number)
        emit(
            trace,
            "primality.fermat_round",
            f"base {base}: {base}^(n-1) mod n = {remainder}",
            level=2,
            base=base,
            remainder=remainder,
        )
        if remainder != 1:
            emit(
                trace,
                "primality.witness",
                f"base {base} proves the number composite",
                witness=base,
            )
            return False
    return True


def miller_rabin_test(
    number: int,
    bases: Iterable[int],
    *,
    trace: TraceCallback | None = None,
) -> bool:
    """Apply the strong Miller-Rabin probable-prime test for each base."""

    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0:
        emit(trace, "primality.witness", "2 divides the candidate", witness=2)
        return False
    odd_part = number - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        powers_of_two += 1
        odd_part //= 2

    for base in _validate_bases(number, bases):
        value = pow(base, odd_part, number)
        chain = [value]
        passed = value in (1, number - 1)
        for _ in range(powers_of_two - 1):
            if passed:
                break
            value = value * value % number
            chain.append(value)
            if value == number - 1:
                passed = True
        emit(
            trace,
            "primality.miller_rabin_round",
            f"base {base}: strong-remainder chain {chain}",
            level=2,
            base=base,
            chain=tuple(chain),
            passed=passed,
        )
        if not passed:
            emit(
                trace,
                "primality.witness",
                f"base {base} proves the number composite",
                witness=base,
            )
            return False
    return True


def solovay_strassen_test(
    number: int,
    bases: Iterable[int],
    *,
    trace: TraceCallback | None = None,
) -> bool:
    """Compare Euler's criterion with the Jacobi symbol for each base."""

    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0:
        emit(trace, "primality.witness", "2 divides the candidate", witness=2)
        return False
    for base in _validate_bases(number, bases):
        symbol = jacobi_symbol(base, number)
        euler_value = pow(base, (number - 1) // 2, number)
        passed = gcd(base, number) == 1 and euler_value == symbol % number
        emit(
            trace,
            "primality.solovay_strassen_round",
            f"base {base}: Euler={euler_value}, Jacobi={symbol}",
            level=2,
            base=base,
            euler_value=euler_value,
            jacobi=symbol,
            passed=passed,
        )
        if not passed:
            emit(
                trace,
                "primality.witness",
                f"base {base} proves the number composite",
                witness=base,
            )
            return False
    return True


def check_primality(
    number: int,
    *,
    method: PrimalityMethod = "miller-rabin",
    rounds: int = 8,
    seed: int | None = None,
    bases: Iterable[int] | None = None,
    trace: TraceCallback | None = None,
) -> PrimalityResult:
    """Run one teaching test and return its assumptions with the verdict."""

    if method not in {"trial", "fermat", "miller-rabin", "solovay-strassen"}:
        raise ValueError(f"unknown primality method: {method}")
    if rounds < 1:
        raise ValueError("rounds must be positive")

    witness: int | None = None

    def capture(event: TraceEvent) -> None:
        nonlocal witness
        if event.code == "primality.witness":
            witness = int(event.data["witness"])
        if trace is not None:
            trace(event)

    if method == "trial":
        verdict = trial_primality_test(number, trace=capture)
        selected_bases: tuple[int, ...] = ()
        deterministic = True
    else:
        if bases is not None:
            selected_bases = tuple(bases)
        elif method == "miller-rabin" and 4 < number < 2**64:
            canonical = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
            reduced = (base % number for base in canonical)
            selected_bases = tuple(base for base in reduced if 1 < base < number - 1)
        elif number > 4:
            rng = Random(seed)
            selected_bases = tuple(rng.randrange(2, number - 1) for _ in range(rounds))
        else:
            selected_bases = ()
        if number > 4 and not selected_bases:
            raise ValueError("at least one base is required")

        if method == "fermat":
            verdict = fermat_test(number, selected_bases, trace=capture)
        elif method == "miller-rabin":
            verdict = miller_rabin_test(number, selected_bases, trace=capture)
        else:
            verdict = solovay_strassen_test(number, selected_bases, trace=capture)
        deterministic = method == "miller-rabin" and number < 2**64 and bases is None

    emit(
        trace,
        "primality.complete",
        f"{number} is {'probably prime' if verdict else 'composite'} by {method}",
        number=number,
        method=method,
        probably_prime=verdict,
        deterministic=deterministic,
    )
    return PrimalityResult(
        number,
        method,
        verdict,
        deterministic,
        selected_bases,
        witness,
    )


__all__ = [
    "PrimalityMethod",
    "PrimalityResult",
    "check_primality",
    "fermat_test",
    "jacobi_symbol",
    "miller_rabin_test",
    "solovay_strassen_test",
    "trial_primality_test",
]
