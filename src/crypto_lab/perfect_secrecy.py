"""One-time pads and finite Shannon perfect-secrecy experiments.

This module makes the probability calculation in Shannon's definition
explicit.  Spaces are deliberately tiny and uniform: the goal is to inspect
the definition, not to provide a production random-number or encryption API.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Callable, Hashable, Mapping, Sequence

from .trace import TraceCallback, emit


def _as_bytes(value: bytes | bytearray | memoryview, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)


def otp_encrypt(
    plaintext: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """XOR a message with an equal-length one-time-pad key."""

    message = _as_bytes(plaintext, "plaintext")
    pad = _as_bytes(key, "key")
    if len(message) != len(pad):
        raise ValueError("one-time-pad key must have exactly the message length")
    ciphertext = bytes(left ^ right for left, right in zip(message, pad, strict=True))
    emit(
        trace,
        "otp.encrypt",
        f"XORed {len(message)} message bytes with a one-time pad",
        length=len(message),
        plaintext=message.hex(),
        key=pad.hex(),
        ciphertext=ciphertext.hex(),
    )
    return ciphertext


def otp_decrypt(
    ciphertext: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Recover an OTP plaintext by XORing the ciphertext with its key."""

    message = _as_bytes(ciphertext, "ciphertext")
    pad = _as_bytes(key, "key")
    if len(message) != len(pad):
        raise ValueError("one-time-pad key must have exactly the ciphertext length")
    plaintext = bytes(left ^ right for left, right in zip(message, pad, strict=True))
    emit(
        trace,
        "otp.decrypt",
        f"XORed {len(message)} ciphertext bytes with a one-time pad",
        length=len(message),
        ciphertext=message.hex(),
        key=pad.hex(),
        plaintext=plaintext.hex(),
    )
    return plaintext


@dataclass(frozen=True, slots=True)
class OTPReuseAnalysis:
    """The leakage exposed when one OTP key is reused for two ciphertexts."""

    ciphertext_xor: bytes
    overlap_length: int
    known_plaintext: bytes | None = None
    recovered_plaintext: bytes | None = None

    @property
    def xor_leakage(self) -> bytes:
        """Alias for the XOR of the two ciphertexts."""

        return self.ciphertext_xor

    @property
    def recovered_message(self) -> bytes | None:
        """Alias for plaintext recovered from a known plaintext prefix."""

        return self.recovered_plaintext


def _xor_overlap(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def analyze_otp_key_reuse(
    ciphertext1: bytes | bytearray | memoryview,
    ciphertext2: bytes | bytearray | memoryview,
    *,
    known_plaintext: bytes | bytearray | memoryview | None = None,
    trace: TraceCallback | None = None,
) -> OTPReuseAnalysis:
    """Calculate ``C1 XOR C2 = P1 XOR P2`` for a reused OTP key.

    If ``known_plaintext`` is supplied, it is interpreted as a prefix of the
    first plaintext and the corresponding prefix of the second plaintext is
    recovered.  Different message lengths are allowed; only the overlap can
    leak information.
    """

    first = _as_bytes(ciphertext1, "ciphertext1")
    second = _as_bytes(ciphertext2, "ciphertext2")
    leakage = _xor_overlap(first, second)
    known = None if known_plaintext is None else _as_bytes(known_plaintext, "known_plaintext")
    recovered = None
    if known is not None:
        if len(known) > len(leakage):
            raise ValueError("known plaintext cannot exceed the ciphertext overlap")
        recovered = _xor_overlap(leakage, known)
    result = OTPReuseAnalysis(leakage, len(leakage), known, recovered)
    emit(
        trace,
        "otp.reuse",
        "reused-key ciphertexts reveal the XOR of their plaintexts",
        ciphertext1=first.hex(),
        ciphertext2=second.hex(),
        ciphertext_xor=leakage.hex(),
        overlap_length=len(leakage),
        known_plaintext=None if known is None else known.hex(),
        recovered_plaintext=None if recovered is None else recovered.hex(),
    )
    return result


def otp_xor_leakage(
    ciphertext1: bytes | bytearray | memoryview,
    ciphertext2: bytes | bytearray | memoryview,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Return the overlapping XOR leakage from two reused-key ciphertexts."""

    return analyze_otp_key_reuse(ciphertext1, ciphertext2, trace=trace).ciphertext_xor


def otp_key_reuse_attack(
    ciphertext1: bytes | bytearray | memoryview,
    ciphertext2: bytes | bytearray | memoryview,
    *,
    known_plaintext: bytes | bytearray | memoryview | None = None,
    trace: TraceCallback | None = None,
) -> bytes:
    """Return plaintext XOR, or recover the second plaintext from a known first one.

    With no known plaintext this returns ``P1 XOR P2``.  Supplying a known
    prefix of ``P1`` returns the matching recovered prefix of ``P2``.
    """

    analysis = analyze_otp_key_reuse(
        ciphertext1,
        ciphertext2,
        known_plaintext=known_plaintext,
        trace=trace,
    )
    return analysis.ciphertext_xor if analysis.recovered_plaintext is None else analysis.recovered_plaintext


one_time_pad_encrypt = otp_encrypt
one_time_pad_decrypt = otp_decrypt


FiniteValue = Hashable
EncryptFunction = Callable[[FiniteValue, FiniteValue], FiniteValue]


@dataclass(frozen=True, slots=True)
class SecrecyViolation:
    """A ciphertext whose posterior message probability differs from its prior."""

    ciphertext: Hashable
    message: Hashable
    prior: Fraction
    posterior: Fraction


@dataclass(frozen=True, slots=True)
class ShannonSecrecyReport:
    """Exact finite probability tables for a Shannon secrecy experiment."""

    message_space: tuple[FiniteValue, ...]
    key_space: tuple[FiniteValue, ...]
    ciphertext_space: tuple[FiniteValue, ...]
    prior_probabilities: Mapping[FiniteValue, Fraction]
    posterior_probabilities: Mapping[FiniteValue, Mapping[FiniteValue, Fraction]]
    joint_counts: Mapping[tuple[FiniteValue, FiniteValue], int]
    ciphertext_counts: Mapping[FiniteValue, int]
    violations: tuple[SecrecyViolation, ...]

    @property
    def is_perfectly_secret(self) -> bool:
        """Whether observing any ciphertext leaves the message distribution unchanged."""

        return not self.violations

    @property
    def perfectly_secret(self) -> bool:
        """Alias for :attr:`is_perfectly_secret`."""

        return self.is_perfectly_secret

    @property
    def prior(self) -> Mapping[FiniteValue, Fraction]:
        """Alias for the uniform message prior."""

        return self.prior_probabilities

    @property
    def posterior(self) -> Mapping[FiniteValue, Mapping[FiniteValue, Fraction]]:
        """Alias for posterior probabilities indexed by ciphertext then message."""

        return self.posterior_probabilities

    @property
    def counterexamples(self) -> tuple[SecrecyViolation, ...]:
        """Alias for posterior/prior mismatches."""

        return self.violations


def _finite_space(values: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...], name: str) -> tuple[FiniteValue, ...]:
    try:
        result = tuple(values)
    except TypeError as error:
        raise TypeError(f"{name} must be a finite iterable") from error
    if not result:
        raise ValueError(f"{name} must not be empty")
    try:
        if len(set(result)) != len(result):
            raise ValueError(f"{name} must not contain duplicates")
    except TypeError as error:
        raise TypeError(f"{name} values must be hashable") from error
    return result


def enumerate_perfect_secrecy(
    message_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    key_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    encrypt: EncryptFunction,
    *,
    trace: TraceCallback | None = None,
) -> ShannonSecrecyReport:
    """Enumerate a uniform finite encryption experiment exactly.

    The theorem tested is Shannon's condition
    ``Pr[M=m | C=c] = Pr[M=m]`` for every message and ciphertext with positive
    probability.  Every message and every key is sampled uniformly.
    """

    if not callable(encrypt):
        raise TypeError("encrypt must be callable as encrypt(message, key)")
    messages = _finite_space(message_space, "message_space")
    keys = _finite_space(key_space, "key_space")
    joint_counts: dict[tuple[FiniteValue, FiniteValue], int] = {}
    ciphertext_counts: dict[FiniteValue, int] = {}
    ciphertext_order: list[FiniteValue] = []
    for message in messages:
        for key in keys:
            ciphertext = encrypt(message, key)
            try:
                hash(ciphertext)
            except TypeError as error:
                raise TypeError("encryption outputs must be hashable") from error
            if ciphertext not in ciphertext_counts:
                ciphertext_order.append(ciphertext)
                ciphertext_counts[ciphertext] = 0
            ciphertext_counts[ciphertext] += 1
            joint_counts[(message, ciphertext)] = joint_counts.get((message, ciphertext), 0) + 1
            emit(
                trace,
                "secrecy.outcome",
                f"M={message!r}, K={key!r} -> C={ciphertext!r}",
                level=2,
                message_value=message,
                key=key,
                ciphertext=ciphertext,
            )

    prior = {message: Fraction(1, len(messages)) for message in messages}
    posterior: dict[FiniteValue, Mapping[FiniteValue, Fraction]] = {}
    violations: list[SecrecyViolation] = []
    for ciphertext in ciphertext_order:
        count = ciphertext_counts[ciphertext]
        probabilities = {
            message: Fraction(joint_counts.get((message, ciphertext), 0), count)
            for message in messages
        }
        posterior[ciphertext] = probabilities
        for message, probability in probabilities.items():
            if probability != prior[message]:
                violations.append(SecrecyViolation(ciphertext, message, prior[message], probability))
        emit(
            trace,
            "secrecy.posterior",
            f"posterior after C={ciphertext!r}: {dict(probabilities)!r}",
            ciphertext=ciphertext,
            probabilities=dict(probabilities),
        )
    report = ShannonSecrecyReport(
        messages,
        keys,
        tuple(ciphertext_order),
        prior,
        posterior,
        dict(joint_counts),
        dict(ciphertext_counts),
        tuple(violations),
    )
    emit(
        trace,
        "secrecy.complete",
        f"perfect secrecy: {report.is_perfectly_secret}",
        perfectly_secret=report.is_perfectly_secret,
        ciphertexts=tuple(ciphertext_order),
        violations=len(violations),
    )
    return report


def perfect_secrecy_experiment(
    message_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    key_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    encrypt: EncryptFunction,
    *,
    trace: TraceCallback | None = None,
) -> ShannonSecrecyReport:
    """Alias for :func:`enumerate_perfect_secrecy`."""

    return enumerate_perfect_secrecy(message_space, key_space, encrypt, trace=trace)


def shannon_perfect_secrecy(
    message_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    key_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    encrypt: EncryptFunction,
    *,
    trace: TraceCallback | None = None,
) -> bool:
    """Return Shannon's perfect-secrecy predicate for a finite uniform space."""

    return enumerate_perfect_secrecy(message_space, key_space, encrypt, trace=trace).is_perfectly_secret


def is_perfectly_secret(
    message_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    key_space: Sequence[FiniteValue] | set[FiniteValue] | tuple[FiniteValue, ...],
    encrypt: EncryptFunction,
    *,
    trace: TraceCallback | None = None,
) -> bool:
    """Alias for :func:`shannon_perfect_secrecy`."""

    return shannon_perfect_secrecy(message_space, key_space, encrypt, trace=trace)


__all__ = [
    "OTPReuseAnalysis",
    "SecrecyViolation",
    "ShannonSecrecyReport",
    "analyze_otp_key_reuse",
    "enumerate_perfect_secrecy",
    "is_perfectly_secret",
    "one_time_pad_decrypt",
    "one_time_pad_encrypt",
    "otp_decrypt",
    "otp_encrypt",
    "otp_key_reuse_attack",
    "otp_xor_leakage",
    "perfect_secrecy_experiment",
    "shannon_perfect_secrecy",
]
