"""Executable security games and intentionally insecure teaching schemes."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from random import Random
from typing import Protocol

from .trace import TraceCallback, emit


class TeachingEncryptionScheme(Protocol):
    def encrypt(self, plaintext: bytes, randomness: Random) -> bytes: ...


def _mask(key: bytes, context: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(key, context + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        )
        counter += 1
    return bytes(output[:length])


@dataclass(frozen=True, slots=True)
class DeterministicXorScheme:
    """A deterministic scheme designed to lose the IND-CPA equality game."""

    key: bytes

    def encrypt(self, plaintext: bytes, randomness: Random) -> bytes:
        mask = _mask(self.key, b"deterministic", len(plaintext))
        return bytes(value ^ pad for value, pad in zip(plaintext, mask, strict=True))


@dataclass(frozen=True, slots=True)
class RandomNonceXorScheme:
    """A randomized comparison scheme for the equality-pattern lesson."""

    key: bytes
    nonce_size: int = 16

    def encrypt(self, plaintext: bytes, randomness: Random) -> bytes:
        nonce = randomness.randbytes(self.nonce_size)
        mask = _mask(self.key, nonce, len(plaintext))
        ciphertext = bytes(
            value ^ pad for value, pad in zip(plaintext, mask, strict=True)
        )
        return nonce + ciphertext


@dataclass(frozen=True, slots=True)
class SecurityGameResult:
    game: str
    trials: int
    wins: int

    @property
    def success_rate(self) -> float:
        return self.wins / self.trials

    @property
    def distinguishing_advantage(self) -> float:
        return abs(2 * self.success_rate - 1)


def run_ind_cpa_equality_game(
    scheme: TeachingEncryptionScheme,
    left_message: bytes,
    right_message: bytes,
    *,
    trials: int = 1_000,
    seed: int = 0,
    trace: TraceCallback | None = None,
) -> SecurityGameResult:
    """Estimate a fixed equality adversary's IND-CPA success probability.

    The adversary first queries encryption of the left message, then guesses
    "left" exactly when the challenge ciphertext is byte-for-byte identical.
    """

    if trials < 1:
        raise ValueError("trials must be positive")
    if len(left_message) != len(right_message) or left_message == right_message:
        raise ValueError("challenge messages must be distinct and equally long")
    randomness = Random(seed)
    wins = 0
    for trial in range(trials):
        reference = scheme.encrypt(left_message, randomness)
        hidden_bit = randomness.randrange(2)
        selected = (left_message, right_message)[hidden_bit]
        challenge = scheme.encrypt(selected, randomness)
        guess = 0 if challenge == reference else 1
        wins += guess == hidden_bit
        if trial < 10:
            emit(
                trace,
                "security.ind_cpa_trial",
                f"trial {trial}: hidden={hidden_bit}, guess={guess}",
                level=2,
                trial=trial,
                hidden_bit=hidden_bit,
                guess=guess,
                won=guess == hidden_bit,
            )
    result = SecurityGameResult("ind-cpa-equality", trials, wins)
    emit(
        trace,
        "security.game_complete",
        f"adversary won {wins}/{trials}; advantage={result.distinguishing_advantage:.3f}",
        trials=trials,
        wins=wins,
        success_rate=result.success_rate,
        advantage=result.distinguishing_advantage,
    )
    return result


__all__ = [
    "DeterministicXorScheme",
    "RandomNonceXorScheme",
    "SecurityGameResult",
    "TeachingEncryptionScheme",
    "run_ind_cpa_equality_game",
]

