"""Inspectable stream-cipher components and failure demonstrations."""

from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
from random import Random

from .trace import TraceCallback, emit


@dataclass(slots=True)
class LFSR:
    """A Fibonacci LFSR; useful for linearity lessons, never for real security."""

    state: int
    width: int
    taps: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.width < 2:
            raise ValueError("width must be at least 2")
        if not 0 < self.state < 1 << self.width:
            raise ValueError("state must be a nonzero value fitting the width")
        if not self.taps or any(not 0 <= tap < self.width for tap in self.taps):
            raise ValueError("tap positions must be within the register")

    def step(self, *, trace: TraceCallback | None = None) -> int:
        output = self.state & 1
        feedback = 0
        for tap in self.taps:
            feedback ^= self.state >> tap & 1
        previous = self.state
        self.state = (self.state >> 1) | (feedback << (self.width - 1))
        emit(
            trace,
            "lfsr.step",
            f"{previous:0{self.width}b} -> {self.state:0{self.width}b}; bit={output}",
            level=2,
            previous=previous,
            state=self.state,
            output=output,
            feedback=feedback,
        )
        return output

    def bits(self, count: int, *, trace: TraceCallback | None = None) -> tuple[int, ...]:
        if count < 0:
            raise ValueError("count must be non-negative")
        return tuple(self.step(trace=trace) for _ in range(count))


def rc4_transform(
    data: bytes, key: bytes, *, trace: TraceCallback | None = None
) -> bytes:
    """Run RC4 KSA/PRGA for historical analysis; RC4 is obsolete and unsafe."""

    if not key:
        raise ValueError("RC4 key must not be empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    emit(trace, "rc4.ksa_complete", "RC4 key scheduling complete", state=tuple(state))
    i = j = 0
    output = bytearray()
    for index, value in enumerate(data):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        mask = state[(state[i] + state[j]) % 256]
        output.append(value ^ mask)
        emit(
            trace,
            "rc4.byte",
            f"byte {index}: keystream={mask:02x}",
            level=2,
            index=index,
            keystream=mask,
            input=value,
            output=value ^ mask,
        )
    return bytes(output)


def _rotate_left_32(value: int, distance: int) -> int:
    return ((value << distance) | (value >> (32 - distance))) & 0xFFFF_FFFF


def chacha_quarter_round(
    a: int,
    b: int,
    c: int,
    d: int,
    *,
    trace: TraceCallback | None = None,
) -> tuple[int, int, int, int]:
    """Apply the ChaCha quarter-round from the standard ARX construction."""

    values = (a, b, c, d)
    if any(not 0 <= value <= 0xFFFF_FFFF for value in values):
        raise ValueError("ChaCha words must fit in 32 bits")
    a = (a + b) & 0xFFFF_FFFF
    d = _rotate_left_32(d ^ a, 16)
    c = (c + d) & 0xFFFF_FFFF
    b = _rotate_left_32(b ^ c, 12)
    a = (a + b) & 0xFFFF_FFFF
    d = _rotate_left_32(d ^ a, 8)
    c = (c + d) & 0xFFFF_FFFF
    b = _rotate_left_32(b ^ c, 7)
    emit(
        trace,
        "chacha.quarter_round",
        f"quarter-round -> {a:08x} {b:08x} {c:08x} {d:08x}",
        level=2,
        a=a,
        b=b,
        c=c,
        d=d,
    )
    return a, b, c, d


def reused_keystream_xor(left_ciphertext: bytes, right_ciphertext: bytes) -> bytes:
    """Recover ``plaintext1 XOR plaintext2`` when a stream is reused."""

    return bytes(
        left ^ right
        for left, right in zip(left_ciphertext, right_ciphertext, strict=False)
    )


def sample_rc4_second_byte_bias(
    samples: int,
    *,
    seed: int,
    trace: TraceCallback | None = None,
) -> dict[int, int]:
    """Sample RC4's historical second-keystream-byte bias toward zero."""

    if samples < 1:
        raise ValueError("samples must be positive")
    randomness = Random(seed)
    counts: Counter[int] = Counter()
    for _ in range(samples):
        key = randomness.randbytes(16)
        second_byte = rc4_transform(b"\x00\x00", key)[1]
        counts[second_byte] += 1
    emit(
        trace,
        "rc4.bias_sample",
        f"zero appeared {counts[0]}/{samples} times as RC4's second byte",
        samples=samples,
        zero_count=counts[0],
        expected_uniform=samples / 256,
    )
    return dict(counts)


__all__ = [
    "LFSR",
    "chacha_quarter_round",
    "rc4_transform",
    "reused_keystream_xor",
    "sample_rc4_second_byte_bias",
]
