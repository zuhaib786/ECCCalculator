"""Randomness, entropy, and key-derivation lessons."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from collections.abc import Mapping
from random import Random

from .trace import TraceCallback, emit


def insecure_prng_bytes(seed: int, length: int) -> bytes:
    """Generate reproducible bytes to demonstrate why seeded PRNGs are predictable."""

    if length < 0:
        raise ValueError("length must be non-negative")
    generator = Random(seed)
    return bytes(generator.randrange(256) for _ in range(length))


def secure_random_bytes(length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    return secrets.token_bytes(length)


def shannon_entropy(counts: Mapping[object, int]) -> float:
    """Return Shannon entropy in bits for an observed frequency table."""

    if any(count < 0 for count in counts.values()):
        raise ValueError("counts must be non-negative")
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
        if count
    )


def min_entropy(counts: Mapping[object, int]) -> float:
    """Return min-entropy, measuring the most likely outcome."""

    if any(count < 0 for count in counts.values()):
        raise ValueError("counts must be non-negative")
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -math.log2(max(counts.values()) / total)


def hkdf_extract(
    input_key_material: bytes,
    salt: bytes = b"",
    *,
    hash_name: str = "sha256",
) -> bytes:
    digest_size = hashlib.new(hash_name).digest_size
    effective_salt = salt or bytes(digest_size)
    return hmac.new(effective_salt, input_key_material, hash_name).digest()


def hkdf_expand(
    pseudorandom_key: bytes,
    length: int,
    info: bytes = b"",
    *,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bytes:
    """Expand an HKDF pseudorandom key according to RFC 5869."""

    digest_size = hashlib.new(hash_name).digest_size
    if not 0 <= length <= 255 * digest_size:
        raise ValueError("HKDF output length is out of range")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes([counter]), hash_name
        ).digest()
        output.extend(previous)
        emit(
            trace,
            "hkdf.block",
            f"HKDF expand block {counter}: {previous.hex()}",
            level=2,
            block=counter,
            value=previous.hex(),
        )
        counter += 1
    result = bytes(output[:length])
    emit(trace, "hkdf.complete", f"derived {length} bytes", length=length, output=result.hex())
    return result


def hkdf(
    input_key_material: bytes,
    length: int,
    *,
    salt: bytes = b"",
    info: bytes = b"",
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bytes:
    return hkdf_expand(
        hkdf_extract(input_key_material, salt, hash_name=hash_name),
        length,
        info,
        hash_name=hash_name,
        trace=trace,
    )


def derive_password_key(
    password: str,
    salt: bytes,
    *,
    iterations: int = 100_000,
    length: int = 32,
    hash_name: str = "sha256",
) -> bytes:
    """Expose PBKDF2 parameters; production policies must choose current costs."""

    if not salt:
        raise ValueError("password derivation requires a non-empty salt")
    if iterations < 1 or length < 1:
        raise ValueError("iterations and length must be positive")
    return hashlib.pbkdf2_hmac(
        hash_name, password.encode("utf-8"), salt, iterations, dklen=length
    )


__all__ = [
    "derive_password_key",
    "hkdf",
    "hkdf_expand",
    "hkdf_extract",
    "insecure_prng_bytes",
    "min_entropy",
    "secure_random_bytes",
    "shannon_entropy",
]

