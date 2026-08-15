"""Inspectable hash-function lessons.

The constructions in this module are deliberately small and insecure.  They
are useful for showing how Merkle--Damgard padding, compression, collisions,
and length extension fit together, but they must never be used to protect
real data.  The practical HMAC implementation lives in :mod:`authentication`.

All algorithms are silent by default.  Pass a :class:`~crypto_lab.trace.TraceCallback`
to receive structured events instead of relying on ``print`` statements.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Final

from .trace import TraceCallback, emit


EDUCATIONAL_WARNING: Final[str] = (
    "Educational hash constructions only; do not use them to protect real data."
)

# The deliberately tiny construction works on 64-bit chaining values and
# eight-byte blocks.  Keeping the values small makes traces and classroom
# examples easy to inspect while still making the padding attack realistic.
TOY_HASH_BLOCK_SIZE: Final[int] = 8
TOY_HASH_DIGEST_SIZE: Final[int] = 8
TOY_HASH_INITIAL_STATE: Final[int] = 0x243F6A8885A308D3
_MASK64: Final[int] = (1 << 64) - 1
_ROUND_CONSTANT: Final[int] = 0x9E3779B97F4A7C15


def _rotl64(value: int, distance: int) -> int:
    distance %= 64
    return ((value << distance) | (value >> (64 - distance))) & _MASK64


def toy_md_padding(message_length: int, block_size: int = TOY_HASH_BLOCK_SIZE) -> bytes:
    """Return Merkle--Damgard glue padding for a message length in bytes.

    The final length field is the usual big-endian bit length.  This helper is
    public because length-extension exercises need students to calculate the
    exact bytes an attacker appends without knowing the secret prefix.
    """

    if message_length < 0:
        raise ValueError("message_length must be non-negative")
    if block_size != TOY_HASH_BLOCK_SIZE:
        raise ValueError("the toy hash uses an 8-byte block size")
    # Eight bytes are reserved for the length field.  (The toy construction is
    # intentionally limited to lengths representable by that field.)
    if message_length >= 1 << 61:
        raise ValueError("message_length is too large for the toy hash")
    zero_count = (-message_length - 1 - 8) % block_size
    return b"\x80" + b"\x00" * zero_count + (message_length * 8).to_bytes(8, "big")


# Friendly spelling used in notebooks.
toy_hash_padding = toy_md_padding


def toy_compress(
    state: int,
    block: bytes,
    *,
    trace: TraceCallback | None = None,
    block_index: int = 0,
) -> int:
    """Compress one full eight-byte block into a 64-bit chaining value."""

    if not 0 <= state <= _MASK64:
        raise ValueError("state must fit in 64 bits")
    if len(block) != TOY_HASH_BLOCK_SIZE:
        raise ValueError("toy hash compression requires one 8-byte block")
    word = int.from_bytes(block, "big")
    mixed = (state ^ word ^ _ROUND_CONSTANT) & _MASK64
    mixed = (mixed + _rotl64(word, 17) + ((state << 7) & _MASK64)) & _MASK64
    mixed ^= _rotl64(mixed, 23)
    mixed = (mixed * 0xD6E8FEB86659FD93) & _MASK64
    result = mixed ^ (mixed >> 29)
    emit(
        trace,
        "hash.compress",
        f"compress block {block_index}: {state:016x} -> {result:016x}",
        level=2,
        block=block_index,
        input_state=f"{state:016x}",
        block_hex=block.hex(),
        output_state=f"{result:016x}",
    )
    return result


def _compress_padded(
    padded: bytes,
    state: int,
    *,
    trace: TraceCallback | None = None,
    first_block_index: int = 0,
) -> int:
    if len(padded) % TOY_HASH_BLOCK_SIZE:
        raise ValueError("padded data must contain complete toy-hash blocks")
    for offset in range(0, len(padded), TOY_HASH_BLOCK_SIZE):
        state = toy_compress(
            state,
            padded[offset : offset + TOY_HASH_BLOCK_SIZE],
            trace=trace,
            block_index=first_block_index + offset // TOY_HASH_BLOCK_SIZE,
        )
    return state


def _state_to_digest(state: int) -> bytes:
    return state.to_bytes(TOY_HASH_DIGEST_SIZE, "big")


def toy_hash(
    message: bytes,
    *,
    trace: TraceCallback | None = None,
    initial_state: int = TOY_HASH_INITIAL_STATE,
) -> bytes:
    """Hash ``message`` with the deliberately insecure toy construction."""

    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not 0 <= initial_state <= _MASK64:
        raise ValueError("initial_state must fit in 64 bits")
    padding = toy_md_padding(len(message))
    emit(
        trace,
        "hash.padding",
        f"append {len(padding)} padding bytes to {len(message)} message bytes",
        message_length=len(message),
        padding_hex=padding.hex(),
        padded_length=len(message) + len(padding),
    )
    state = _compress_padded(message + padding, initial_state, trace=trace)
    digest = _state_to_digest(state)
    emit(
        trace,
        "hash.complete",
        f"toy digest: {digest.hex()}",
        digest=digest.hex(),
        message_length=len(message),
    )
    return digest


@dataclass(frozen=True, slots=True)
class ToyMerkleDamgard:
    """Object-oriented facade for the toy Merkle--Damgard construction."""

    initial_state: int = TOY_HASH_INITIAL_STATE

    def digest(self, message: bytes, *, trace: TraceCallback | None = None) -> bytes:
        return toy_hash(message, initial_state=self.initial_state, trace=trace)

    def hash(self, message: bytes, *, trace: TraceCallback | None = None) -> bytes:
        return self.digest(message, trace=trace)

    def compress(
        self,
        state: int,
        block: bytes,
        *,
        trace: TraceCallback | None = None,
        block_index: int = 0,
    ) -> int:
        return toy_compress(state, block, trace=trace, block_index=block_index)


ToyHash = ToyMerkleDamgard


def toy_prefix_mac(
    secret: bytes,
    message: bytes,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Educational secret-prefix MAC used to motivate length extension."""

    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    emit(
        trace,
        "hash.prefix_mac",
        "hash secret || message (insecure secret-prefix MAC)",
        secret_length=len(secret),
        message_length=len(message),
        warning="Merkle-Damgard secret-prefix MACs are length-extension vulnerable",
    )
    return toy_hash(secret + message, trace=trace)


# Common alternatives for students who call the construction a Merkle--Damgard
# hash instead of the shorter ``toy_hash`` name.
toy_merkle_damgard = toy_hash
merkle_damgard_hash = toy_hash
toy_merkle_damgard_hash = toy_hash


@dataclass(frozen=True, slots=True)
class LengthExtensionResult:
    """Result of appending data using only a digest and a length guess."""

    original_length: int
    extension: bytes
    glue_padding: bytes
    digest: bytes

    @property
    def forged_suffix(self) -> bytes:
        """Bytes an attacker appends after the unknown original message."""

        return self.glue_padding + self.extension

    @property
    def appended_message(self) -> bytes:
        """Alias for :attr:`forged_suffix` used by notebook exercises."""

        return self.forged_suffix

    @property
    def forged_message(self) -> bytes:
        """Alias for the attacker-controlled suffix.

        The unknown original bytes are intentionally absent; callers can form
        the full check as ``original || result.forged_message`` in a demo.
        """

        return self.forged_suffix


def continue_toy_hash(
    known_digest: bytes,
    processed_length: int,
    extension: bytes,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Continue hashing from a known internal state.

    ``processed_length`` must include the original message and its glue
    padding.  This is the primitive that makes a length-extension attack
    possible for Merkle--Damgard constructions.
    """

    if not isinstance(known_digest, bytes) or len(known_digest) != TOY_HASH_DIGEST_SIZE:
        raise ValueError("known_digest must be an 8-byte toy digest")
    if processed_length < 0 or processed_length % TOY_HASH_BLOCK_SIZE:
        raise ValueError("processed_length must be a non-negative block-aligned length")
    if not isinstance(extension, bytes):
        raise TypeError("extension must be bytes")
    final_padding = toy_md_padding(processed_length + len(extension))
    emit(
        trace,
        "hash.length_extension",
        "continue from the exposed internal state",
        original_processed_length=processed_length,
        extension_length=len(extension),
        final_padding_hex=final_padding.hex(),
    )
    state = int.from_bytes(known_digest, "big")
    state = _compress_padded(
        extension + final_padding,
        state,
        trace=trace,
        first_block_index=processed_length // TOY_HASH_BLOCK_SIZE,
    )
    return _state_to_digest(state)


def length_extension_attack(
    known_digest: bytes,
    original_length: int,
    extension: bytes,
    *,
    trace: TraceCallback | None = None,
) -> LengthExtensionResult:
    """Forge a toy Merkle--Damgard digest without the original message.

    ``original_length`` is a guessed byte length.  If the guess is right,
    ``toy_hash(original || result.forged_suffix)`` equals ``result.digest``.
    The function intentionally does not accept the original message: keeping
    that separation makes the attack model explicit.
    """

    if original_length < 0:
        raise ValueError("original_length must be non-negative")
    if not isinstance(extension, bytes):
        raise TypeError("extension must be bytes")
    glue = toy_md_padding(original_length)
    digest = continue_toy_hash(
        known_digest,
        original_length + len(glue),
        extension,
        trace=trace,
    )
    emit(
        trace,
        "hash.length_extension.complete",
        f"forged digest: {digest.hex()}",
        original_length=original_length,
        glue_padding_hex=glue.hex(),
        extension_hex=extension.hex(),
        digest=digest.hex(),
    )
    return LengthExtensionResult(original_length, extension, glue, digest)


# Alternate name found in many cryptography texts.
toy_length_extension = length_extension_attack
forge_toy_prefix_mac = length_extension_attack
length_extension = length_extension_attack


def verify_length_extension(
    original_message: bytes,
    result: LengthExtensionResult,
    *,
    trace: TraceCallback | None = None,
) -> bool:
    """Check a forged result against the real original message (a demo helper)."""

    if len(original_message) != result.original_length:
        return False
    expected = toy_hash(original_message + result.forged_suffix, trace=trace)
    return expected == result.digest


@dataclass(frozen=True, slots=True)
class BirthdayCollision:
    """Two deterministic messages with the same truncated toy digest."""

    message1: bytes
    message2: bytes
    digest: bytes
    digest_bits: int
    attempts: int
    seed: int | str | bytes | None

    @property
    def first_message(self) -> bytes:
        return self.message1

    @property
    def second_message(self) -> bytes:
        return self.message2

    @property
    def digest1(self) -> bytes:
        return toy_hash(self.message1)

    @property
    def digest2(self) -> bytes:
        return toy_hash(self.message2)

    @property
    def truncated_digest(self) -> bytes:
        return self.digest


def birthday_collision_search(
    *,
    seed: int | str | bytes | None = 0,
    digest_bits: int = 16,
    max_attempts: int = 100_000,
    message_size: int = 12,
    trace: TraceCallback | None = None,
) -> BirthdayCollision:
    """Find a deterministic collision in a truncated toy digest.

    A seeded ``random.Random`` is used so lectures, notebooks, and tests see
    exactly the same birthday experiment.  ``digest_bits`` intentionally
    permits short outputs so a collision can be demonstrated quickly.
    """

    if not 1 <= digest_bits <= TOY_HASH_DIGEST_SIZE * 8:
        raise ValueError("digest_bits must be between 1 and 64")
    if max_attempts < 2:
        raise ValueError("max_attempts must be at least 2")
    if message_size < 1:
        raise ValueError("message_size must be positive")
    rng = random.Random(seed)
    mask = (1 << digest_bits) - 1
    seen: dict[int, tuple[bytes, int]] = {}
    for attempt in range(1, max_attempts + 1):
        candidate = bytes(rng.getrandbits(8) for _ in range(message_size))
        full_digest = toy_hash(candidate)
        truncated = int.from_bytes(full_digest, "big") & mask
        emit(
            trace,
            "hash.birthday_attempt",
            f"attempt {attempt}: truncated digest {truncated:0{(digest_bits + 3) // 4}x}",
            level=2,
            attempt=attempt,
            candidate_message=candidate.hex(),
            digest=full_digest.hex(),
            truncated_digest=truncated,
            digest_bits=digest_bits,
        )
        previous = seen.get(truncated)
        if previous is not None and previous[0] != candidate:
            digest_bytes = truncated.to_bytes((digest_bits + 7) // 8, "big")
            emit(
                trace,
                "hash.birthday_collision",
                f"collision after {attempt} attempts: {digest_bytes.hex()}",
                attempts=attempt,
                digest=digest_bytes.hex(),
                digest_bits=digest_bits,
                message1=previous[0].hex(),
                message2=candidate.hex(),
            )
            return BirthdayCollision(
                previous[0], candidate, digest_bytes, digest_bits, attempt, seed
            )
        seen[truncated] = (candidate, attempt)
    raise RuntimeError(
        f"no {digest_bits}-bit birthday collision found in {max_attempts} attempts"
    )


# Concise alias for command-line and notebook code.
find_birthday_collision = birthday_collision_search
birthday_collision = birthday_collision_search


__all__ = [
    "BirthdayCollision",
    "EDUCATIONAL_WARNING",
    "LengthExtensionResult",
    "TOY_HASH_BLOCK_SIZE",
    "TOY_HASH_DIGEST_SIZE",
    "TOY_HASH_INITIAL_STATE",
    "ToyMerkleDamgard",
    "ToyHash",
    "birthday_collision_search",
    "birthday_collision",
    "continue_toy_hash",
    "find_birthday_collision",
    "forge_toy_prefix_mac",
    "length_extension_attack",
    "length_extension",
    "merkle_damgard_hash",
    "toy_compress",
    "toy_hash",
    "toy_hash_padding",
    "toy_length_extension",
    "toy_md_padding",
    "toy_merkle_damgard",
    "toy_merkle_damgard_hash",
    "toy_prefix_mac",
    "verify_length_extension",
]
