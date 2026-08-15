"""Executable attack labs against deliberately vulnerable constructions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .feistel import FeistelMessage, ToyFeistelCipher
from .trace import TraceCallback, emit


@dataclass(frozen=True, slots=True)
class ComparisonLeak:
    equal: bool
    matched_prefix: int


def leaking_compare(candidate: bytes, secret: bytes) -> ComparisonLeak:
    """Model an early-return comparison whose timing leaks prefix length."""

    matched = 0
    for supplied, expected in zip(candidate, secret, strict=False):
        if supplied != expected:
            return ComparisonLeak(False, matched)
        matched += 1
    return ComparisonLeak(len(candidate) == len(secret), matched)


def recover_with_prefix_oracle(
    secret: bytes,
    alphabet: Iterable[int] = range(256),
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Recover a secret using the modeled comparison-count side channel."""

    choices = tuple(alphabet)
    recovered = bytearray()
    for index in range(len(secret)):
        for candidate in choices:
            if not 0 <= candidate <= 255:
                raise ValueError("alphabet entries must be bytes")
            probe = bytes(recovered) + bytes([candidate])
            leak = leaking_compare(probe, secret)
            if leak.matched_prefix == index + 1:
                recovered.append(candidate)
                emit(
                    trace,
                    "attack.timing_byte",
                    f"recovered byte {index}: {candidate:02x}",
                    level=2,
                    index=index,
                    value=candidate,
                )
                break
        else:
            raise ValueError(f"alphabet does not contain secret byte at index {index}")
    return bytes(recovered)


def cbc_bitflip(
    previous_block: bytes,
    *,
    offset: int,
    known_plaintext_byte: int,
    desired_plaintext_byte: int,
) -> bytes:
    """Alter one preceding-block byte to predictably alter CBC plaintext."""

    if not 0 <= offset < len(previous_block):
        raise ValueError("offset is outside the block")
    if not 0 <= known_plaintext_byte <= 255 or not 0 <= desired_plaintext_byte <= 255:
        raise ValueError("plaintext values must be bytes")
    modified = bytearray(previous_block)
    modified[offset] ^= known_plaintext_byte ^ desired_plaintext_byte
    return bytes(modified)


def _padding_oracle(cipher: ToyFeistelCipher, message: FeistelMessage) -> bool:
    try:
        cipher.decrypt(message)
    except ValueError:
        return False
    return True


def recover_cbc_last_block(
    cipher: ToyFeistelCipher,
    message: FeistelMessage,
    *,
    trace: TraceCallback | None = None,
) -> tuple[bytes, int]:
    """Recover the final padded plaintext block using a CBC padding oracle."""

    if message.mode != "cbc" or message.iv is None:
        raise ValueError("padding-oracle lesson requires CBC and an IV")
    block_size = cipher.block_size
    if len(message.ciphertext) < block_size or len(message.ciphertext) % block_size:
        raise ValueError("ciphertext must contain complete blocks")
    blocks = [
        message.ciphertext[offset : offset + block_size]
        for offset in range(0, len(message.ciphertext), block_size)
    ]
    original_previous = message.iv if len(blocks) == 1 else blocks[-2]
    target = blocks[-1]
    prefix = b"" if len(blocks) <= 2 else b"".join(blocks[:-2])
    intermediate = bytearray(block_size)
    plaintext = bytearray(block_size)
    queries = 0

    def query(crafted_previous: bytes) -> bool:
        nonlocal queries
        queries += 1
        if len(blocks) == 1:
            packet = FeistelMessage(target, "cbc", crafted_previous)
        else:
            packet = FeistelMessage(prefix + crafted_previous + target, "cbc", message.iv)
        return _padding_oracle(cipher, packet)

    for padding in range(1, block_size + 1):
        index = block_size - padding
        crafted = bytearray(original_previous)
        for position in range(index + 1, block_size):
            crafted[position] = intermediate[position] ^ padding
        for guess in range(256):
            crafted[index] = guess
            if not query(bytes(crafted)):
                continue
            if padding == 1 and index > 0:
                confirmation = bytearray(crafted)
                confirmation[index - 1] ^= 1
                if not query(bytes(confirmation)):
                    continue
            intermediate[index] = guess ^ padding
            plaintext[index] = intermediate[index] ^ original_previous[index]
            emit(
                trace,
                "attack.padding_byte",
                f"recovered padded byte {index}: {plaintext[index]:02x}",
                level=2,
                index=index,
                value=plaintext[index],
                queries=queries,
            )
            break
        else:
            raise RuntimeError(f"padding oracle failed at byte {index}")
    emit(
        trace,
        "attack.padding_complete",
        f"recovered final padded block in {queries} oracle queries",
        plaintext=bytes(plaintext).hex(),
        queries=queries,
    )
    return bytes(plaintext), queries


__all__ = [
    "ComparisonLeak",
    "cbc_bitflip",
    "leaking_compare",
    "recover_cbc_last_block",
    "recover_with_prefix_oracle",
]

