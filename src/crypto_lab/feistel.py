"""A deliberately small Feistel network for teaching block-cipher structure.

This is not DES, AES, or a secure original cipher. Its purpose is to expose key
scheduling, rounds, the Feistel swap, padding, ECB, and CBC in compact code.
"""

from __future__ import annotations

from dataclasses import dataclass
from secrets import token_bytes
from typing import Literal

from .encoding import pkcs7_pad, pkcs7_unpad, split_blocks, xor_bytes
from .trace import TraceCallback, emit

BlockMode = Literal["ecb", "cbc"]
_WORD_MASK = 0xFFFF_FFFF
_KEY_MASK = 0xFFFF_FFFF_FFFF_FFFF


def _rotate_left(value: int, distance: int, width: int) -> int:
    distance %= width
    mask = (1 << width) - 1
    return ((value << distance) | (value >> (width - distance))) & mask


@dataclass(frozen=True, slots=True)
class FeistelMessage:
    ciphertext: bytes
    mode: BlockMode
    iv: bytes | None

    def hex(self) -> str:
        return self.ciphertext.hex()


@dataclass(frozen=True, slots=True)
class ToyFeistelCipher:
    """An 8-byte, configurable-round teaching network with a 64-bit key."""

    key: int
    rounds: int = 8

    block_size = 8

    def __post_init__(self) -> None:
        if not 0 <= self.key <= _KEY_MASK:
            raise ValueError("key must fit in 64 bits")
        if not 2 <= self.rounds <= 32:
            raise ValueError("rounds must be between 2 and 32")

    @property
    def round_keys(self) -> tuple[int, ...]:
        keys = []
        for round_number in range(self.rounds):
            rotated = _rotate_left(self.key, round_number * 7, 64)
            high, low = rotated >> 32, rotated & _WORD_MASK
            keys.append((high ^ low ^ (0x9E37_79B9 * (round_number + 1))) & _WORD_MASK)
        return tuple(keys)

    @staticmethod
    def round_function(right: int, round_key: int) -> int:
        """A visible mixing function; invertibility is supplied by Feistel."""

        mixed = (right + round_key) & _WORD_MASK
        mixed ^= _rotate_left(mixed, 5, 32)
        return (mixed * 0x045D_9F3B) & _WORD_MASK

    def _transform_block(
        self,
        block: bytes,
        keys: tuple[int, ...],
        *,
        operation: str,
        block_index: int,
        trace: TraceCallback | None,
    ) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("Feistel blocks must be exactly 8 bytes")
        left = int.from_bytes(block[:4], "big")
        right = int.from_bytes(block[4:], "big")
        for round_number, round_key in enumerate(keys, start=1):
            left, right = right, left ^ self.round_function(right, round_key)
            emit(
                trace,
                "feistel.round",
                f"{operation} block {block_index}, round {round_number}: "
                f"L={left:08x} R={right:08x}",
                level=2,
                operation=operation,
                block=block_index,
                round=round_number,
                round_key=f"{round_key:08x}",
                left=f"{left:08x}",
                right=f"{right:08x}",
            )
        return right.to_bytes(4, "big") + left.to_bytes(4, "big")

    def encrypt_block(
        self,
        block: bytes,
        *,
        block_index: int = 0,
        trace: TraceCallback | None = None,
    ) -> bytes:
        return self._transform_block(
            block,
            self.round_keys,
            operation="encrypt",
            block_index=block_index,
            trace=trace,
        )

    def decrypt_block(
        self,
        block: bytes,
        *,
        block_index: int = 0,
        trace: TraceCallback | None = None,
    ) -> bytes:
        return self._transform_block(
            block,
            tuple(reversed(self.round_keys)),
            operation="decrypt",
            block_index=block_index,
            trace=trace,
        )

    def encrypt(
        self,
        plaintext: bytes,
        *,
        mode: BlockMode = "cbc",
        iv: bytes | None = None,
        trace: TraceCallback | None = None,
    ) -> FeistelMessage:
        if mode not in ("ecb", "cbc"):
            raise ValueError("mode must be 'ecb' or 'cbc'")
        if mode == "ecb":
            if iv is not None:
                raise ValueError("ECB does not use an IV")
        else:
            iv = token_bytes(self.block_size) if iv is None else iv
            if len(iv) != self.block_size:
                raise ValueError("CBC IV must be exactly 8 bytes")

        padded = pkcs7_pad(plaintext, self.block_size)
        emit(
            trace,
            "feistel.pad",
            f"padded {len(plaintext)} bytes to {len(padded)} bytes",
            plaintext_length=len(plaintext),
            padded_length=len(padded),
        )
        encrypted: list[bytes] = []
        previous = iv
        for index, block in enumerate(split_blocks(padded, self.block_size, require_full=True)):
            input_block = xor_bytes(block, previous) if mode == "cbc" and previous else block
            output = self.encrypt_block(input_block, block_index=index, trace=trace)
            encrypted.append(output)
            previous = output
            emit(
                trace,
                "feistel.block",
                f"encrypted block {index}: {block.hex()} -> {output.hex()}",
                block=index,
                plaintext=block.hex(),
                ciphertext=output.hex(),
                mode=mode,
            )
        return FeistelMessage(b"".join(encrypted), mode, iv)

    def decrypt(
        self,
        message: FeistelMessage,
        *,
        trace: TraceCallback | None = None,
    ) -> bytes:
        if len(message.ciphertext) == 0 or len(message.ciphertext) % self.block_size:
            raise ValueError("ciphertext must contain complete blocks")
        if message.mode == "cbc":
            if message.iv is None or len(message.iv) != self.block_size:
                raise ValueError("CBC ciphertext requires an 8-byte IV")
        elif message.mode != "ecb":
            raise ValueError("mode must be 'ecb' or 'cbc'")

        decrypted: list[bytes] = []
        previous = message.iv
        for index, block in enumerate(
            split_blocks(message.ciphertext, self.block_size, require_full=True)
        ):
            output = self.decrypt_block(block, block_index=index, trace=trace)
            plaintext = xor_bytes(output, previous) if message.mode == "cbc" and previous else output
            decrypted.append(plaintext)
            previous = block
            emit(
                trace,
                "feistel.block",
                f"decrypted block {index}: {block.hex()} -> {plaintext.hex()}",
                block=index,
                plaintext=plaintext.hex(),
                ciphertext=block.hex(),
                mode=message.mode,
            )
        return pkcs7_unpad(b"".join(decrypted), self.block_size)


__all__ = ["BlockMode", "FeistelMessage", "ToyFeistelCipher"]

