"""Explicit conversions used by the teaching ciphers."""

from __future__ import annotations


def bytes_to_int(data: bytes, *, byteorder: str = "big") -> int:
    """Interpret bytes as one unsigned integer."""

    return int.from_bytes(data, byteorder=byteorder, signed=False)


def int_to_bytes(
    value: int,
    *,
    length: int | None = None,
    byteorder: str = "big",
) -> bytes:
    """Encode a non-negative integer, optionally using an exact byte length."""

    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    if length < 0:
        raise ValueError("length must be non-negative")
    try:
        return value.to_bytes(length, byteorder=byteorder, signed=False)
    except OverflowError as error:
        raise ValueError(f"value does not fit in {length} bytes") from error


def split_blocks(data: bytes, block_size: int, *, require_full: bool = False) -> tuple[bytes, ...]:
    """Split bytes into blocks without silently adding padding."""

    if block_size < 1:
        raise ValueError("block_size must be positive")
    if require_full and len(data) % block_size:
        raise ValueError("data length is not a multiple of block_size")
    return tuple(data[offset : offset + block_size] for offset in range(0, len(data), block_size))


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings."""

    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad to a block boundary using the PKCS#7 byte convention."""

    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Validate and remove PKCS#7-style padding."""

    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")
    if not data or len(data) % block_size:
        raise ValueError("padded data must contain complete blocks")
    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("invalid padding length")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid padding bytes")
    return data[:-padding_length]


__all__ = [
    "bytes_to_int",
    "int_to_bytes",
    "pkcs7_pad",
    "pkcs7_unpad",
    "split_blocks",
    "xor_bytes",
]

