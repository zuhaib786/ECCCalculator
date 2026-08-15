"""Inspectable symmetric-cipher components for academic use only."""

from __future__ import annotations

from dataclasses import dataclass
import hmac

from .trace import TraceCallback, emit


def _gf_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        high = left & 0x80
        left = left << 1 & 0xFF
        if high:
            left ^= 0x1B
        right >>= 1
    return result


def _gf_power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_multiply(result, value)
        value = _gf_multiply(value, value)
        exponent >>= 1
    return result


def _rotate_byte(value: int, distance: int) -> int:
    return ((value << distance) | (value >> (8 - distance))) & 0xFF


def _make_sbox() -> tuple[int, ...]:
    values = []
    for value in range(256):
        inverse = 0 if value == 0 else _gf_power(value, 254)
        transformed = inverse
        for distance in range(1, 5):
            transformed ^= _rotate_byte(inverse, distance)
        values.append(transformed ^ 0x63)
    return tuple(values)


SBOX = _make_sbox()
INVERSE_SBOX = tuple(SBOX.index(value) for value in range(256))


def _xor_state(left: list[int], right: bytes) -> list[int]:
    return [value ^ key_byte for value, key_byte in zip(left, right, strict=True)]


def _shift_rows(state: list[int], *, inverse: bool = False) -> list[int]:
    shifted = [0] * 16
    for row in range(4):
        for column in range(4):
            source_column = (column - row if inverse else column + row) % 4
            shifted[4 * column + row] = state[4 * source_column + row]
    return shifted


def _mix_columns(state: list[int], *, inverse: bool = False) -> list[int]:
    output = [0] * 16
    matrix = (
        ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))
        if inverse
        else ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    )
    for column in range(4):
        values = state[4 * column : 4 * column + 4]
        for row in range(4):
            output[4 * column + row] = (
                _gf_multiply(matrix[row][0], values[0])
                ^ _gf_multiply(matrix[row][1], values[1])
                ^ _gf_multiply(matrix[row][2], values[2])
                ^ _gf_multiply(matrix[row][3], values[3])
            )
    return output


def _expand_key(key: bytes) -> tuple[bytes, ...]:
    if len(key) != 16:
        raise ValueError("AES-128 keys must contain exactly 16 bytes")
    words = [list(key[offset : offset + 4]) for offset in range(0, 16, 4)]
    rcon = 1
    while len(words) < 44:
        temporary = words[-1].copy()
        if len(words) % 4 == 0:
            temporary = temporary[1:] + temporary[:1]
            temporary = [SBOX[value] for value in temporary]
            temporary[0] ^= rcon
            rcon = _gf_multiply(rcon, 2)
        words.append(
            [value ^ previous for value, previous in zip(words[-4], temporary, strict=True)]
        )
    return tuple(
        bytes(sum(words[index : index + 4], [])) for index in range(0, 44, 4)
    )


def _trace_state(
    trace: TraceCallback | None,
    code: str,
    round_number: int,
    state: list[int],
) -> None:
    emit(
        trace,
        code,
        f"AES round {round_number} {code.rsplit('.', 1)[-1]}: {bytes(state).hex()}",
        level=2,
        round=round_number,
        state=bytes(state).hex(),
    )


@dataclass(frozen=True, slots=True)
class AES128:
    """A direct AES-128 round implementation intended for tracing and lessons."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 16:
            raise ValueError("AES-128 keys must contain exactly 16 bytes")

    @property
    def round_keys(self) -> tuple[bytes, ...]:
        return _expand_key(self.key)

    def encrypt_block(
        self, block: bytes, *, trace: TraceCallback | None = None
    ) -> bytes:
        if len(block) != 16:
            raise ValueError("AES blocks must contain exactly 16 bytes")
        state = _xor_state(list(block), self.round_keys[0])
        _trace_state(trace, "aes.add_round_key", 0, state)
        for round_number in range(1, 11):
            state = [SBOX[value] for value in state]
            _trace_state(trace, "aes.sub_bytes", round_number, state)
            state = _shift_rows(state)
            _trace_state(trace, "aes.shift_rows", round_number, state)
            if round_number != 10:
                state = _mix_columns(state)
                _trace_state(trace, "aes.mix_columns", round_number, state)
            state = _xor_state(state, self.round_keys[round_number])
            _trace_state(trace, "aes.add_round_key", round_number, state)
        emit(trace, "aes.complete", f"AES ciphertext: {bytes(state).hex()}", ciphertext=bytes(state).hex())
        return bytes(state)

    def decrypt_block(
        self, block: bytes, *, trace: TraceCallback | None = None
    ) -> bytes:
        if len(block) != 16:
            raise ValueError("AES blocks must contain exactly 16 bytes")
        state = _xor_state(list(block), self.round_keys[10])
        _trace_state(trace, "aes.inverse_add_round_key", 10, state)
        for round_number in range(9, -1, -1):
            state = _shift_rows(state, inverse=True)
            _trace_state(trace, "aes.inverse_shift_rows", round_number, state)
            state = [INVERSE_SBOX[value] for value in state]
            _trace_state(trace, "aes.inverse_sub_bytes", round_number, state)
            state = _xor_state(state, self.round_keys[round_number])
            _trace_state(trace, "aes.inverse_add_round_key", round_number, state)
            if round_number:
                state = _mix_columns(state, inverse=True)
                _trace_state(trace, "aes.inverse_mix_columns", round_number, state)
        emit(trace, "aes.decrypt_complete", f"AES plaintext: {bytes(state).hex()}", plaintext=bytes(state).hex())
        return bytes(state)


def aes_ctr_transform(
    data: bytes,
    key: bytes,
    nonce: bytes,
    *,
    initial_counter: int = 0,
    trace: TraceCallback | None = None,
) -> bytes:
    """Encrypt or decrypt using an 8-byte nonce and 64-bit AES-CTR counter."""

    if len(nonce) != 8:
        raise ValueError("AES-CTR teaching nonces must contain exactly 8 bytes")
    if not 0 <= initial_counter < 2**64:
        raise ValueError("initial_counter must fit in 64 bits")
    cipher = AES128(key)
    output = bytearray()
    for block_index, offset in enumerate(range(0, len(data), 16)):
        counter = initial_counter + block_index
        if counter >= 2**64:
            raise ValueError("AES-CTR counter overflow")
        counter_block = nonce + counter.to_bytes(8, "big")
        keystream = cipher.encrypt_block(counter_block)
        chunk = data[offset : offset + 16]
        transformed = bytes(
            value ^ mask for value, mask in zip(chunk, keystream, strict=False)
        )
        output.extend(transformed)
        emit(
            trace,
            "aes.ctr_block",
            f"CTR block {block_index}: counter={counter}",
            block=block_index,
            counter=counter,
            counter_block=counter_block.hex(),
            keystream=keystream.hex(),
            input=chunk.hex(),
            output=transformed.hex(),
        )
    return bytes(output)


def hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("values must have equal lengths")
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))


def _gcm_multiply(left: int, right: int) -> int:
    """Multiply in GF(2^128) using the GCM reduction polynomial."""

    result = 0
    value = right
    reduction = 0xE1000000000000000000000000000000
    for bit in range(128):
        if left & (1 << (127 - bit)):
            result ^= value
        value = value >> 1 ^ (reduction if value & 1 else 0)
    return result


def _ghash(hash_subkey: bytes, associated_data: bytes, ciphertext: bytes) -> bytes:
    h_value = int.from_bytes(hash_subkey, "big")
    blocks = bytearray()
    blocks.extend(associated_data)
    blocks.extend(bytes((-len(associated_data)) % 16))
    blocks.extend(ciphertext)
    blocks.extend(bytes((-len(ciphertext)) % 16))
    blocks.extend((len(associated_data) * 8).to_bytes(8, "big"))
    blocks.extend((len(ciphertext) * 8).to_bytes(8, "big"))
    accumulator = 0
    for offset in range(0, len(blocks), 16):
        accumulator = _gcm_multiply(
            accumulator ^ int.from_bytes(blocks[offset : offset + 16], "big"),
            h_value,
        )
    return accumulator.to_bytes(16, "big")


@dataclass(frozen=True, slots=True)
class GCMMessage:
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    associated_data: bytes = b""


def _increment_gcm_counter(counter_block: bytes) -> bytes:
    prefix, counter = counter_block[:12], int.from_bytes(counter_block[12:], "big")
    return prefix + ((counter + 1) & 0xFFFF_FFFF).to_bytes(4, "big")


def _gcm_ctr(data: bytes, cipher: AES128, initial_counter: bytes) -> bytes:
    output = bytearray()
    counter = initial_counter
    for offset in range(0, len(data), 16):
        counter = _increment_gcm_counter(counter)
        stream = cipher.encrypt_block(counter)
        chunk = data[offset : offset + 16]
        output.extend(value ^ mask for value, mask in zip(chunk, stream, strict=False))
    return bytes(output)


def aes_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    *,
    associated_data: bytes = b"",
    trace: TraceCallback | None = None,
) -> GCMMessage:
    """Expose AES-GCM's CTR encryption and GHASH authentication steps."""

    if len(nonce) != 12:
        raise ValueError("this GCM lesson supports the standard 12-byte nonce form")
    cipher = AES128(key)
    hash_subkey = cipher.encrypt_block(bytes(16))
    initial_counter = nonce + b"\x00\x00\x00\x01"
    ciphertext = _gcm_ctr(plaintext, cipher, initial_counter)
    authentication = _ghash(hash_subkey, associated_data, ciphertext)
    encrypted_counter = cipher.encrypt_block(initial_counter)
    tag = bytes(a ^ b for a, b in zip(encrypted_counter, authentication, strict=True))
    emit(
        trace,
        "gcm.complete",
        f"GCM produced {len(ciphertext)} ciphertext bytes and tag {tag.hex()}",
        hash_subkey=hash_subkey.hex(),
        ciphertext=ciphertext.hex(),
        tag=tag.hex(),
        associated_data=associated_data.hex(),
    )
    return GCMMessage(nonce, ciphertext, tag, associated_data)


def aes_gcm_decrypt(
    message: GCMMessage,
    key: bytes,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Authenticate before releasing GCM plaintext."""

    if len(message.nonce) != 12 or len(message.tag) != 16:
        raise ValueError("invalid GCM nonce or tag length")
    cipher = AES128(key)
    hash_subkey = cipher.encrypt_block(bytes(16))
    initial_counter = message.nonce + b"\x00\x00\x00\x01"
    authentication = _ghash(
        hash_subkey, message.associated_data, message.ciphertext
    )
    expected = bytes(
        a ^ b
        for a, b in zip(
            cipher.encrypt_block(initial_counter), authentication, strict=True
        )
    )
    if not hmac.compare_digest(expected, message.tag):
        emit(trace, "gcm.reject", "GCM tag verification failed")
        raise ValueError("GCM authentication failed")
    plaintext = _gcm_ctr(message.ciphertext, cipher, initial_counter)
    emit(trace, "gcm.decrypt_complete", "GCM tag accepted", plaintext=plaintext.hex())
    return plaintext


__all__ = [
    "AES128",
    "GCMMessage",
    "INVERSE_SBOX",
    "SBOX",
    "aes_ctr_transform",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "hamming_distance",
]
