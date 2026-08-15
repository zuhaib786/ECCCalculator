"""Textbook RSA for inspecting key derivation, encoding, and exponentiation.

There is deliberately no secure padding scheme here. Real applications must use
a maintained cryptography library and an appropriate randomized construction
such as RSA-OAEP.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd

from ecc_factor import is_probable_prime

from .encoding import bytes_to_int, int_to_bytes, split_blocks
from .number_theory import mod_inverse, mod_pow
from .trace import TraceCallback, emit


@dataclass(frozen=True, slots=True)
class RSAPublicKey:
    modulus: int
    exponent: int

    @property
    def message_block_size(self) -> int:
        """Largest byte block guaranteed to represent an integer below ``n``."""

        return (self.modulus.bit_length() - 1) // 8

    def encrypt_int(self, message: int, *, trace: TraceCallback | None = None) -> int:
        if not 0 <= message < self.modulus:
            raise ValueError("message integer must satisfy 0 <= message < modulus")
        emit(
            trace,
            "rsa.encrypt",
            f"compute {message}^{self.exponent} mod {self.modulus}",
            plaintext_integer=message,
            exponent=self.exponent,
            modulus=self.modulus,
        )
        return mod_pow(message, self.exponent, self.modulus, trace=trace)

    def encrypt_bytes(
        self, data: bytes, *, trace: TraceCallback | None = None
    ) -> "RSAEncryptedMessage":
        block_size = self.message_block_size
        if block_size < 1:
            raise ValueError("RSA modulus is too small to encode one byte")
        encrypted: list[int] = []
        for index, block in enumerate(split_blocks(data, block_size)):
            value = bytes_to_int(block)
            emit(
                trace,
                "rsa.encode_block",
                f"block {index}: {block.hex()} -> {value}",
                block=index,
                encoded=value,
                hex=block.hex(),
            )
            encrypted.append(self.encrypt_int(value, trace=trace))
        return RSAEncryptedMessage(tuple(encrypted), block_size, len(data))

    def encrypt_text(
        self,
        text: str,
        *,
        encoding: str = "utf-8",
        trace: TraceCallback | None = None,
    ) -> "RSAEncryptedMessage":
        return self.encrypt_bytes(text.encode(encoding), trace=trace)


@dataclass(frozen=True, slots=True)
class RSAPrivateKey:
    modulus: int
    exponent: int
    prime_p: int
    prime_q: int

    def decrypt_int(self, ciphertext: int, *, trace: TraceCallback | None = None) -> int:
        if not 0 <= ciphertext < self.modulus:
            raise ValueError("ciphertext integer must satisfy 0 <= value < modulus")
        emit(
            trace,
            "rsa.decrypt",
            f"compute {ciphertext}^{self.exponent} mod {self.modulus}",
            ciphertext=ciphertext,
            exponent=self.exponent,
            modulus=self.modulus,
        )
        return mod_pow(ciphertext, self.exponent, self.modulus, trace=trace)

    def decrypt_bytes(
        self,
        message: "RSAEncryptedMessage",
        *,
        trace: TraceCallback | None = None,
    ) -> bytes:
        if message.byte_length == 0:
            return b""
        expected_blocks = (message.byte_length + message.block_size - 1) // message.block_size
        if len(message.blocks) != expected_blocks:
            raise ValueError("encrypted-message metadata does not match its blocks")

        decoded = bytearray()
        last_length = message.byte_length % message.block_size or message.block_size
        for index, ciphertext in enumerate(message.blocks):
            value = self.decrypt_int(ciphertext, trace=trace)
            length = last_length if index == expected_blocks - 1 else message.block_size
            block = int_to_bytes(value, length=length)
            emit(
                trace,
                "rsa.decode_block",
                f"block {index}: {value} -> {block.hex()}",
                block=index,
                encoded=value,
                hex=block.hex(),
            )
            decoded.extend(block)
        return bytes(decoded)

    def decrypt_text(
        self,
        message: "RSAEncryptedMessage",
        *,
        encoding: str = "utf-8",
        trace: TraceCallback | None = None,
    ) -> str:
        return self.decrypt_bytes(message, trace=trace).decode(encoding)


@dataclass(frozen=True, slots=True)
class RSAEncryptedMessage:
    blocks: tuple[int, ...]
    block_size: int
    byte_length: int

    def __post_init__(self) -> None:
        if self.block_size < 1:
            raise ValueError("block_size must be positive")
        if self.byte_length < 0:
            raise ValueError("byte_length must be non-negative")
        if any(block < 0 for block in self.blocks):
            raise ValueError("ciphertext blocks must be non-negative")


@dataclass(frozen=True, slots=True)
class RSAKeyPair:
    public: RSAPublicKey
    private: RSAPrivateKey
    totient: int

    @classmethod
    def from_primes(
        cls,
        prime_p: int,
        prime_q: int,
        *,
        public_exponent: int = 65_537,
        trace: TraceCallback | None = None,
    ) -> "RSAKeyPair":
        if prime_p == prime_q:
            raise ValueError("RSA teaching primes must be distinct")
        if not is_probable_prime(prime_p) or not is_probable_prime(prime_q):
            raise ValueError("prime_p and prime_q must both be prime")
        modulus = prime_p * prime_q
        totient = (prime_p - 1) * (prime_q - 1)
        if not 1 < public_exponent < totient:
            raise ValueError("public exponent must satisfy 1 < e < phi(n)")
        if gcd(public_exponent, totient) != 1:
            raise ValueError("public exponent must be coprime with phi(n)")
        private_exponent = mod_inverse(public_exponent, totient)
        emit(
            trace,
            "rsa.keygen",
            f"n={modulus}, phi(n)={totient}, e={public_exponent}, d={private_exponent}",
            prime_p=prime_p,
            prime_q=prime_q,
            modulus=modulus,
            totient=totient,
            public_exponent=public_exponent,
            private_exponent=private_exponent,
        )
        return cls(
            RSAPublicKey(modulus, public_exponent),
            RSAPrivateKey(modulus, private_exponent, prime_p, prime_q),
            totient,
        )


__all__ = ["RSAEncryptedMessage", "RSAKeyPair", "RSAPrivateKey", "RSAPublicKey"]
