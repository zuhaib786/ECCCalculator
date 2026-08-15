"""Small protocol compositions showing how cryptographic pieces interact.

These models omit production encoding, negotiation, certificate policy, and
side-channel defenses. They exist only to make protocol data flow inspectable.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from random import Random

from .encoding import int_to_bytes
from .randomness import hkdf
from .rsa import RSAKeyPair, RSAPrivateKey, RSAPublicKey
from .symmetric import aes_ctr_transform
from .trace import TraceCallback, emit


@dataclass(frozen=True, slots=True)
class HybridPacket:
    encapsulated_secret: int
    nonce: bytes
    ciphertext: bytes


def hybrid_encrypt(
    plaintext: bytes,
    public_key: RSAPublicKey,
    *,
    seed: int,
    trace: TraceCallback | None = None,
) -> HybridPacket:
    """Demonstrate RSA KEM plus AES-CTR DEM without claiming authentication."""

    if public_key.modulus <= 3:
        raise ValueError("RSA modulus is too small")
    randomness = Random(seed)
    secret = randomness.randrange(2, public_key.modulus)
    encapsulated = public_key.encrypt_int(secret)
    secret_bytes = int_to_bytes(secret)
    key_material = hkdf(secret_bytes, 24, info=b"crypto-lab hybrid lesson")
    aes_key, nonce = key_material[:16], key_material[16:]
    ciphertext = aes_ctr_transform(plaintext, aes_key, nonce)
    emit(
        trace,
        "protocol.kem",
        f"encapsulated session secret as RSA integer {encapsulated}",
        session_secret=secret,
        encapsulated_secret=encapsulated,
    )
    emit(
        trace,
        "protocol.dem",
        f"encrypted {len(plaintext)} bytes with derived AES-CTR key",
        nonce=nonce.hex(),
        ciphertext=ciphertext.hex(),
    )
    return HybridPacket(encapsulated, nonce, ciphertext)


def hybrid_decrypt(
    packet: HybridPacket,
    private_key: RSAPrivateKey,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    secret = private_key.decrypt_int(packet.encapsulated_secret)
    key_material = hkdf(
        int_to_bytes(secret), 24, info=b"crypto-lab hybrid lesson"
    )
    if not hmac.compare_digest(key_material[16:], packet.nonce):
        raise ValueError("packet nonce does not match the encapsulated lesson key")
    plaintext = aes_ctr_transform(packet.ciphertext, key_material[:16], packet.nonce)
    emit(trace, "protocol.hybrid_decrypt", "recovered hybrid plaintext", plaintext=plaintext.hex())
    return plaintext


@dataclass(frozen=True, slots=True)
class Certificate:
    subject: str
    modulus: int
    exponent: int
    issuer: str
    signature: int

    def unsigned_bytes(self) -> bytes:
        return f"{self.subject}|{self.modulus}|{self.exponent}|{self.issuer}".encode()


@dataclass(frozen=True, slots=True)
class TeachingCertificateAuthority:
    name: str
    keys: RSAKeyPair

    def issue(self, subject: str, key: RSAPublicKey) -> Certificate:
        unsigned = f"{subject}|{key.modulus}|{key.exponent}|{self.name}".encode()
        digest = int.from_bytes(hashlib.sha256(unsigned).digest(), "big") % self.keys.public.modulus
        signature = self.keys.private.decrypt_int(digest)
        return Certificate(subject, key.modulus, key.exponent, self.name, signature)

    def verify(self, certificate: Certificate) -> bool:
        if certificate.issuer != self.name:
            return False
        expected = int.from_bytes(
            hashlib.sha256(certificate.unsigned_bytes()).digest(), "big"
        ) % self.keys.public.modulus
        recovered = self.keys.public.encrypt_int(certificate.signature)
        return hmac.compare_digest(int_to_bytes(expected), int_to_bytes(recovered))


@dataclass(frozen=True, slots=True)
class HandshakeTranscript:
    client_public: int
    server_public: int
    shared_secret: int
    transcript_hash: bytes
    client_finished: bytes
    server_finished: bytes


def simplified_tls_handshake(
    *,
    prime: int,
    generator: int,
    client_private: int,
    server_private: int,
    client_nonce: bytes,
    server_nonce: bytes,
    trace: TraceCallback | None = None,
) -> HandshakeTranscript:
    """Model ephemeral DH, transcript hashing, HKDF, and Finished MACs."""

    if prime < 5 or not 1 < generator < prime:
        raise ValueError("invalid teaching DH group")
    if not 1 < client_private < prime - 1 or not 1 < server_private < prime - 1:
        raise ValueError("private exponents must lie within the group range")
    client_public = pow(generator, client_private, prime)
    server_public = pow(generator, server_private, prime)
    client_shared = pow(server_public, client_private, prime)
    server_shared = pow(client_public, server_private, prime)
    if client_shared != server_shared:
        raise AssertionError("Diffie-Hellman agreement failed")
    transcript = b"|".join(
        (
            b"ClientHello",
            client_nonce,
            int_to_bytes(client_public),
            b"ServerHello",
            server_nonce,
            int_to_bytes(server_public),
        )
    )
    transcript_hash = hashlib.sha256(transcript).digest()
    traffic_secret = hkdf(
        int_to_bytes(client_shared),
        64,
        salt=client_nonce + server_nonce,
        info=transcript_hash,
    )
    client_finished = hmac.new(
        traffic_secret[:32], transcript_hash + b"client", hashlib.sha256
    ).digest()
    server_finished = hmac.new(
        traffic_secret[32:], transcript_hash + b"server", hashlib.sha256
    ).digest()
    emit(
        trace,
        "protocol.client_hello",
        f"client sends nonce and DH share {client_public}",
        client_public=client_public,
        nonce=client_nonce.hex(),
    )
    emit(
        trace,
        "protocol.server_hello",
        f"server sends nonce and DH share {server_public}",
        server_public=server_public,
        nonce=server_nonce.hex(),
    )
    emit(
        trace,
        "protocol.finished",
        "both peers authenticate the same transcript hash",
        transcript_hash=transcript_hash.hex(),
        client_finished=client_finished.hex(),
        server_finished=server_finished.hex(),
    )
    return HandshakeTranscript(
        client_public,
        server_public,
        client_shared,
        transcript_hash,
        client_finished,
        server_finished,
    )


@dataclass(slots=True)
class ReplayCache:
    """Track unique protocol nonces and reject a repeated message."""

    seen: set[bytes]

    def __init__(self) -> None:
        self.seen = set()

    def accept(self, nonce: bytes) -> bool:
        if not nonce or nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True


__all__ = [
    "Certificate",
    "HandshakeTranscript",
    "HybridPacket",
    "ReplayCache",
    "TeachingCertificateAuthority",
    "hybrid_decrypt",
    "hybrid_encrypt",
    "simplified_tls_handshake",
]

