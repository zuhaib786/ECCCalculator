"""Message-authentication and authenticated-encryption lessons.

The APIs are intentionally explicit about insecure teaching constructions.
HMAC-SHA-256 follows the standard construction and is suitable for known
answer exercises, but the surrounding toy CBC-MAC and Feistel cipher are not
production cryptography.  In particular, the CBC-MAC forgery helper shows why
plain CBC-MAC must not authenticate variable-length messages.

Functions are silent unless a :class:`~crypto_lab.trace.TraceCallback` is
provided.  Authentication failures raise :class:`AuthenticationError` rather
than returning unauthenticated plaintext.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Final

from .encoding import split_blocks, xor_bytes
from .feistel import FeistelMessage, ToyFeistelCipher
from .trace import TraceCallback, emit


EDUCATIONAL_WARNING: Final[str] = (
    "Educational authentication constructions only; do not use them to protect real data."
)


class AuthenticationError(ValueError):
    """Raised when an authenticated message fails verification."""


def _ensure_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def hmac_digest(
    key: bytes,
    message: bytes,
    *,
    digest_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bytes:
    """Compute HMAC by exposing its ``H(K xor ipad, ...)`` and outer steps.

    The digest operation itself is delegated to :mod:`hashlib`; this keeps the
    digest implementation auditable while making HMAC's two-keyed-hash layout
    visible in a trace.  It intentionally does not use :func:`hmac.new` so
    students can inspect the pads and compare the result with a known-answer
    vector.
    """

    _ensure_bytes(key, "key")
    _ensure_bytes(message, "message")
    try:
        digest_constructor = getattr(hashlib, digest_name)
    except AttributeError as error:
        raise ValueError(f"unknown hashlib digest: {digest_name}") from error
    probe = digest_constructor()
    block_size = probe.block_size
    if block_size <= 0:
        raise ValueError(f"digest {digest_name!r} does not expose a block size")
    normalized_key = digest_constructor(key).digest() if len(key) > block_size else key
    key_block = normalized_key.ljust(block_size, b"\x00")
    ipad = bytes(byte ^ 0x36 for byte in key_block)
    opad = bytes(byte ^ 0x5C for byte in key_block)
    emit(
        trace,
        "hmac.setup",
        f"HMAC-{digest_name}: normalized key to {block_size} bytes",
        digest_name=digest_name,
        block_size=block_size,
        original_key_length=len(key),
        normalized_key_length=len(normalized_key),
        ipad_hex=ipad.hex(),
        opad_hex=opad.hex(),
    )
    inner = digest_constructor(ipad + message).digest()
    emit(
        trace,
        "hmac.inner",
        f"inner digest: {inner.hex()}",
        digest_name=digest_name,
        message_length=len(message),
        digest=inner.hex(),
    )
    result = digest_constructor(opad + inner).digest()
    emit(
        trace,
        "hmac.outer",
        f"outer digest/tag: {result.hex()}",
        digest_name=digest_name,
        digest=result.hex(),
    )
    return result


def hmac_sha256(
    key: bytes,
    message: bytes,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Compute HMAC-SHA-256 with a traceable standard construction."""

    return hmac_digest(key, message, digest_name="sha256", trace=trace)


compute_hmac = hmac_digest
hmac_sha256_digest = hmac_sha256


def verify_hmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    digest_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bool:
    """Verify a tag using a constant-time comparison."""

    _ensure_bytes(tag, "tag")
    expected = hmac_digest(key, message, digest_name=digest_name, trace=trace)
    valid = hmac.compare_digest(expected, tag)
    emit(
        trace,
        "hmac.verify",
        "HMAC verification succeeded" if valid else "HMAC verification failed",
        valid=valid,
        supplied_tag=tag.hex(),
        expected_tag=expected.hex(),
    )
    return valid


hmac_verify = verify_hmac


@dataclass(frozen=True, slots=True)
class HMAC:
    """Reusable typed HMAC lesson object."""

    key: bytes
    digest_name: str = "sha256"

    def compute(self, message: bytes, *, trace: TraceCallback | None = None) -> bytes:
        return hmac_digest(
            self.key, message, digest_name=self.digest_name, trace=trace
        )

    def digest(self, message: bytes, *, trace: TraceCallback | None = None) -> bytes:
        return self.compute(message, trace=trace)

    def verify(
        self,
        message: bytes,
        tag: bytes,
        *,
        trace: TraceCallback | None = None,
    ) -> bool:
        return verify_hmac(
            self.key,
            message,
            tag,
            digest_name=self.digest_name,
            trace=trace,
        )


def _coerce_cipher(cipher: ToyFeistelCipher | int) -> ToyFeistelCipher:
    if isinstance(cipher, ToyFeistelCipher):
        return cipher
    if isinstance(cipher, int):
        return ToyFeistelCipher(cipher)
    raise TypeError("cipher must be ToyFeistelCipher or a 64-bit integer key")


def cbc_mac(
    message: bytes | ToyFeistelCipher | int,
    cipher: ToyFeistelCipher | int | bytes,
    *,
    trace: TraceCallback | None = None,
) -> bytes:
    """Compute a zero-IV CBC-MAC over complete blocks only.

    There is no padding: accepting a variable-length, attacker-controlled
    message is precisely the misuse demonstrated by
    :func:`cbc_mac_length_extension_forgery`.
    """

    # Accept both ``cbc_mac(message, cipher)`` (the documented form) and the
    # common classroom spelling ``cbc_mac(cipher, message)``.
    if isinstance(message, (ToyFeistelCipher, int)) and isinstance(cipher, bytes):
        message, cipher = cipher, message
    _ensure_bytes(message, "message")
    cipher_obj = _coerce_cipher(cipher)
    if not message or len(message) % cipher_obj.block_size:
        raise ValueError(
            f"CBC-MAC requires a non-empty message in {cipher_obj.block_size}-byte blocks"
        )
    chaining = bytes(cipher_obj.block_size)
    emit(
        trace,
        "cbc_mac.start",
        f"CBC-MAC over {len(message) // cipher_obj.block_size} full blocks",
        message_length=len(message),
        block_size=cipher_obj.block_size,
        initial=chaining.hex(),
    )
    for index, block in enumerate(
        split_blocks(message, cipher_obj.block_size, require_full=True)
    ):
        input_block = xor_bytes(block, chaining)
        chaining = cipher_obj.encrypt_block(
            input_block, block_index=index, trace=trace
        )
        emit(
            trace,
            "cbc_mac.block",
            f"block {index}: {block.hex()} -> {chaining.hex()}",
            level=1,
            block=index,
            message_block=block.hex(),
            xor_input=input_block.hex(),
            chaining=chaining.hex(),
        )
    emit(trace, "cbc_mac.complete", f"CBC-MAC tag: {chaining.hex()}", tag=chaining.hex())
    return chaining


def verify_cbc_mac(
    message: bytes,
    tag: bytes,
    cipher: ToyFeistelCipher | int,
    *,
    trace: TraceCallback | None = None,
) -> bool:
    _ensure_bytes(tag, "tag")
    try:
        expected = cbc_mac(message, cipher, trace=trace)
    except ValueError:
        emit(trace, "cbc_mac.verify", "CBC-MAC input was not valid", valid=False)
        return False
    valid = hmac.compare_digest(expected, tag)
    emit(
        trace,
        "cbc_mac.verify",
        "CBC-MAC verification succeeded" if valid else "CBC-MAC verification failed",
        valid=valid,
        supplied_tag=tag.hex(),
        expected_tag=expected.hex(),
    )
    return valid


cbc_mac_verify = verify_cbc_mac


@dataclass(frozen=True, slots=True)
class CBCMAC:
    """Reusable zero-IV CBC-MAC lesson object."""

    cipher: ToyFeistelCipher

    def compute(self, message: bytes, *, trace: TraceCallback | None = None) -> bytes:
        return cbc_mac(message, self.cipher, trace=trace)

    def verify(
        self,
        message: bytes,
        tag: bytes,
        *,
        trace: TraceCallback | None = None,
    ) -> bool:
        return verify_cbc_mac(message, tag, self.cipher, trace=trace)

    def forge(
        self,
        original_message: bytes,
        original_tag: bytes,
        extension: bytes,
        *,
        extension_tag: bytes | None = None,
        trace: TraceCallback | None = None,
    ) -> "CBCMACForgery":
        return cbc_mac_length_extension_forgery(
            original_message,
            original_tag,
            extension,
            self.cipher,
            extension_tag=extension_tag,
            trace=trace,
        )


@dataclass(frozen=True, slots=True)
class CBCMACForgery:
    """A variable-length CBC-MAC forgery built from two valid MAC queries."""

    original_message: bytes
    original_tag: bytes
    extension: bytes
    extension_tag: bytes
    bridge_block: bytes
    forged_message: bytes
    forged_tag: bytes

    @property
    def message(self) -> bytes:
        return self.forged_message

    @property
    def tag(self) -> bytes:
        return self.forged_tag


def cbc_mac_length_extension_forgery(
    original_message: bytes,
    original_tag: bytes,
    extension: bytes,
    cipher: ToyFeistelCipher | int,
    *,
    extension_tag: bytes | None = None,
    trace: TraceCallback | None = None,
) -> CBCMACForgery:
    """Construct the classic variable-length CBC-MAC forgery.

    Given valid ``(M, tag(M))`` and ``(X, tag(X))`` oracle responses, create
    ``M || (tag(M) xor X[0]) || X[1:]``.  Its CBC-MAC equals ``tag(X)``.  The
    construction is for a lesson only: a production MAC should be length
    aware and use HMAC or an authenticated-encryption mode.
    """

    _ensure_bytes(original_message, "original_message")
    _ensure_bytes(original_tag, "original_tag")
    _ensure_bytes(extension, "extension")
    cipher_obj = _coerce_cipher(cipher)
    block_size = cipher_obj.block_size
    if not original_message or len(original_message) % block_size:
        raise ValueError("original_message must contain complete non-empty blocks")
    if not extension or len(extension) % block_size:
        raise ValueError("extension must contain complete non-empty blocks")
    if len(original_tag) != block_size:
        raise ValueError("original_tag must equal the cipher block size")
    if extension_tag is None:
        extension_tag = cbc_mac(extension, cipher_obj, trace=trace)
    elif len(extension_tag) != block_size:
        raise ValueError("extension_tag must equal the cipher block size")
    bridge = xor_bytes(original_tag, extension[:block_size])
    forged_message = original_message + bridge + extension[block_size:]
    forged = CBCMACForgery(
        original_message,
        original_tag,
        extension,
        extension_tag,
        bridge,
        forged_message,
        extension_tag,
    )
    emit(
        trace,
        "cbc_mac.forgery",
        "forged a variable-length CBC-MAC message",
        original_length=len(original_message),
        extension_length=len(extension),
        bridge_block=bridge.hex(),
        forged_message=forged_message.hex(),
        forged_tag=extension_tag.hex(),
    )
    return forged


# Names used in lecture notes and challenge descriptions.
cbc_mac_forgery = cbc_mac_length_extension_forgery
cbc_mac_variable_length_forgery = cbc_mac_length_extension_forgery


@dataclass(frozen=True, slots=True)
class AuthenticatedCiphertext:
    """Ciphertext, mode metadata, IV, and an encrypt-then-MAC tag."""

    encrypted: FeistelMessage
    tag: bytes

    @property
    def ciphertext(self) -> bytes:
        return self.encrypted.ciphertext

    @property
    def mode(self) -> str:
        return self.encrypted.mode

    @property
    def iv(self) -> bytes | None:
        return self.encrypted.iv


EtMMessage = AuthenticatedCiphertext
AuthenticatedMessage = AuthenticatedCiphertext


def _authenticated_bytes(message: FeistelMessage) -> bytes:
    mode = message.mode.encode("ascii")
    iv = message.iv or b""
    return b"crypto-lab-etm\x00" + len(mode).to_bytes(1, "big") + mode + len(iv).to_bytes(
        1, "big"
    ) + iv + message.ciphertext


@dataclass(frozen=True, slots=True)
class EncryptThenMAC:
    """Traceable encrypt-then-HMAC wrapper around the toy Feistel cipher."""

    cipher: ToyFeistelCipher
    mac_key: bytes
    digest_name: str = "sha256"

    def encrypt(
        self,
        plaintext: bytes,
        *,
        mode: str = "cbc",
        iv: bytes | None = None,
        trace: TraceCallback | None = None,
    ) -> AuthenticatedCiphertext:
        encrypted = self.cipher.encrypt(plaintext, mode=mode, iv=iv, trace=trace)
        mac_input = _authenticated_bytes(encrypted)
        tag = hmac_digest(
            self.mac_key, mac_input, digest_name=self.digest_name, trace=trace
        )
        emit(
            trace,
            "etm.encrypt",
            "encrypted plaintext and authenticated ciphertext metadata",
            plaintext_length=len(plaintext),
            ciphertext_length=len(encrypted.ciphertext),
            mode=encrypted.mode,
            iv=(encrypted.iv or b"").hex(),
            tag=tag.hex(),
        )
        return AuthenticatedCiphertext(encrypted, tag)

    def decrypt(
        self,
        message: AuthenticatedCiphertext,
        *,
        trace: TraceCallback | None = None,
    ) -> bytes:
        if not isinstance(message, AuthenticatedCiphertext):
            raise TypeError("message must be AuthenticatedCiphertext")
        expected = hmac_digest(
            self.mac_key,
            _authenticated_bytes(message.encrypted),
            digest_name=self.digest_name,
            trace=trace,
        )
        if not hmac.compare_digest(expected, message.tag):
            emit(
                trace,
                "etm.reject",
                "authentication failed before decryption",
                supplied_tag=message.tag.hex(),
                expected_tag=expected.hex(),
            )
            raise AuthenticationError("encrypt-then-MAC tag verification failed")
        emit(trace, "etm.accept", "authentication succeeded; decrypting", tag=message.tag.hex())
        return self.cipher.decrypt(message.encrypted, trace=trace)


EncryptThenAuthenticate = EncryptThenMAC


def encrypt_then_mac_encrypt(
    plaintext: bytes,
    cipher: ToyFeistelCipher,
    mac_key: bytes,
    *,
    mode: str = "cbc",
    iv: bytes | None = None,
    digest_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> AuthenticatedCiphertext:
    """Standalone encrypt-then-MAC helper."""

    return EncryptThenMAC(cipher, mac_key, digest_name).encrypt(
        plaintext, mode=mode, iv=iv, trace=trace
    )


def encrypt_then_mac_decrypt(
    message: AuthenticatedCiphertext,
    cipher: ToyFeistelCipher,
    mac_key: bytes,
    *,
    digest_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bytes:
    return EncryptThenMAC(cipher, mac_key, digest_name).decrypt(message, trace=trace)


__all__ = [
    "AuthenticatedCiphertext",
    "AuthenticatedMessage",
    "AuthenticationError",
    "CBCMAC",
    "CBCMACForgery",
    "EDUCATIONAL_WARNING",
    "EncryptThenMAC",
    "EncryptThenAuthenticate",
    "EtMMessage",
    "HMAC",
    "cbc_mac",
    "cbc_mac_forgery",
    "cbc_mac_length_extension_forgery",
    "cbc_mac_variable_length_forgery",
    "compute_hmac",
    "encrypt_then_mac_decrypt",
    "encrypt_then_mac_encrypt",
    "hmac_digest",
    "hmac_sha256",
    "hmac_sha256_digest",
    "hmac_verify",
    "cbc_mac_verify",
    "verify_cbc_mac",
    "verify_hmac",
]
