"""Inspectable digital-signature lessons and nonce-reuse attacks.

Every construction here is deliberately pedagogical.  Textbook RSA is
hash-and-sign without secure encoding, Lamport signatures are one-time and
large, and the tiny DSA/ECDSA parameter sets are for arithmetic exercises.
None of these functions should protect real messages.  APIs are silent by
default and accept the repository's structured trace callback.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import random
from typing import Final

from .elliptic import Curve, INFINITY, Point
from .number_theory import mod_inverse, mod_pow
from .rsa import RSAKeyPair, RSAPrivateKey, RSAPublicKey
from .trace import TraceCallback, emit


EDUCATIONAL_WARNING: Final[str] = (
    "Educational signatures only; textbook RSA, tiny DSA, ECDSA, and Lamport "
    "keys are not production cryptography."
)


def _ensure_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _hash_bytes(message: bytes, hash_name: str = "sha256") -> bytes:
    _ensure_bytes(message, "message")
    try:
        return hashlib.new(hash_name, message).digest()
    except ValueError as error:
        raise ValueError(f"unknown hash function: {hash_name}") from error


def rsa_hash_digest(message: bytes, *, hash_name: str = "sha256") -> bytes:
    """Return the digest used by the intentionally textbook RSA signature."""

    return _hash_bytes(message, hash_name)


def _rsa_public_key(key: RSAKeyPair | RSAPublicKey) -> RSAPublicKey:
    if isinstance(key, RSAKeyPair):
        return key.public
    if isinstance(key, RSAPublicKey):
        return key
    raise TypeError("key must be RSAKeyPair or RSAPublicKey")


def _rsa_private_key(key: RSAKeyPair | RSAPrivateKey) -> RSAPrivateKey:
    if isinstance(key, RSAKeyPair):
        return key.private
    if isinstance(key, RSAPrivateKey):
        return key
    raise TypeError("key must be RSAKeyPair or RSAPrivateKey")


@dataclass(frozen=True, slots=True)
class RSATextbookSignature:
    """A signature plus the reduced digest shown in the classroom trace."""

    value: int
    digest_integer: int
    hash_name: str = "sha256"

    def __int__(self) -> int:
        return self.value


RSASignature = RSATextbookSignature


def rsa_sign(
    message: bytes,
    key: RSAKeyPair | RSAPrivateKey,
    *,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> int:
    """Sign ``message`` by reducing a hash modulo ``n`` and applying RSA ``d``.

    Reducing a digest modulo ``n`` is intentionally not a real signature
    encoding.  It makes the operation work with the repository's small
    classroom RSA keys while exposing the textbook ``m^d mod n`` arithmetic.
    """

    private = _rsa_private_key(key)
    digest = _hash_bytes(message, hash_name)
    digest_integer = int.from_bytes(digest, "big") % private.modulus
    signature = mod_pow(digest_integer, private.exponent, private.modulus, trace=trace)
    emit(
        trace,
        "rsa_signature.sign",
        f"hash-and-sign digest {digest_integer} -> signature {signature}",
        hash_name=hash_name,
        digest=digest.hex(),
        digest_integer=digest_integer,
        signature=signature,
        modulus=private.modulus,
    )
    return signature


def rsa_sign_detailed(
    message: bytes,
    key: RSAKeyPair | RSAPrivateKey,
    *,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> RSATextbookSignature:
    """Return the signature together with the reduced hash integer."""

    private = _rsa_private_key(key)
    digest = _hash_bytes(message, hash_name)
    digest_integer = int.from_bytes(digest, "big") % private.modulus
    value = rsa_sign(message, private, hash_name=hash_name, trace=trace)
    return RSATextbookSignature(value, digest_integer, hash_name)


def rsa_verify(
    message: bytes,
    signature: int | RSATextbookSignature,
    key: RSAKeyPair | RSAPublicKey,
    *,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bool:
    """Verify a textbook RSA hash-and-sign signature."""

    public = _rsa_public_key(key)
    value = int(signature) if isinstance(signature, RSATextbookSignature) else signature
    if not isinstance(value, int) or not 0 <= value < public.modulus:
        return False
    digest = _hash_bytes(message, hash_name)
    expected = int.from_bytes(digest, "big") % public.modulus
    recovered = mod_pow(value, public.exponent, public.modulus, trace=trace)
    valid = recovered == expected
    emit(
        trace,
        "rsa_signature.verify",
        "RSA signature accepted" if valid else "RSA signature rejected",
        hash_name=hash_name,
        digest=digest.hex(),
        expected=expected,
        recovered=recovered,
        signature=value,
        valid=valid,
    )
    return valid


rsa_hash_and_sign = rsa_sign
textbook_rsa_sign = rsa_sign
verify_rsa_signature = rsa_verify


@dataclass(frozen=True, slots=True)
class LamportSignature:
    """One selected secret value for each bit of a message digest."""

    values: tuple[bytes, ...]
    hash_name: str = "sha256"

    @property
    def parts(self) -> tuple[bytes, ...]:
        return self.values


@dataclass(frozen=True, slots=True)
class LamportPublicKey:
    """The 2*n hash commitments in a Lamport one-time public key."""

    commitments: tuple[tuple[bytes, bytes], ...]
    hash_name: str = "sha256"

    @property
    def digest_size(self) -> int:
        return len(self.commitments) // 8

    @property
    def bit_count(self) -> int:
        return len(self.commitments)

    def verify(
        self,
        message: bytes,
        signature: LamportSignature,
        *,
        trace: TraceCallback | None = None,
    ) -> bool:
        return lamport_verify(self, message, signature, trace=trace)


@dataclass(frozen=True, slots=True)
class LamportPrivateKey:
    """Lamport secrets.  A private key must only be used once."""

    secrets: tuple[tuple[bytes, bytes], ...]
    hash_name: str = "sha256"

    @property
    def digest_size(self) -> int:
        return len(self.secrets) // 8

    @property
    def bit_count(self) -> int:
        return len(self.secrets)

    def sign(
        self,
        message: bytes,
        *,
        trace: TraceCallback | None = None,
    ) -> LamportSignature:
        return lamport_sign(self, message, trace=trace)


@dataclass(frozen=True, slots=True)
class LamportKeyPair:
    private: LamportPrivateKey
    public: LamportPublicKey

    @classmethod
    def generate(
        cls,
        *,
        seed: int | str | bytes | None = 0,
        hash_name: str = "sha256",
        trace: TraceCallback | None = None,
    ) -> "LamportKeyPair":
        return lamport_keygen(seed=seed, hash_name=hash_name, trace=trace)

    @property
    def private_key(self) -> LamportPrivateKey:
        return self.private

    @property
    def public_key(self) -> LamportPublicKey:
        return self.public


LamportKeypair = LamportKeyPair


def lamport_keygen(
    *,
    seed: int | str | bytes | None = 0,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> LamportKeyPair:
    """Generate deterministic Lamport secrets with a seeded PRNG.

    Deterministic generation is convenient for reproducible lectures; it is
    not appropriate for deployment because the seed is not an entropy source.
    """

    digest_size = len(_hash_bytes(b"", hash_name))
    rng = random.Random(seed)
    secrets: list[tuple[bytes, bytes]] = []
    commitments: list[tuple[bytes, bytes]] = []
    # A Lamport key has two secrets for every *bit* of the digest, not merely
    # one pair per digest byte.
    for index in range(digest_size * 8):
        pair = tuple(
            rng.getrandbits(8 * digest_size).to_bytes(digest_size, "big")
            for _ in range(2)
        )
        assert len(pair) == 2
        secrets.append((pair[0], pair[1]))
        commitments.append(
            (
                hashlib.new(hash_name, pair[0]).digest(),
                hashlib.new(hash_name, pair[1]).digest(),
            )
        )
    private = LamportPrivateKey(tuple(secrets), hash_name)
    public = LamportPublicKey(tuple(commitments), hash_name)
    emit(
        trace,
        "lamport.keygen",
        f"generated {digest_size * 8} one-time digest-bit commitments",
        digest_size=digest_size,
        hash_name=hash_name,
        seed=repr(seed),
    )
    return LamportKeyPair(private, public)


def _digest_bits(digest: bytes) -> tuple[int, ...]:
    return tuple((byte >> (7 - offset)) & 1 for byte in digest for offset in range(8))


def lamport_sign(
    private_key: LamportPrivateKey,
    message: bytes,
    *,
    trace: TraceCallback | None = None,
) -> LamportSignature:
    if not isinstance(private_key, LamportPrivateKey):
        raise TypeError("private_key must be LamportPrivateKey")
    digest = _hash_bytes(message, private_key.hash_name)
    bits = _digest_bits(digest)
    if len(bits) != len(private_key.secrets):
        raise ValueError("Lamport secret length does not match the selected hash")
    values = tuple(
        private_key.secrets[index][bit]
        for index, bit in enumerate(bits)
    )
    emit(
        trace,
        "lamport.sign",
        "selected one secret for each message-digest bit",
        hash_name=private_key.hash_name,
        digest=digest.hex(),
        bits="".join(str(bit) for bit in bits),
        component_count=len(values),
        warning="Lamport private keys are one-time keys",
    )
    return LamportSignature(values, private_key.hash_name)


def lamport_verify(
    public_key: LamportPublicKey,
    message: bytes,
    signature: LamportSignature,
    *,
    trace: TraceCallback | None = None,
) -> bool:
    if not isinstance(public_key, LamportPublicKey):
        raise TypeError("public_key must be LamportPublicKey")
    if not isinstance(signature, LamportSignature):
        return False
    if signature.hash_name != public_key.hash_name:
        return False
    digest = _hash_bytes(message, public_key.hash_name)
    bits = _digest_bits(digest)
    if len(signature.values) != len(bits) or len(public_key.commitments) != len(bits):
        return False
    valid = True
    for index, (value, bit) in enumerate(zip(signature.values, bits, strict=True)):
        if not isinstance(value, bytes):
            valid = False
            break
        commitment = public_key.commitments[index][bit]
        if not hmac.compare_digest(hashlib.new(public_key.hash_name, value).digest(), commitment):
            valid = False
            break
    emit(
        trace,
        "lamport.verify",
        "Lamport signature accepted" if valid else "Lamport signature rejected",
        hash_name=public_key.hash_name,
        digest=digest.hex(),
        valid=valid,
    )
    return valid


generate_lamport_keypair = lamport_keygen
lamport_generate = lamport_keygen


@dataclass(frozen=True, slots=True)
class DSAParameters:
    """Small DSA parameters ``q | p-1`` for hand-checkable exercises."""

    p: int = 23
    q: int = 11
    g: int = 2

    def __post_init__(self) -> None:
        if self.p <= 2 or self.q <= 1 or (self.p - 1) % self.q:
            raise ValueError("DSA parameters require q | (p - 1), with p > 2")
        if not 1 < self.g < self.p or pow(self.g, self.q, self.p) != 1:
            raise ValueError("g must be a non-identity element of order dividing q")


DEFAULT_DSA_PARAMETERS: Final[DSAParameters] = DSAParameters()
DSAParams = DSAParameters


@dataclass(frozen=True, slots=True)
class DSASignature:
    r: int
    s: int


@dataclass(frozen=True, slots=True)
class DSAKeyPair:
    parameters: DSAParameters
    private: int
    public: int

    @classmethod
    def generate(
        cls,
        parameters: DSAParameters = DEFAULT_DSA_PARAMETERS,
        *,
        private_key: int | None = None,
        seed: int | str | bytes | None = 0,
        trace: TraceCallback | None = None,
    ) -> "DSAKeyPair":
        return dsa_keygen(
            parameters, private_key=private_key, seed=seed, trace=trace
        )

    @property
    def private_key(self) -> int:
        return self.private

    @property
    def public_key(self) -> int:
        return self.public

    def sign(
        self,
        message: bytes,
        *,
        nonce: int | None = None,
        seed: int | str | bytes | None = 0,
        hash_name: str = "sha256",
        trace: TraceCallback | None = None,
    ) -> "DSASignature":
        return dsa_sign(
            message,
            self,
            nonce=nonce,
            seed=seed,
            hash_name=hash_name,
            trace=trace,
        )

    def verify(
        self,
        message: bytes,
        signature: "DSASignature",
        *,
        hash_name: str = "sha256",
        trace: TraceCallback | None = None,
    ) -> bool:
        return dsa_verify(message, signature, self, hash_name=hash_name, trace=trace)


DSAKeypair = DSAKeyPair


def dsa_keygen(
    parameters: DSAParameters = DEFAULT_DSA_PARAMETERS,
    *,
    private_key: int | None = None,
    seed: int | str | bytes | None = 0,
    trace: TraceCallback | None = None,
) -> DSAKeyPair:
    if private_key is None:
        private_key = random.Random(seed).randrange(1, parameters.q)
    if not 1 <= private_key < parameters.q:
        raise ValueError("DSA private key must satisfy 1 <= x < q")
    public = pow(parameters.g, private_key, parameters.p)
    emit(
        trace,
        "dsa.keygen",
        f"public key y=g^x mod p={public}",
        p=parameters.p,
        q=parameters.q,
        g=parameters.g,
        private=private_key,
        public=public,
    )
    return DSAKeyPair(parameters, private_key, public)


def _dsa_hash(message: bytes, parameters: DSAParameters, hash_name: str) -> int:
    return int.from_bytes(_hash_bytes(message, hash_name), "big") % parameters.q


def _choose_nonce(q: int, seed: int | str | bytes | None) -> int:
    return random.Random(seed).randrange(1, q)


def dsa_sign(
    message: bytes,
    key: DSAKeyPair | int,
    *,
    nonce: int | None = None,
    seed: int | str | bytes | None = 0,
    parameters: DSAParameters = DEFAULT_DSA_PARAMETERS,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> DSASignature:
    if isinstance(key, DSAKeyPair):
        parameters, private = key.parameters, key.private
    elif isinstance(key, int):
        private = key
    else:
        raise TypeError("key must be DSAKeyPair or an integer private key")
    if not 1 <= private < parameters.q:
        raise ValueError("DSA private key must satisfy 1 <= x < q")
    z = _dsa_hash(message, parameters, hash_name)
    selected_nonce = _choose_nonce(parameters.q, seed) if nonce is None else nonce
    if not 1 <= selected_nonce < parameters.q:
        raise ValueError("DSA nonce must satisfy 1 <= k < q")
    r = pow(parameters.g, selected_nonce, parameters.p) % parameters.q
    if r == 0:
        raise ValueError("selected nonce produced r=0; choose another nonce")
    s = (mod_inverse(selected_nonce, parameters.q) * (z + private * r)) % parameters.q
    if s == 0:
        raise ValueError("selected nonce produced s=0; choose another nonce")
    signature = DSASignature(r, s)
    emit(
        trace,
        "dsa.sign",
        f"DSA signature (r, s)=({r}, {s})",
        hash_name=hash_name,
        digest_integer=z,
        nonce=selected_nonce,
        r=r,
        s=s,
        warning="never reuse a DSA nonce",
    )
    return signature


def dsa_verify(
    message: bytes,
    signature: DSASignature,
    key: DSAKeyPair | DSAParameters | int,
    *,
    parameters: DSAParameters | None = None,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bool:
    if isinstance(key, DSAKeyPair):
        parameters, public = key.parameters, key.public
    elif isinstance(key, DSAParameters):
        raise TypeError("verification also needs a DSA public key")
    elif isinstance(key, int):
        parameters, public = parameters or DEFAULT_DSA_PARAMETERS, key
    else:
        raise TypeError("key must be DSAKeyPair or an integer public key")
    if not isinstance(signature, DSASignature):
        return False
    r, s = signature.r, signature.s
    if not 0 < r < parameters.q or not 0 < s < parameters.q:
        return False
    try:
        w = mod_inverse(s, parameters.q)
    except ValueError:
        return False
    z = _dsa_hash(message, parameters, hash_name)
    u1 = z * w % parameters.q
    u2 = r * w % parameters.q
    value = (pow(parameters.g, u1, parameters.p) * pow(public, u2, parameters.p) % parameters.p) % parameters.q
    valid = value == r
    emit(
        trace,
        "dsa.verify",
        "DSA signature accepted" if valid else "DSA signature rejected",
        hash_name=hash_name,
        digest_integer=z,
        u1=u1,
        u2=u2,
        value=value,
        r=r,
        valid=valid,
    )
    return valid


def dsa_recover_private_key_from_reused_nonce(
    message1: bytes,
    signature1: DSASignature,
    message2: bytes,
    signature2: DSASignature,
    parameters: DSAParameters = DEFAULT_DSA_PARAMETERS,
    *,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> int:
    """Recover ``x`` from two DSA signatures sharing the same nonce ``k``."""

    if signature1.r != signature2.r:
        raise ValueError("signatures do not expose a reused nonce (r differs)")
    if signature1.s == signature2.s:
        raise ValueError("signatures have no invertible s difference")
    z1 = _dsa_hash(message1, parameters, hash_name)
    z2 = _dsa_hash(message2, parameters, hash_name)
    try:
        k = ((z1 - z2) * mod_inverse(signature1.s - signature2.s, parameters.q)) % parameters.q
        private = ((signature1.s * k - z1) * mod_inverse(signature1.r, parameters.q)) % parameters.q
    except ValueError as error:
        raise ValueError("reused-nonce equations are not invertible") from error
    emit(
        trace,
        "dsa.reused_nonce",
        f"recovered nonce k={k} and private key x={private}",
        z1=z1,
        z2=z2,
        r=signature1.r,
        s1=signature1.s,
        s2=signature2.s,
        recovered_nonce=k,
        recovered_private=private,
    )
    return private


recover_dsa_private_key = dsa_recover_private_key_from_reused_nonce
recover_dsa_private = dsa_recover_private_key_from_reused_nonce


@dataclass(frozen=True, slots=True)
class ECDSAParameters:
    """A short-Weierstrass curve, generator, and generator order."""

    curve: Curve
    generator: Point
    order: int

    def __post_init__(self) -> None:
        if self.order <= 1:
            raise ValueError("ECDSA order must be greater than one")
        if not self.curve.contains(self.generator):
            raise ValueError("ECDSA generator must lie on the curve")
        if self.curve.multiply(self.order, self.generator) != INFINITY:
            raise ValueError("ECDSA order must annihilate the generator")


# Small prime-order subgroup: y^2 = x^3 + 2 over F_97, G has order 13.
DEFAULT_ECDSA_PARAMETERS: Final[ECDSAParameters] = ECDSAParameters(
    Curve(0, 2, 97), Point(7, 32), 13
)
ECDSAParams = ECDSAParameters


@dataclass(frozen=True, slots=True)
class ECDSASignature:
    r: int
    s: int


@dataclass(frozen=True, slots=True)
class ECDSAKeyPair:
    parameters: ECDSAParameters
    private: int
    public: Point

    @classmethod
    def generate(
        cls,
        parameters: ECDSAParameters = DEFAULT_ECDSA_PARAMETERS,
        *,
        private_key: int | None = None,
        seed: int | str | bytes | None = 0,
        trace: TraceCallback | None = None,
    ) -> "ECDSAKeyPair":
        return ecdsa_keygen(
            parameters, private_key=private_key, seed=seed, trace=trace
        )

    @property
    def private_key(self) -> int:
        return self.private

    @property
    def public_key(self) -> Point:
        return self.public

    def sign(
        self,
        message: bytes,
        *,
        nonce: int | None = None,
        seed: int | str | bytes | None = 0,
        hash_name: str = "sha256",
        trace: TraceCallback | None = None,
    ) -> "ECDSASignature":
        return ecdsa_sign(
            message,
            self,
            nonce=nonce,
            seed=seed,
            hash_name=hash_name,
            trace=trace,
        )

    def verify(
        self,
        message: bytes,
        signature: "ECDSASignature",
        *,
        hash_name: str = "sha256",
        trace: TraceCallback | None = None,
    ) -> bool:
        return ecdsa_verify(message, signature, self, hash_name=hash_name, trace=trace)


ECDSAKeypair = ECDSAKeyPair


def ecdsa_keygen(
    parameters: ECDSAParameters = DEFAULT_ECDSA_PARAMETERS,
    *,
    private_key: int | None = None,
    seed: int | str | bytes | None = 0,
    trace: TraceCallback | None = None,
) -> ECDSAKeyPair:
    if private_key is None:
        private_key = random.Random(seed).randrange(1, parameters.order)
    if not 1 <= private_key < parameters.order:
        raise ValueError("ECDSA private key must satisfy 1 <= d < order")
    public = parameters.curve.multiply(private_key, parameters.generator)
    emit(
        trace,
        "ecdsa.keygen",
        f"public point Q=dG={public}",
        private=private_key,
        public=repr(public),
        order=parameters.order,
    )
    return ECDSAKeyPair(parameters, private_key, public)


def _ecdsa_hash(message: bytes, parameters: ECDSAParameters, hash_name: str) -> int:
    return int.from_bytes(_hash_bytes(message, hash_name), "big") % parameters.order


def ecdsa_sign(
    message: bytes,
    key: ECDSAKeyPair | int,
    *,
    nonce: int | None = None,
    seed: int | str | bytes | None = 0,
    parameters: ECDSAParameters = DEFAULT_ECDSA_PARAMETERS,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> ECDSASignature:
    if isinstance(key, ECDSAKeyPair):
        parameters, private = key.parameters, key.private
    elif isinstance(key, int):
        private = key
    else:
        raise TypeError("key must be ECDSAKeyPair or an integer private key")
    if not 1 <= private < parameters.order:
        raise ValueError("ECDSA private key must satisfy 1 <= d < order")
    z = _ecdsa_hash(message, parameters, hash_name)
    selected_nonce = _choose_nonce(parameters.order, seed) if nonce is None else nonce
    if not 1 <= selected_nonce < parameters.order:
        raise ValueError("ECDSA nonce must satisfy 1 <= k < order")
    point = parameters.curve.multiply(selected_nonce, parameters.generator)
    if point.is_infinity or point.x is None:
        raise ValueError("selected nonce produced the point at infinity")
    r = point.x % parameters.order
    if r == 0:
        raise ValueError("selected nonce produced r=0; choose another nonce")
    s = (mod_inverse(selected_nonce, parameters.order) * (z + r * private)) % parameters.order
    if s == 0:
        raise ValueError("selected nonce produced s=0; choose another nonce")
    signature = ECDSASignature(r, s)
    emit(
        trace,
        "ecdsa.sign",
        f"ECDSA signature (r, s)=({r}, {s})",
        hash_name=hash_name,
        digest_integer=z,
        nonce=selected_nonce,
        point=repr(point),
        r=r,
        s=s,
        warning="never reuse an ECDSA nonce",
    )
    return signature


def ecdsa_verify(
    message: bytes,
    signature: ECDSASignature,
    key: ECDSAKeyPair | Point,
    *,
    parameters: ECDSAParameters = DEFAULT_ECDSA_PARAMETERS,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> bool:
    if isinstance(key, ECDSAKeyPair):
        parameters, public = key.parameters, key.public
    elif isinstance(key, Point):
        public = key
    else:
        raise TypeError("key must be ECDSAKeyPair or a public Point")
    if not isinstance(signature, ECDSASignature):
        return False
    r, s = signature.r, signature.s
    if not 0 < r < parameters.order or not 0 < s < parameters.order:
        return False
    try:
        w = mod_inverse(s, parameters.order)
    except ValueError:
        return False
    z = _ecdsa_hash(message, parameters, hash_name)
    u1 = z * w % parameters.order
    u2 = r * w % parameters.order
    try:
        point = parameters.curve.add(
            parameters.curve.multiply(u1, parameters.generator),
            parameters.curve.multiply(u2, public),
        )
    except (ArithmeticError, ValueError):
        return False
    valid = not point.is_infinity and point.x is not None and point.x % parameters.order == r
    emit(
        trace,
        "ecdsa.verify",
        "ECDSA signature accepted" if valid else "ECDSA signature rejected",
        hash_name=hash_name,
        digest_integer=z,
        u1=u1,
        u2=u2,
        point=repr(point),
        r=r,
        valid=valid,
    )
    return valid


def ecdsa_recover_private_key_from_reused_nonce(
    message1: bytes,
    signature1: ECDSASignature,
    message2: bytes,
    signature2: ECDSASignature,
    parameters: ECDSAParameters = DEFAULT_ECDSA_PARAMETERS,
    *,
    hash_name: str = "sha256",
    trace: TraceCallback | None = None,
) -> int:
    """Recover an ECDSA private scalar from two signatures with one nonce."""

    if signature1.r != signature2.r:
        raise ValueError("signatures do not expose a reused nonce (r differs)")
    if signature1.s == signature2.s:
        raise ValueError("signatures have no invertible s difference")
    z1 = _ecdsa_hash(message1, parameters, hash_name)
    z2 = _ecdsa_hash(message2, parameters, hash_name)
    try:
        k = ((z1 - z2) * mod_inverse(signature1.s - signature2.s, parameters.order)) % parameters.order
        private = ((signature1.s * k - z1) * mod_inverse(signature1.r, parameters.order)) % parameters.order
    except ValueError as error:
        raise ValueError("reused-nonce equations are not invertible") from error
    emit(
        trace,
        "ecdsa.reused_nonce",
        f"recovered nonce k={k} and private key d={private}",
        z1=z1,
        z2=z2,
        r=signature1.r,
        s1=signature1.s,
        s2=signature2.s,
        recovered_nonce=k,
        recovered_private=private,
    )
    return private


recover_ecdsa_private_key = ecdsa_recover_private_key_from_reused_nonce
recover_ecdsa_private = ecdsa_recover_private_key_from_reused_nonce


__all__ = [
    "DEFAULT_DSA_PARAMETERS",
    "DEFAULT_ECDSA_PARAMETERS",
    "DSAKeyPair",
    "DSAKeypair",
    "DSAParams",
    "DSAParameters",
    "DSASignature",
    "ECDSAKeyPair",
    "ECDSAKeypair",
    "ECDSAParams",
    "ECDSAParameters",
    "ECDSASignature",
    "EDUCATIONAL_WARNING",
    "LamportKeyPair",
    "LamportKeypair",
    "LamportPrivateKey",
    "LamportPublicKey",
    "LamportSignature",
    "RSATextbookSignature",
    "RSASignature",
    "dsa_keygen",
    "dsa_recover_private_key_from_reused_nonce",
    "dsa_sign",
    "dsa_verify",
    "ecdsa_keygen",
    "ecdsa_recover_private_key_from_reused_nonce",
    "ecdsa_sign",
    "ecdsa_verify",
    "generate_lamport_keypair",
    "lamport_keygen",
    "lamport_generate",
    "lamport_sign",
    "lamport_verify",
    "recover_dsa_private_key",
    "recover_dsa_private",
    "recover_ecdsa_private_key",
    "recover_ecdsa_private",
    "rsa_hash_and_sign",
    "rsa_hash_digest",
    "rsa_sign",
    "rsa_sign_detailed",
    "textbook_rsa_sign",
    "rsa_verify",
    "verify_rsa_signature",
]
