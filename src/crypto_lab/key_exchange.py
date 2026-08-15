"""Finite-field DH, ECDH, ElGamal, and subgroup-validation lessons.

These are textbook constructions intended to make the group operations visible
in a first cryptography course.  They do not provide authenticated key
exchange, parameter generation, or side-channel resistance for real systems.
"""

from __future__ import annotations

from dataclasses import dataclass
from random import Random, SystemRandom

from ecc_factor import is_probable_prime

from .algebra import multiplicative_order
from .elliptic import Curve, INFINITY, Point
from .number_theory import mod_inverse
from .trace import TraceCallback, emit


def _integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")


@dataclass(frozen=True, slots=True)
class DHParameters:
    """A prime-field DH group and the order of its generator."""

    prime: int
    generator: int
    order: int | None = None

    def __post_init__(self) -> None:
        _integer(self.prime, "prime")
        _integer(self.generator, "generator")
        if self.prime < 5 or not is_probable_prime(self.prime):
            raise ValueError("DH prime must be an odd prime at least 5")
        generator = self.generator % self.prime
        object.__setattr__(self, "generator", generator)
        selected_order = self.prime - 1 if self.order is None else self.order
        _integer(selected_order, "order")
        if selected_order < 2 or (self.prime - 1) % selected_order:
            raise ValueError("DH generator order must be a divisor of prime - 1")
        if generator in (0, 1) or pow(generator, selected_order, self.prime) != 1:
            raise ValueError("generator is not in the requested subgroup")
        actual_order = multiplicative_order(generator, self.prime, group_order=selected_order)
        if actual_order != selected_order:
            raise ValueError(
                f"generator has order {actual_order}, not the requested {selected_order}"
            )
        object.__setattr__(self, "order", selected_order)

    @property
    def modulus(self) -> int:
        """Alias used by some group-theory notes."""

        return self.prime


def validate_dh_parameters(
    prime: int,
    generator: int,
    order: int | None = None,
    *,
    trace: TraceCallback | None = None,
) -> DHParameters:
    """Validate and return a finite-field DH parameter object."""

    parameters = DHParameters(prime, generator, order)
    emit(
        trace,
        "dh.parameters",
        f"validated DH group p={parameters.prime}, g={parameters.generator}, order={parameters.order}",
        prime=parameters.prime,
        generator=parameters.generator,
        order=parameters.order,
    )
    return parameters


@dataclass(frozen=True, slots=True)
class DHKeyPair:
    parameters: DHParameters
    private: int
    public: int

    @property
    def private_key(self) -> int:
        return self.private

    @property
    def public_key(self) -> int:
        return self.public


def generate_dh_keypair(
    parameters: DHParameters,
    private_key: int | None = None,
    *,
    seed: int | None = None,
    trace: TraceCallback | None = None,
) -> DHKeyPair:
    """Generate a DH key pair, optionally with a reproducible private scalar."""

    if not isinstance(parameters, DHParameters):
        raise TypeError("parameters must be a DHParameters instance")
    if private_key is None:
        rng = Random(seed) if seed is not None else SystemRandom()
        private_key = rng.randrange(1, parameters.order)
    _validate_private_scalar(private_key, parameters.order, "private_key")
    public_key = pow(parameters.generator, private_key, parameters.prime)
    emit(
        trace,
        "dh.keygen",
        f"DH public key g^{private_key} mod p = {public_key}",
        private=private_key,
        public=public_key,
        prime=parameters.prime,
        generator=parameters.generator,
        order=parameters.order,
    )
    return DHKeyPair(parameters, private_key, public_key)


def validate_dh_public_key(
    parameters: DHParameters,
    public_key: int,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Validate that a peer key is a non-identity element in this subgroup."""

    if not isinstance(parameters, DHParameters):
        raise TypeError("parameters must be a DHParameters instance")
    _integer(public_key, "public_key")
    if not 2 <= public_key < parameters.prime:
        raise ValueError("DH public key must be in the field's non-identity range")
    if pow(public_key, parameters.order, parameters.prime) != 1:
        raise ValueError("DH public key is outside the configured subgroup")
    emit(
        trace,
        "dh.public_key_valid",
        f"validated DH public key {public_key}",
        public=public_key,
        order=parameters.order,
    )
    return public_key


def dh_shared_secret(
    parameters: DHParameters,
    private_key: int,
    peer_public_key: int,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Compute one side of a validated finite-field DH exchange."""

    _validate_private_scalar(private_key, parameters.order, "private_key")
    peer_public_key = validate_dh_public_key(parameters, peer_public_key, trace=trace)
    secret = pow(peer_public_key, private_key, parameters.prime)
    emit(
        trace,
        "dh.shared_secret",
        f"peer_public^{private_key} mod p = {secret}",
        private=private_key,
        peer_public=peer_public_key,
        shared_secret=secret,
    )
    return secret


def diffie_hellman(
    prime: int,
    generator: int,
    private_a: int,
    private_b: int,
    *,
    order: int | None = None,
    trace: TraceCallback | None = None,
) -> int:
    """Run both sides of finite-field DH and return their shared secret."""

    parameters = validate_dh_parameters(prime, generator, order, trace=trace)
    alice = generate_dh_keypair(parameters, private_a, trace=trace)
    bob = generate_dh_keypair(parameters, private_b, trace=trace)
    left = dh_shared_secret(parameters, alice.private, bob.public, trace=trace)
    right = dh_shared_secret(parameters, bob.private, alice.public, trace=trace)
    if left != right:  # Defensive assertion for a useful teaching failure.
        raise ArithmeticError("DH sides derived different shared secrets")
    emit(trace, "dh.complete", f"DH shared secret = {left}", shared_secret=left)
    return left


finite_field_diffie_hellman = diffie_hellman
finite_field_dh = diffie_hellman


@dataclass(frozen=True, slots=True)
class ECDHParameters:
    """An elliptic-curve group with explicitly supplied point orders."""

    curve: Curve
    base_point: Point
    base_order: int
    curve_order: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.curve, Curve) or not isinstance(self.base_point, Point):
            raise TypeError("curve and base_point must use crypto_lab elliptic types")
        _integer(self.base_order, "base_order")
        if self.base_order < 2 or self.base_point.is_infinity:
            raise ValueError("base_order must be at least 2 and base point finite")
        if not self.curve.contains(self.base_point):
            raise ValueError("base point is not on the curve")
        try:
            identity = self.curve.multiply(self.base_order, self.base_point)
        except Exception as error:  # pragma: no cover - protects parameter lessons
            raise ValueError("could not verify base point order") from error
        if identity != INFINITY:
            raise ValueError("base_order * base_point must be the point at infinity")
        if self.curve_order is not None:
            _integer(self.curve_order, "curve_order")
            if self.curve_order < self.base_order or self.curve_order % self.base_order:
                raise ValueError("curve_order must be a multiple of base_order")
            if self.curve.multiply(self.curve_order, self.base_point) != INFINITY:
                raise ValueError("curve_order does not annihilate the base point")


@dataclass(frozen=True, slots=True)
class ECDHKeyPair:
    parameters: ECDHParameters
    private: int
    public: Point

    @property
    def private_key(self) -> int:
        return self.private

    @property
    def public_key(self) -> Point:
        return self.public


def generate_ecdh_keypair(
    parameters: ECDHParameters,
    private_key: int | None = None,
    *,
    seed: int | None = None,
    trace: TraceCallback | None = None,
) -> ECDHKeyPair:
    """Generate an ECDH key pair from supplied curve/base-point orders."""

    if private_key is None:
        rng = Random(seed) if seed is not None else SystemRandom()
        private_key = rng.randrange(1, parameters.base_order)
    _validate_private_scalar(private_key, parameters.base_order, "private_key")
    public = parameters.curve.multiply(private_key, parameters.base_point)
    emit(
        trace,
        "ecdh.keygen",
        f"public point = {private_key}G",
        private=private_key,
        public=public,
        base_order=parameters.base_order,
    )
    return ECDHKeyPair(parameters, private_key, public)


def validate_ecdh_public_key(parameters: ECDHParameters, public_key: Point) -> Point:
    if not isinstance(public_key, Point) or public_key.is_infinity:
        raise ValueError("ECDH public key must be a finite point")
    if not parameters.curve.contains(public_key):
        raise ValueError("ECDH public key is not on the curve")
    if parameters.curve.multiply(parameters.base_order, public_key) != INFINITY:
        raise ValueError("ECDH public key is outside the configured subgroup")
    return public_key


def ecdh_shared_secret(
    parameters: ECDHParameters,
    private_key: int,
    peer_public_key: Point,
    *,
    trace: TraceCallback | None = None,
) -> Point:
    """Compute one side of a validated ECDH exchange."""

    _validate_private_scalar(private_key, parameters.base_order, "private_key")
    peer_public_key = validate_ecdh_public_key(parameters, peer_public_key)
    secret = parameters.curve.multiply(private_key, peer_public_key)
    emit(
        trace,
        "ecdh.shared_secret",
        f"peer_public * {private_key} = {secret}",
        private=private_key,
        peer_public=peer_public_key,
        shared_secret=secret,
    )
    return secret


def elliptic_curve_diffie_hellman(
    curve: Curve,
    base_point: Point,
    private_a: int,
    private_b: int,
    *,
    base_order: int,
    curve_order: int | None = None,
    trace: TraceCallback | None = None,
) -> Point:
    """Run both sides of ECDH with explicit curve and base-point orders."""

    parameters = ECDHParameters(curve, base_point, base_order, curve_order)
    alice = generate_ecdh_keypair(parameters, private_a, trace=trace)
    bob = generate_ecdh_keypair(parameters, private_b, trace=trace)
    left = ecdh_shared_secret(parameters, alice.private, bob.public, trace=trace)
    right = ecdh_shared_secret(parameters, bob.private, alice.public, trace=trace)
    if left != right:
        raise ArithmeticError("ECDH sides derived different shared points")
    emit(trace, "ecdh.complete", f"ECDH shared point = {left}", shared_secret=left)
    return left


@dataclass(frozen=True, slots=True)
class ElGamalPublicKey:
    prime: int
    generator: int
    public_component: int
    order: int | None = None

    def __post_init__(self) -> None:
        parameters = DHParameters(self.prime, self.generator, self.order)
        public = validate_dh_public_key(parameters, self.public_component)
        object.__setattr__(self, "prime", parameters.prime)
        object.__setattr__(self, "generator", parameters.generator)
        object.__setattr__(self, "order", parameters.order)
        object.__setattr__(self, "public_component", public)

    @property
    def y(self) -> int:
        return self.public_component


@dataclass(frozen=True, slots=True)
class ElGamalPrivateKey:
    prime: int
    generator: int
    private_exponent: int
    public_component: int
    order: int | None = None

    @property
    def x(self) -> int:
        return self.private_exponent

    @property
    def public_key(self) -> ElGamalPublicKey:
        return ElGamalPublicKey(
            self.prime,
            self.generator,
            self.public_component,
            self.order,
        )


@dataclass(frozen=True, slots=True)
class ElGamalKeyPair:
    public: ElGamalPublicKey
    private: ElGamalPrivateKey


@dataclass(frozen=True, slots=True)
class ElGamalCiphertext:
    first: int
    second: int

    @property
    def c1(self) -> int:
        return self.first

    @property
    def c2(self) -> int:
        return self.second


def generate_elgamal_keypair(
    prime: int,
    generator: int,
    private_key: int | None = None,
    *,
    order: int | None = None,
    seed: int | None = None,
    trace: TraceCallback | None = None,
) -> ElGamalKeyPair:
    """Generate textbook ElGamal keys over a validated DH group."""

    parameters = validate_dh_parameters(prime, generator, order, trace=trace)
    dh_pair = generate_dh_keypair(parameters, private_key, seed=seed, trace=trace)
    public = ElGamalPublicKey(parameters.prime, parameters.generator, dh_pair.public, parameters.order)
    private = ElGamalPrivateKey(
        parameters.prime,
        parameters.generator,
        dh_pair.private,
        dh_pair.public,
        parameters.order,
    )
    emit(trace, "elgamal.keygen", f"ElGamal public component y = {dh_pair.public}", public=dh_pair.public)
    return ElGamalKeyPair(public, private)


def elgamal_encrypt(
    public_key: ElGamalPublicKey,
    message: int,
    ephemeral_key: int | None = None,
    *,
    seed: int | None = None,
    trace: TraceCallback | None = None,
) -> ElGamalCiphertext:
    """Encrypt one field element with textbook ElGamal."""

    _integer(message, "message")
    if not 0 <= message < public_key.prime:
        raise ValueError("message must satisfy 0 <= message < prime")
    parameters = DHParameters(public_key.prime, public_key.generator, public_key.order)
    if ephemeral_key is None:
        rng = Random(seed) if seed is not None else SystemRandom()
        ephemeral_key = rng.randrange(1, parameters.order)
    _validate_private_scalar(ephemeral_key, parameters.order, "ephemeral_key")
    shared = pow(public_key.public_component, ephemeral_key, parameters.prime)
    ciphertext = ElGamalCiphertext(
        pow(parameters.generator, ephemeral_key, parameters.prime),
        message * shared % parameters.prime,
    )
    emit(
        trace,
        "elgamal.encrypt",
        f"ElGamal ciphertext = ({ciphertext.first}, {ciphertext.second})",
        plaintext=message,
        ephemeral=ephemeral_key,
        shared=shared,
        c1=ciphertext.first,
        c2=ciphertext.second,
    )
    return ciphertext


def elgamal_decrypt(
    private_key: ElGamalPrivateKey,
    ciphertext: ElGamalCiphertext,
    *,
    trace: TraceCallback | None = None,
) -> int:
    """Decrypt a textbook ElGamal ciphertext."""

    parameters = DHParameters(private_key.prime, private_key.generator, private_key.order)
    _validate_private_scalar(private_key.private_exponent, parameters.order, "private_exponent")
    if not isinstance(ciphertext, ElGamalCiphertext):
        raise TypeError("ciphertext must be an ElGamalCiphertext")
    if not 1 <= ciphertext.first < parameters.prime or not 0 <= ciphertext.second < parameters.prime:
        raise ValueError("ciphertext components are outside the field")
    shared = pow(ciphertext.first, private_key.private_exponent, parameters.prime)
    message = ciphertext.second * mod_inverse(shared, parameters.prime) % parameters.prime
    emit(
        trace,
        "elgamal.decrypt",
        f"ElGamal plaintext = {message}",
        c1=ciphertext.first,
        c2=ciphertext.second,
        shared=shared,
        plaintext=message,
    )
    return message


elgamal_keygen = generate_elgamal_keypair


@dataclass(frozen=True, slots=True)
class SmallSubgroupAttackResult:
    prime: int
    malicious_element: int
    subgroup_order: int
    victim_private: int
    observed_shared_secret: int
    recovered_residue: int


def demonstrate_small_subgroup_attack(
    prime: int,
    victim_private: int,
    malicious_element: int,
    subgroup_order: int,
    *,
    trace: TraceCallback | None = None,
) -> SmallSubgroupAttackResult:
    """Recover a victim's private exponent modulo a small subgroup order.

    The oracle is modelled by returning ``malicious_element**victim_private``.
    In a real protocol, rejecting public keys outside the negotiated subgroup
    prevents this leakage.
    """

    _integer(prime, "prime")
    _integer(victim_private, "victim_private")
    _integer(malicious_element, "malicious_element")
    _integer(subgroup_order, "subgroup_order")
    if prime < 5 or not is_probable_prime(prime):
        raise ValueError("prime must be an odd prime")
    if subgroup_order < 2 or (prime - 1) % subgroup_order:
        raise ValueError("subgroup_order must divide prime - 1")
    malicious_element %= prime
    actual = multiplicative_order(malicious_element, prime, group_order=subgroup_order)
    if actual != subgroup_order:
        raise ValueError("malicious_element does not have the requested subgroup order")
    observed = pow(malicious_element, victim_private, prime)
    recovered: int | None = None
    for residue in range(subgroup_order):
        if pow(malicious_element, residue, prime) == observed:
            recovered = residue
            break
    assert recovered is not None
    result = SmallSubgroupAttackResult(
        prime,
        malicious_element,
        subgroup_order,
        victim_private,
        observed,
        recovered,
    )
    emit(
        trace,
        "dh.small_subgroup_attack",
        f"oracle reveals private exponent modulo {subgroup_order}: {recovered}",
        prime=prime,
        element=malicious_element,
        subgroup_order=subgroup_order,
        observed=observed,
        recovered=recovered,
    )
    return result


small_subgroup_attack = demonstrate_small_subgroup_attack
small_subgroup_demo = demonstrate_small_subgroup_attack
DiffieHellmanParameters = DHParameters
DiffieHellmanKeyPair = DHKeyPair
ElGamalPublic = ElGamalPublicKey
ElGamalPrivate = ElGamalPrivateKey


def _validate_private_scalar(value: int, order: int, name: str) -> None:
    _integer(value, name)
    if not 1 <= value < order:
        raise ValueError(f"{name} must satisfy 1 <= {name} < subgroup order")


__all__ = [
    "DHKeyPair",
    "DHParameters",
    "DiffieHellmanKeyPair",
    "DiffieHellmanParameters",
    "ECDHKeyPair",
    "ECDHParameters",
    "ElGamalCiphertext",
    "ElGamalKeyPair",
    "ElGamalPrivateKey",
    "ElGamalPrivate",
    "ElGamalPublicKey",
    "ElGamalPublic",
    "SmallSubgroupAttackResult",
    "demonstrate_small_subgroup_attack",
    "dh_shared_secret",
    "diffie_hellman",
    "ecdh_shared_secret",
    "elgamal_decrypt",
    "elgamal_encrypt",
    "elgamal_keygen",
    "elliptic_curve_diffie_hellman",
    "finite_field_diffie_hellman",
    "finite_field_dh",
    "generate_dh_keypair",
    "generate_ecdh_keypair",
    "generate_elgamal_keypair",
    "small_subgroup_attack",
    "small_subgroup_demo",
    "validate_dh_parameters",
    "validate_dh_public_key",
    "validate_ecdh_public_key",
]
