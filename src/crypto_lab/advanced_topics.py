"""Compact final-week demonstrations: zero knowledge, LWE, MPC, and BB84."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random

from .number_theory import mod_inverse
from .trace import TraceCallback, emit


@dataclass(frozen=True, slots=True)
class SchnorrTranscript:
    commitment: int
    challenge: int
    response: int


def schnorr_public_key(secret: int, *, prime: int, generator: int) -> int:
    if not 0 < secret < prime - 1:
        raise ValueError("secret must lie within the exponent range")
    return pow(generator, secret, prime)


def schnorr_prove(
    secret: int,
    *,
    nonce: int,
    challenge: int,
    prime: int,
    subgroup_order: int,
    generator: int,
    trace: TraceCallback | None = None,
) -> SchnorrTranscript:
    """Produce an interactive Schnorr identification transcript."""

    if (prime - 1) % subgroup_order:
        raise ValueError("subgroup_order must divide prime - 1")
    if pow(generator, subgroup_order, prime) != 1:
        raise ValueError("generator is not in the requested subgroup")
    commitment = pow(generator, nonce % subgroup_order, prime)
    response = (nonce + challenge * secret) % subgroup_order
    emit(
        trace,
        "zk.commit",
        f"prover sends commitment {commitment}",
        commitment=commitment,
    )
    emit(
        trace,
        "zk.response",
        f"challenge={challenge}; response={response}",
        challenge=challenge,
        response=response,
    )
    return SchnorrTranscript(commitment, challenge, response)


def schnorr_verify(
    public_key: int,
    transcript: SchnorrTranscript,
    *,
    prime: int,
    generator: int,
) -> bool:
    left = pow(generator, transcript.response, prime)
    right = (
        transcript.commitment
        * pow(public_key, transcript.challenge, prime)
        % prime
    )
    return left == right


def simulate_schnorr_transcript(
    public_key: int,
    *,
    challenge: int,
    response: int,
    prime: int,
    generator: int,
) -> SchnorrTranscript:
    """Simulate a valid honest-verifier transcript without the secret."""

    commitment = (
        pow(generator, response, prime)
        * mod_inverse(pow(public_key, challenge, prime), prime)
        % prime
    )
    return SchnorrTranscript(commitment, challenge, response)


@dataclass(frozen=True, slots=True)
class LWEPublicKey:
    matrix: tuple[tuple[int, ...], ...]
    vector: tuple[int, ...]
    modulus: int


@dataclass(frozen=True, slots=True)
class LWEKeyPair:
    public: LWEPublicKey
    secret: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LWECiphertext:
    vector: tuple[int, ...]
    value: int


def lwe_keygen(
    *,
    dimension: int = 4,
    samples: int = 8,
    modulus: int = 257,
    seed: int = 0,
    trace: TraceCallback | None = None,
) -> LWEKeyPair:
    """Generate deliberately tiny, insecure Learning-With-Errors parameters."""

    if dimension < 2 or samples < dimension or modulus < 11:
        raise ValueError("LWE lesson needs dimension >= 2, samples >= dimension, q >= 11")
    randomness = Random(seed)
    secret = tuple(randomness.randrange(modulus) for _ in range(dimension))
    matrix = tuple(
        tuple(randomness.randrange(modulus) for _ in range(dimension))
        for _ in range(samples)
    )
    errors = tuple(randomness.choice((-1, 0, 1)) for _ in range(samples))
    vector = tuple(
        (sum(a * s for a, s in zip(row, secret, strict=True)) + error) % modulus
        for row, error in zip(matrix, errors, strict=True)
    )
    emit(
        trace,
        "lwe.keygen",
        "published noisy linear equations A*s + e",
        matrix=matrix,
        public_vector=vector,
        errors=errors,
    )
    return LWEKeyPair(LWEPublicKey(matrix, vector, modulus), secret)


def lwe_encrypt_bit(
    bit: int,
    public_key: LWEPublicKey,
    *,
    seed: int,
    trace: TraceCallback | None = None,
) -> LWECiphertext:
    if bit not in (0, 1):
        raise ValueError("LWE lesson encrypts one bit")
    randomness = Random(seed)
    choices = tuple(randomness.randrange(2) for _ in public_key.matrix)
    if not any(choices):
        choices = (1,) + choices[1:]
    dimension = len(public_key.matrix[0])
    vector = tuple(
        sum(choice * public_key.matrix[row][column] for row, choice in enumerate(choices))
        % public_key.modulus
        for column in range(dimension)
    )
    value = (
        sum(choice * entry for choice, entry in zip(choices, public_key.vector, strict=True))
        + bit * (public_key.modulus // 2)
    ) % public_key.modulus
    emit(
        trace,
        "lwe.encrypt",
        f"encoded bit {bit} near {'q/2' if bit else '0'}",
        choices=choices,
        vector=vector,
        value=value,
    )
    return LWECiphertext(vector, value)


def lwe_decrypt_bit(ciphertext: LWECiphertext, key_pair: LWEKeyPair) -> int:
    modulus = key_pair.public.modulus
    noisy_message = (
        ciphertext.value
        - sum(
            value * secret
            for value, secret in zip(ciphertext.vector, key_pair.secret, strict=True)
        )
    ) % modulus
    distance_zero = min(noisy_message, modulus - noisy_message)
    midpoint = modulus // 2
    distance_one = min(
        (noisy_message - midpoint) % modulus,
        (midpoint - noisy_message) % modulus,
    )
    return int(distance_one < distance_zero)


def additive_share(
    secret: int,
    parties: int,
    modulus: int,
    *,
    seed: int,
) -> tuple[int, ...]:
    if parties < 2 or modulus < 2:
        raise ValueError("need at least two parties and a valid modulus")
    randomness = Random(seed)
    shares = [randomness.randrange(modulus) for _ in range(parties - 1)]
    shares.append((secret - sum(shares)) % modulus)
    return tuple(shares)


def reconstruct_additive(shares: tuple[int, ...], modulus: int) -> int:
    if not shares:
        raise ValueError("at least one share is required")
    return sum(shares) % modulus


def mpc_secure_sum(
    values: tuple[int, ...],
    modulus: int,
    *,
    seed: int,
    trace: TraceCallback | None = None,
) -> int:
    """Demonstrate secure sum by distributing additive shares to all parties."""

    if len(values) < 2:
        raise ValueError("secure sum needs at least two parties")
    rows = tuple(
        additive_share(value, len(values), modulus, seed=seed + index)
        for index, value in enumerate(values)
    )
    column_totals = tuple(sum(row[column] for row in rows) % modulus for column in range(len(values)))
    result = reconstruct_additive(column_totals, modulus)
    emit(
        trace,
        "mpc.secure_sum",
        f"reconstructed aggregate {result} without opening individual shares",
        shares=rows,
        column_totals=column_totals,
        result=result,
    )
    return result


@dataclass(frozen=True, slots=True)
class BB84Result:
    sifted_alice: tuple[int, ...]
    sifted_bob: tuple[int, ...]
    error_rate: float
    intercepted: int


def simulate_bb84(
    qubits: int,
    *,
    seed: int,
    intercept_probability: float = 0.0,
    trace: TraceCallback | None = None,
) -> BB84Result:
    """Simulate BB84 basis sifting and intercept-resend disturbance."""

    if qubits < 1 or not 0 <= intercept_probability <= 1:
        raise ValueError("invalid BB84 simulation parameters")
    randomness = Random(seed)
    alice_bits = [randomness.randrange(2) for _ in range(qubits)]
    alice_bases = [randomness.randrange(2) for _ in range(qubits)]
    bob_bases = [randomness.randrange(2) for _ in range(qubits)]
    received_bits = alice_bits.copy()
    received_bases = alice_bases.copy()
    intercepted = 0
    for index in range(qubits):
        if randomness.random() < intercept_probability:
            intercepted += 1
            eve_basis = randomness.randrange(2)
            eve_bit = (
                alice_bits[index]
                if eve_basis == alice_bases[index]
                else randomness.randrange(2)
            )
            received_bits[index] = eve_bit
            received_bases[index] = eve_basis
    bob_bits = [
        received_bits[index]
        if bob_bases[index] == received_bases[index]
        else randomness.randrange(2)
        for index in range(qubits)
    ]
    matching = [index for index in range(qubits) if alice_bases[index] == bob_bases[index]]
    sifted_alice = tuple(alice_bits[index] for index in matching)
    sifted_bob = tuple(bob_bits[index] for index in matching)
    errors = sum(a != b for a, b in zip(sifted_alice, sifted_bob, strict=True))
    error_rate = errors / len(matching) if matching else 0.0
    emit(
        trace,
        "bb84.complete",
        f"sifted {len(matching)} bits; QBER={error_rate:.3f}",
        sifted=len(matching),
        errors=errors,
        error_rate=error_rate,
        intercepted=intercepted,
    )
    return BB84Result(sifted_alice, sifted_bob, error_rate, intercepted)


__all__ = [
    "BB84Result",
    "LWECiphertext",
    "LWEKeyPair",
    "LWEPublicKey",
    "SchnorrTranscript",
    "additive_share",
    "lwe_decrypt_bit",
    "lwe_encrypt_bit",
    "lwe_keygen",
    "mpc_secure_sum",
    "reconstruct_additive",
    "schnorr_prove",
    "schnorr_public_key",
    "schnorr_verify",
    "simulate_bb84",
    "simulate_schnorr_transcript",
]

