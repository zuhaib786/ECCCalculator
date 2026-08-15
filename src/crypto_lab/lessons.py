"""A dependency-ordered catalogue for a first undergraduate crypto course.

The catalogue is deliberately data-only.  Each entry points at the idea that
should be taught, the misconception worth confronting, and a small command or
API example that can be used to begin an exercise.  Implementations in this
repository are inspectable teaching models; they are not a replacement for a
reviewed cryptographic library.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class Lesson:
    """One immutable lesson in the introductory cryptography curriculum."""

    slug: str
    title: str
    unit: str
    summary: str
    cli_examples: tuple[str, ...] = ()
    concepts: tuple[str, ...] = ()
    misconceptions: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Normalize iterable lesson metadata while retaining immutability."""

        for name in ("slug", "title", "unit", "summary"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("cli_examples", "concepts", "misconceptions", "prerequisites"):
            value = getattr(self, name)
            if isinstance(value, str):
                raise TypeError(f"{name} must be an iterable of strings, not a string")
            try:
                normalized = tuple(value)
            except TypeError as error:
                raise TypeError(f"{name} must be an iterable of strings") from error
            if any(not isinstance(item, str) or not item.strip() for item in normalized):
                raise ValueError(f"{name} entries must be non-empty strings")
            object.__setattr__(self, name, normalized)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this lesson."""

        return {
            "slug": self.slug,
            "title": self.title,
            "unit": self.unit,
            "summary": self.summary,
            "cli_examples": list(self.cli_examples),
            "concepts": list(self.concepts),
            "misconceptions": list(self.misconceptions),
            "prerequisites": list(self.prerequisites),
        }


LESSONS: tuple[Lesson, ...] = (
    Lesson(
        "representation",
        "Representations, encodings, and XOR",
        "foundations",
        "Move between text, bytes, integers, blocks, and XOR while keeping lengths and conventions explicit.",
        ("crypto-lab encode 'hello' --block-size 4",),
        ("UTF-8", "hex", "integers", "blocks", "XOR"),
        ("A larger integer is automatically a stronger key.", "Encoding is encryption."),
    ),
    Lesson(
        "classical-ciphers",
        "Classical substitution ciphers",
        "classical cryptography",
        "Use Caesar, affine, substitution, Vigenere, and Hill ciphers to expose key spaces and algebraic structure.",
        ("crypto-lab lessons classical-ciphers",),
        ("Caesar", "affine maps", "substitution", "Vigenere", "Hill matrices", "modular arithmetic"),
        ("Obscurity or a long-looking key makes a substitution cipher secure.", "Punctuation creates cryptographic randomness."),
        ("representation",),
    ),
    Lesson(
        "classical-cryptanalysis",
        "Breaking classical ciphers",
        "classical cryptography",
        "Apply frequency analysis, known-plaintext reasoning, and Kasiski examination to recover repeating-key structure.",
        ("crypto-lab lessons classical-cryptanalysis",),
        ("letter frequencies", "repeated n-grams", "Kasiski distances", "key-length candidates"),
        ("A frequency table uniquely identifies the plaintext.", "A Kasiski candidate proves the key length."),
        ("classical-ciphers",),
    ),
    Lesson(
        "perfect-secrecy",
        "One-time pads and perfect secrecy",
        "foundations",
        "Enumerate tiny message and key spaces to see when ciphertext leaves the posterior message distribution unchanged.",
        ("crypto-lab lessons perfect-secrecy",),
        ("one-time pad", "Shannon secrecy", "prior", "posterior", "key entropy"),
        ("The one-time pad is secure when its key is short or reused.", "Perfect secrecy means the key can be reused."),
        ("representation",),
    ),
    Lesson(
        "security-definitions",
        "What does secure mean?",
        "security foundations",
        "Compare perfect secrecy with computational security and play IND-EAV, IND-CPA, IND-CCA, collision, and forgery games.",
        ("crypto-lab lessons security-definitions",),
        ("Kerckhoffs principle", "security games", "IND-CPA", "IND-CCA", "EUF-CMA", "advantage"),
        ("Security means an attacker can never learn anything.", "A successful implementation is automatically secure."),
        ("perfect-secrecy",),
    ),
    Lesson(
        "randomness",
        "Randomness, entropy, nonces, and salts",
        "security foundations",
        "Measure entropy and contrast unpredictable randomness with seeded or biased generators, then assign every nonce a unique role.",
        ("crypto-lab lessons randomness",),
        ("Shannon entropy", "min-entropy", "CSPRNG", "nonce", "IV", "salt", "KDF"),
        ("A nonce must be secret.", "A random-looking deterministic seed is unpredictable."),
        ("security-definitions",),
    ),
    Lesson(
        "symmetric-design",
        "Symmetric encryption and security goals",
        "symmetric cryptography",
        "Distinguish confusion, diffusion, key spaces, block and stream primitives, and the confidentiality goal of a symmetric scheme.",
        ("crypto-lab feistel-demo 'class lesson' --mode cbc",),
        ("block cipher", "stream cipher", "Feistel network", "confusion", "diffusion", "key space"),
        ("A block cipher encrypts arbitrary-length messages by itself.", "More rounds compensate for a reused nonce."),
        ("security-definitions", "randomness"),
    ),
    Lesson(
        "aes",
        "AES internals",
        "symmetric cryptography",
        "Trace AES-128 key expansion and rounds to connect substitution-permutation design with a standard block cipher.",
        ("crypto-lab lessons aes",),
        ("S-box", "SubBytes", "ShiftRows", "MixColumns", "AddRoundKey", "key schedule"),
        ("AES is secure because its S-box is secret.", "A single AES block can safely encrypt a long file."),
        ("symmetric-design",),
    ),
    Lesson(
        "stream-ciphers",
        "Stream ciphers and ChaCha",
        "symmetric cryptography",
        "Compare LFSRs, RC4, and ChaCha quarter-rounds while observing why keystream uniqueness and bias matter.",
        ("crypto-lab lessons stream-ciphers",),
        ("LFSR", "RC4", "ChaCha", "keystream", "quarter round", "bias"),
        ("A stream cipher key may be reused when plaintexts differ.", "A fast XOR generator is automatically a secure stream cipher."),
        ("symmetric-design", "randomness"),
    ),
    Lesson(
        "modes-of-operation",
        "Modes of operation and AEAD nonces",
        "symmetric cryptography",
        "Build ECB, CBC, CTR, and authenticated-encryption stories to show padding, IVs, counters, malleability, and nonce discipline.",
        ("crypto-lab lessons modes-of-operation",),
        ("ECB", "CBC", "CTR", "padding", "IV", "counter", "AEAD nonce"),
        ("A secure block cipher makes ECB secure for patterns.", "CTR mode authenticates ciphertext."),
        ("aes", "stream-ciphers"),
    ),
    Lesson(
        "hash-functions",
        "Hash functions and birthday bounds",
        "hashes and authentication",
        "Study preimages, second preimages, collisions, the birthday paradox, and Merkle-Damgard-style compression intuition.",
        ("crypto-lab lessons hash-functions",),
        ("SHA-256", "collision resistance", "preimage resistance", "birthday bound", "length extension"),
        ("A hash is reversible encryption.", "A 256-bit hash always needs 256 guesses for a collision."),
        ("representation", "security-definitions"),
    ),
    Lesson(
        "authentication-aead",
        "MACs, HMAC, and authenticated encryption",
        "hashes and authentication",
        "Construct and verify MACs, compare encrypt-then-MAC with unsafe orderings, and make integrity a first-class security goal.",
        ("crypto-lab lessons authentication-aead",),
        ("MAC", "HMAC", "CBC-MAC", "encrypt-then-MAC", "AEAD", "forgery"),
        ("Encryption alone detects tampering.", "A MAC key can be public like a hash function."),
        ("hash-functions", "modes-of-operation"),
    ),
    Lesson(
        "attack-labs",
        "Attacks: nonce reuse, padding oracles, and timing",
        "security foundations",
        "Break intentionally vulnerable constructions to connect abstract definitions with chosen-ciphertext, malleability, and side-channel failures.",
        ("crypto-lab lessons attack-labs",),
        ("nonce reuse", "CBC bit flipping", "padding oracle", "timing leak", "chosen ciphertext"),
        ("An attack requires recovering the whole key.", "A timing difference is harmless if plaintext stays hidden."),
        ("authentication-aead", "security-definitions", "randomness"),
    ),
    Lesson(
        "number-theory",
        "Number theory for public-key cryptography",
        "number theory",
        "Use gcd, extended Euclid, modular inverses, Euler phi, CRT, and modular exponentiation as public-key building blocks.",
        ("crypto-lab modpow 4 13 497",),
        ("gcd", "Bezout coefficients", "modular inverse", "Euler phi", "CRT", "square-and-multiply"),
        ("Modular division always exists.", "A congruence has one integer representative."),
        ("representation",),
    ),
    Lesson(
        "primality",
        "Primality tests and pseudoprimes",
        "number theory",
        "Compare trial division, Fermat, Miller-Rabin, and Solovay-Strassen, including Carmichael numbers and probabilistic error.",
        ("crypto-lab prime 561 --test fermat --base 2", "crypto-lab prime 561 --test miller-rabin --base 2"),
        ("trial division", "Fermat witnesses", "Carmichael number", "Miller-Rabin", "Jacobi symbol"),
        ("Passing one Fermat test proves primality.", "Probable prime means a mathematical proof for every input."),
        ("number-theory",),
    ),
    Lesson(
        "factoring",
        "Factoring and the cost of public-key assumptions",
        "number theory",
        "Factor classroom integers with trial division, Pollard rho, continued fractions, and elliptic-curve methods while tracking work.",
        ("crypto-lab factor 1022117 -m cfrac --cfrac-bound 50 -vv",),
        ("trial division", "Pollard rho", "ECM", "continued fractions", "smooth relations", "complexity"),
        ("A factoring algorithm that works on examples breaks RSA at every size.", "Hardness and impossibility are the same claim."),
        ("primality",),
    ),
    Lesson(
        "groups-and-fields",
        "Groups, cyclic groups, and finite fields",
        "algebra and public-key foundations",
        "Calculate orders, generators, inverses, and finite-field operations so discrete-log protocols have a precise algebraic setting.",
        ("crypto-lab lessons groups-and-fields",),
        ("group", "cyclic group", "subgroup", "order", "generator", "finite field"),
        ("Every nonzero residue modulo any integer forms a field.", "A generator has to generate every integer."),
        ("number-theory",),
    ),
    Lesson(
        "discrete-log",
        "Discrete logarithms",
        "public-key cryptography",
        "Solve small discrete-log instances with baby-step giant-step, Pollard rho, and Pohlig-Hellman to expose the hardness assumption.",
        ("crypto-lab lessons discrete-log",),
        ("baby-step giant-step", "Pollard rho DLP", "Pohlig-Hellman", "generic-group cost"),
        ("A discrete logarithm is an ordinary real logarithm.", "One failed search proves a discrete log does not exist."),
        ("groups-and-fields",),
    ),
    Lesson(
        "diffie-hellman",
        "Diffie-Hellman key exchange",
        "public-key cryptography",
        "Derive a shared secret over a finite cyclic group and examine public parameters, subgroup checks, and the man-in-the-middle gap.",
        ("crypto-lab lessons diffie-hellman",),
        ("DH", "shared secret", "key exchange", "subgroup validation", "man-in-the-middle"),
        ("Diffie-Hellman authenticates the participants by itself.", "The public exponent must be hidden."),
        ("discrete-log",),
    ),
    Lesson(
        "elgamal",
        "ElGamal encryption",
        "public-key cryptography",
        "Turn Diffie-Hellman into randomized public-key encryption and inspect why fresh randomness prevents deterministic equality leakage.",
        ("crypto-lab lessons elgamal",),
        ("ElGamal", "randomized encryption", "semantic security intuition", "malleability"),
        ("ElGamal ciphertexts are deterministic.", "Public-key encryption automatically authenticates messages."),
        ("diffie-hellman", "randomness"),
    ),
    Lesson(
        "ecc-ecdh",
        "Elliptic curves and ECDH",
        "public-key cryptography",
        "Add and multiply points on an elliptic curve, then map the Diffie-Hellman idea to a compact group with validation rules.",
        ("crypto-lab lessons ecc-ecdh",),
        ("elliptic curve", "point addition", "point at infinity", "scalar multiplication", "ECDH", "invalid curve"),
        ("Elliptic curves are ellipses in the plane.", "A smaller key has the same security without parameter validation."),
        ("groups-and-fields", "discrete-log"),
    ),
    Lesson(
        "rsa-hybrid",
        "RSA and hybrid encryption",
        "public-key cryptography",
        "Derive textbook RSA from factoring and modular inverses, then combine public-key key transport with symmetric data encryption.",
        ("crypto-lab rsa-demo 'hello'",),
        ("RSA", "Euler theorem", "key generation", "OAEP intuition", "KEM/DEM", "hybrid encryption"),
        ("Textbook RSA safely encrypts arbitrary messages.", "Public-key encryption should process a whole file directly."),
        ("number-theory", "randomness", "modes-of-operation"),
    ),
    Lesson(
        "signatures",
        "Digital signatures and nonce failures",
        "authentication",
        "Sign and verify messages with RSA and discrete-log ideas, then recover a secret from a deliberately reused ECDSA nonce.",
        ("crypto-lab lessons signatures",),
        ("signature", "EUF-CMA", "RSA-PSS intuition", "DSA", "ECDSA", "nonce reuse"),
        ("A signature encrypts a message for the signer.", "A random nonce may safely be reused in ECDSA."),
        ("rsa-hybrid", "discrete-log", "randomness", "security-definitions"),
    ),
    Lesson(
        "certificates-pki-tls",
        "Certificates, PKI, and a TLS handshake",
        "protocols",
        "Assemble a certificate chain and a simplified TLS transcript to connect signatures, key exchange, AEAD, replay protection, and trust.",
        ("crypto-lab lessons certificates-pki-tls",),
        ("certificate", "CA", "PKI", "TLS", "transcript", "forward secrecy", "replay"),
        ("A certificate encrypts the server's private key.", "TLS is one encryption operation rather than a protocol transcript."),
        ("signatures", "ecc-ecdh", "authentication-aead", "rsa-hybrid"),
    ),
    Lesson(
        "secret-sharing",
        "Shamir secret sharing",
        "protocols",
        "Split a secret into polynomial shares and reconstruct it with Lagrange interpolation, including the threshold security intuition.",
        ("crypto-lab lessons secret-sharing",),
        ("threshold", "polynomial interpolation", "Lagrange basis", "dealer", "share privacy"),
        ("Any single share is the secret.", "More shares always reveal more than the threshold polynomial permits."),
        ("groups-and-fields",),
    ),
    Lesson(
        "zero-knowledge",
        "Optional advanced topic: zero-knowledge proofs",
        "advanced topics",
        "Optional advanced material: use a toy proof transcript to separate knowledge, soundness, completeness, and zero knowledge. Educational only; not a production proof system.",
        ("crypto-lab lessons zero-knowledge",),
        ("interactive proof", "completeness", "soundness", "zero knowledge", "simulator", "Fiat-Shamir intuition"),
        ("Zero knowledge means the verifier learns nothing at all, including truth.", "A convincing transcript automatically proves a real-world identity."),
        ("security-definitions", "groups-and-fields"),
    ),
    Lesson(
        "secure-mpc",
        "Optional advanced topic: secure multiparty computation",
        "advanced topics",
        "Optional advanced material: model parties, inputs, leakage, and a tiny secret-sharing computation. Educational only; real MPC needs a formal threat model.",
        ("crypto-lab lessons secure-mpc",),
        ("MPC", "semi-honest adversary", "malicious adversary", "garbled circuit intuition", "input privacy"),
        ("MPC means data is never communicated.", "A protocol is secure without specifying corrupted parties."),
        ("secret-sharing", "security-definitions"),
    ),
    Lesson(
        "post-quantum",
        "Optional advanced topic: post-quantum cryptography",
        "advanced topics",
        "Optional advanced material: compare the assumptions behind lattice, code, hash, and isogeny proposals and why migration matters. Educational only; use standardized libraries in practice.",
        ("crypto-lab lessons post-quantum",),
        ("quantum threat", "lattice", "LWE", "hash-based signature", "hybrid migration", "standardization"),
        ("Post-quantum means quantum computers already break every scheme.", "A toy LWE sample is a deployed cryptosystem."),
        ("discrete-log", "rsa-hybrid", "security-definitions"),
    ),
    Lesson(
        "bb84",
        "Optional advanced topic: BB84 and quantum key distribution",
        "advanced topics",
        "Optional advanced material: simulate BB84 bases, measurement disturbance, sifting, and error estimation. Educational only; this is not a quantum network implementation.",
        ("crypto-lab lessons bb84",),
        ("BB84", "basis", "measurement", "no-cloning", "sifting", "quantum bit error rate"),
        ("QKD sends a secret message without authentication.", "A quantum channel removes the need for classical cryptography."),
        ("randomness", "security-definitions"),
    ),
)


LESSON_INDEX: Mapping[str, Lesson] = MappingProxyType({lesson.slug: lesson for lesson in LESSONS})


def list_lessons(*, unit: str | None = None) -> tuple[Lesson, ...]:
    """Return lessons in curriculum order, optionally restricted to a unit."""

    if unit is None:
        return LESSONS
    if not isinstance(unit, str) or not unit.strip():
        raise ValueError("unit must be a non-empty string or None")
    return tuple(lesson for lesson in LESSONS if lesson.unit == unit)


def get_lesson(slug: str) -> Lesson:
    """Return a lesson by slug, raising ``KeyError`` for an unknown slug."""

    if not isinstance(slug, str):
        raise TypeError("slug must be a string")
    try:
        return LESSON_INDEX[slug]
    except KeyError as error:
        raise KeyError(f"unknown lesson slug: {slug!r}") from error


def _materialize_lessons(lessons: Iterable[Lesson]) -> tuple[Lesson, ...]:
    result = tuple(lessons)
    if any(not isinstance(lesson, Lesson) for lesson in result):
        raise TypeError("lessons must contain Lesson instances")
    return result


def validate_prerequisites(lessons: Iterable[Lesson] = LESSONS) -> bool:
    """Validate unique slugs, references, and acyclicity of a lesson graph.

    The function returns ``True`` for a valid graph and raises ``ValueError``
    with an actionable message for duplicate, missing, self, or cyclic edges.
    """

    entries = _materialize_lessons(lessons)
    by_slug: dict[str, Lesson] = {}
    for lesson in entries:
        if lesson.slug in by_slug:
            raise ValueError(f"duplicate lesson slug: {lesson.slug!r}")
        by_slug[lesson.slug] = lesson
    for lesson in entries:
        if lesson.slug in lesson.prerequisites:
            raise ValueError(f"lesson {lesson.slug!r} cannot require itself")
        missing = [slug for slug in lesson.prerequisites if slug not in by_slug]
        if missing:
            raise ValueError(f"lesson {lesson.slug!r} has unknown prerequisites: {missing!r}")

    state: dict[str, int] = {}

    def visit(slug: str) -> None:
        current = state.get(slug, 0)
        if current == 1:
            raise ValueError(f"cyclic lesson prerequisite involving {slug!r}")
        if current == 2:
            return
        state[slug] = 1
        for prerequisite in by_slug[slug].prerequisites:
            visit(prerequisite)
        state[slug] = 2

    for lesson in entries:
        visit(lesson.slug)
    return True


def topological_order(lessons: Iterable[Lesson] = LESSONS) -> tuple[Lesson, ...]:
    """Return a stable prerequisite-respecting order of ``lessons``."""

    entries = _materialize_lessons(lessons)
    validate_prerequisites(entries)
    position = {lesson.slug: index for index, lesson in enumerate(entries)}
    by_slug = {lesson.slug: lesson for lesson in entries}
    if all(
        position[prerequisite] < position[lesson.slug]
        for lesson in entries
        for prerequisite in lesson.prerequisites
    ):
        # Preserve the authorial order when it is already a valid linear
        # extension; this keeps a hand-written syllabus readable.
        return entries
    remaining = {lesson.slug: set(lesson.prerequisites) for lesson in entries}
    ordered: list[Lesson] = []
    while remaining:
        ready = [slug for slug, prerequisites in remaining.items() if not prerequisites]
        if not ready:  # Defensive: validation already detects cycles.
            raise ValueError("lesson prerequisite graph is cyclic")
        for slug in sorted(ready, key=position.__getitem__):
            ordered.append(by_slug[slug])
            del remaining[slug]
        for prerequisites in remaining.values():
            prerequisites.difference_update(ready)
    return tuple(ordered)


def topological_lessons(lessons: Iterable[Lesson] = LESSONS) -> tuple[Lesson, ...]:
    """Alias for :func:`topological_order`."""

    return topological_order(lessons)


def catalog_as_dict(lessons: Iterable[Lesson] = LESSONS) -> list[dict[str, Any]]:
    """Return a JSON-serializable list of lesson dictionaries."""

    entries = _materialize_lessons(lessons)
    validate_prerequisites(entries)
    return [lesson.as_dict() for lesson in entries]


def as_dict(lessons: Iterable[Lesson] = LESSONS) -> list[dict[str, Any]]:
    """Short alias for :func:`catalog_as_dict`."""

    return catalog_as_dict(lessons)


__all__ = [
    "LESSONS",
    "LESSON_INDEX",
    "Lesson",
    "as_dict",
    "catalog_as_dict",
    "get_lesson",
    "list_lessons",
    "topological_lessons",
    "topological_order",
    "validate_prerequisites",
]
