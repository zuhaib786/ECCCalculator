# Crypto Classroom

Crypto Classroom is a dependency-free Python teaching SDK and CLI for exploring
the mechanics behind an introductory cryptography course. The implementations
favor readable steps and structured traces over speed or production hardening.

> **Educational use only.** Textbook RSA and the toy Feistel network in this
> project must not be used to protect real data. Use a maintained cryptography
> library and reviewed protocols in real systems.

## What is included

- Encoding: text, bytes, hexadecimal, integers, fixed-size blocks, XOR, and
  PKCS#7-style padding.
- Number theory: extended Euclid, modular inverses, and visible
  square-and-multiply exponentiation.
- Primality: exact trial testing plus Fermat, Miller-Rabin, Solovay-Strassen,
  Jacobi symbols, witnesses, and reproducible probabilistic rounds.
- Factorization: trial division, Brent's Pollard rho, CFRAC continued-fraction
  relations, and stage-one Lenstra ECM.
- Elliptic curves: reusable point addition and scalar multiplication over a
  prime or composite modulus.
- Textbook RSA: key derivation from classroom primes, integer operations, byte
  block encoding, encryption, and decryption.
- Block-cipher concepts: a deliberately nonstandard 64-bit Feistel network,
  round-key derivation, ECB, CBC, IVs, XOR chaining, and padding.
- Classical cryptography: Caesar, affine, substitution, Vigenere, Hill,
  frequency/Kasiski analysis, one-time pads, and exact perfect-secrecy models.
- Symmetric cryptography: inspectable AES-128, CTR, AES-GCM, LFSRs, historical
  RC4, ChaCha quarter rounds, avalanche measurements, and nonce-reuse labs.
- Security foundations: entropy, predictable versus secure randomness, HKDF,
  password KDFs, and runnable IND-CPA equality games.
- Public-key foundations: CRT, finite-field arithmetic, groups, primitive
  roots, three discrete-log algorithms, DH, ECDH, ElGamal, and subgroup labs.
- Hashes and authentication: Merkle-Damgard structure, birthday collisions,
  length extension, HMAC, CBC-MAC, encrypt-then-MAC, and AEAD.
- Signatures and protocols: RSA, Lamport, DSA, ECDSA, nonce-reuse recovery,
  hybrid encryption, teaching certificates, TLS-style transcripts, replay
  protection, and Shamir secret sharing.
- Attack and enrichment labs: timing leakage, CBC bit flipping, padding
  oracles, Schnorr identification, tiny LWE, additive MPC, and BB84.
- A dependency-ordered 29-lesson catalogue and a complete 14-week course map.
- Structured tracing: SDK calls are quiet by default; the CLI maps `-v` to
  conceptual stages and `-vv` to individual rounds or exponent bits.

## Setup with uv

Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are required for the
project workflow.

```console
uv sync
uv run crypto-lab --help
uv run crypto-lab lessons
```

There are no runtime dependencies. `uv.lock` makes the development environment
reproducible.

## Teaching CLI

Inspect how text becomes bytes, integers, and blocks:

```console
uv run crypto-lab encode "Hello" --block-size 2
```

Show square-and-multiply. `-vv` prints each exponent-bit decision to stderr:

```console
uv run crypto-lab modpow 4 13 497 -vv
```

Compare primality tests, including a classic Fermat-test trap:

```console
uv run crypto-lab prime 561 --test fermat --base 2 -vv
uv run crypto-lab prime 561 --test miller-rabin --base 2 -vv
uv run crypto-lab prime 2305843009213693951 --test miller-rabin --json
```

Run a complete textbook RSA round trip:

```console
uv run crypto-lab rsa-demo "Hi" --p 61 --q 53 -e 17
uv run crypto-lab rsa-demo "cryptography" -v
```

Run the toy Feistel network in CBC or ECB mode. Repeat `-v` to inspect rounds:

```console
uv run crypto-lab feistel-demo "repeated repeated" --mode cbc -v
uv run crypto-lab feistel-demo "AAAAAAAAAAAAAAAA" --mode ecb -vv
```

Factorization is available through the unified CLI and the focused legacy
command:

```console
uv run crypto-lab factor 1000036000099 --method rho --seed 7 -v
uv run ecc-factor 10097063 --method ecm --seed 11
uv run ecc-factor 1022117 --method cfrac --cfrac-bound 50 -vv
```

The rest of the course uses the same quiet/verbose/JSON contract:

```console
uv run crypto-lab classical vigenere ATTACKATDAWN --key LEMON -v
uv run crypto-lab aes-demo 00112233445566778899aabbccddeeff -vv
uv run crypto-lab security-game --scheme deterministic --trials 1000 --json
uv run crypto-lab dlog 5 8 23 --algorithm pohlig-hellman -v
uv run crypto-lab dh-demo -v
uv run crypto-lab shamir-demo 42 --threshold 3 --shares 5
uv run crypto-lab hash-demo message --extension '&admin=true' -v
uv run crypto-lab signature-demo message --scheme ecdsa
uv run crypto-lab attack-demo padding-oracle -v
uv run crypto-lab tls-demo -v
uv run crypto-lab advanced-demo bb84 --eve 1.0 --json
```

## Manim ECM animation

The repository includes a Manim scene driven by a real, deterministic SDK trace.
It factors the 42-digit number
`171672454111613454817272489449327062678543` as `1009 * (2^127 - 1)`.
The scene animates curve selection, every stage-one prime-power multiplication,
the failed modular inverse, the gcd leak, and the final factorization.

Install only the optional animation dependencies and render a quick preview:

```console
uv sync --extra animation
uv run --extra animation manim checkhealth
uv run --extra animation manim -pql \
  examples/manim_ecm_factorization.py EcmFactorizationScene
```

Use `-pqh` instead of `-pql` for a high-quality render. Manim may require Cairo,
Pango, or related system libraries depending on the operating system. See the
[Manim ECM example guide](docs/MANIM_ECM.md) for the event mapping and extension
ideas.

All commands support concise output. Teaching demos and factorization also offer
JSON for notebooks/scripts; verbose traces always go to stderr, so stdout stays
machine-readable.

## Python SDK

The common classroom namespace exposes the main building blocks:

```python
from crypto_lab import AES128, RSAKeyPair, factorize, mod_pow, shamir_recover, shamir_split

assert mod_pow(4, 13, 497) == 445
assert factorize(8051, method="rho", seed=4) == (83, 97)

keys = RSAKeyPair.from_primes(61, 53, public_exponent=17)
encrypted = keys.public.encrypt_text("Hi")
assert keys.private.decrypt_text(encrypted) == "Hi"

aes = AES128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
assert aes.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == \
    "69c4e0d86a7b0430d8cdb78070b4c55a"

shares = shamir_split(42, threshold=3, share_count=5, prime=257, seed=9)
assert shamir_recover(shares[:3], 257) == 42
```

Library APIs never print. To build a lecture visualization or notebook, collect
structured events:

```python
from crypto_lab import TraceEvent, mod_pow

def show(event: TraceEvent) -> None:
    if event.level <= 2:
        print(event.code, event.message, event.data)

mod_pow(4, 13, 497, trace=show)
```

The block-cipher model makes mode behavior easy to compare:

```python
from crypto_lab import ToyFeistelCipher

cipher = ToyFeistelCipher(0x133457799BBCDFF1)
ecb = cipher.encrypt(b"A" * 16, mode="ecb")
cbc = cipher.encrypt(b"A" * 16, mode="cbc", iv=bytes(8))

assert ecb.ciphertext[:8] == ecb.ciphertext[8:16]
assert cbc.ciphertext[:8] != cbc.ciphertext[8:16]
assert cipher.decrypt(cbc) == b"A" * 16
```

## Repository layout

```text
src/
├── crypto_lab/              # Unified educational SDK and CLI
│   ├── encoding.py          # Representation, blocks, XOR, padding
│   ├── number_theory.py     # Euclid and square-and-multiply
│   ├── primality.py         # Fermat, Miller-Rabin, Solovay-Strassen
│   ├── rsa.py               # Textbook RSA lesson implementation
│   ├── feistel.py           # Toy block cipher plus ECB/CBC
│   ├── classical.py         # Classical ciphers and cryptanalysis
│   ├── symmetric.py         # AES-128, CTR, and GCM
│   ├── hashing.py           # Toy hashes, collisions, extension attacks
│   ├── authentication.py    # HMAC, CBC-MAC, encrypt-then-MAC
│   ├── key_exchange.py      # DH, ECDH, ElGamal, subgroup lessons
│   ├── signatures.py        # RSA, Lamport, DSA, and ECDSA
│   ├── protocols.py         # Hybrid encryption, certificates, TLS model
│   ├── lessons.py           # Dependency-ordered course catalogue
│   └── trace.py             # Structured teaching events
└── ecc_factor/              # Focused factorization and curve package
    ├── factorization.py     # Trial, Pollard rho, CFRAC, ECM
    └── elliptic.py          # Composite-modulus curve arithmetic
tests/                       # SDK and CLI behavior
docs/TEACHING_GUIDE.md       # Suggested classroom sequence
docs/COURSE_OUTLINE.md       # Complete 14-week undergraduate course
examples/                    # Trace-backed runnable demonstrations
```

## Development

```console
uv sync
uv run python -m unittest discover -s tests -v
uv build
```

See [the 14-week course outline](docs/COURSE_OUTLINE.md) and
[teaching guide](docs/TEACHING_GUIDE.md) for sequencing, outcomes, labs,
discussion prompts, and assessments.

## Acknowledgments

This project was developed with the help of OpenAI's GPT-5.6-Sol. It is intended
purely for academic and teaching purposes.
