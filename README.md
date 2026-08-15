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
- Number theory: extended Euclid, modular inverses, visible
  square-and-multiply exponentiation, and primality testing.
- Factorization: trial division, Brent's Pollard rho, and stage-one Lenstra ECM.
- Elliptic curves: reusable point addition and scalar multiplication over a
  prime or composite modulus.
- Textbook RSA: key derivation from classroom primes, integer operations, byte
  block encoding, encryption, and decryption.
- Block-cipher concepts: a deliberately nonstandard 64-bit Feistel network,
  round-key derivation, ECB, CBC, IVs, XOR chaining, and padding.
- Structured tracing: SDK calls are quiet by default; the CLI maps `-v` to
  conceptual stages and `-vv` to individual rounds or exponent bits.

## Setup with uv

Python 3.10 or newer and [uv](https://docs.astral.sh/uv/) are required for the
project workflow.

```console
uv sync
uv run crypto-lab --help
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
```

All commands support concise output. Teaching demos and factorization also offer
JSON for notebooks/scripts; verbose traces always go to stderr, so stdout stays
machine-readable.

## Python SDK

The common classroom namespace exposes the main building blocks:

```python
from crypto_lab import RSAKeyPair, factorize, mod_pow

assert mod_pow(4, 13, 497) == 445
assert factorize(8051, method="rho", seed=4) == (83, 97)

keys = RSAKeyPair.from_primes(61, 53, public_exponent=17)
encrypted = keys.public.encrypt_text("Hi")
assert keys.private.decrypt_text(encrypted) == "Hi"
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
│   ├── rsa.py               # Textbook RSA lesson implementation
│   ├── feistel.py           # Toy block cipher plus ECB/CBC
│   └── trace.py             # Structured teaching events
└── ecc_factor/              # Focused factorization and curve package
    ├── factorization.py     # Trial, Pollard rho, ECM
    └── elliptic.py          # Composite-modulus curve arithmetic
tests/                       # SDK and CLI behavior
docs/TEACHING_GUIDE.md       # Suggested classroom sequence
```

## Development

```console
uv sync
uv run python -m unittest discover -s tests -v
uv build
```

See [the teaching guide](docs/TEACHING_GUIDE.md) for lesson sequencing,
discussion prompts, and exercises.

## Acknowledgments

This project was developed with the help of OpenAI's GPT-5.6-Sol. It is intended
purely for academic and teaching purposes.
