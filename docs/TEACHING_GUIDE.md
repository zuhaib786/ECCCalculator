# Teaching guide

This library is designed for observation and modification. A useful classroom
pattern is: predict a transformation, run it without tracing, rerun with `-v` or
`-vv`, and then change one input while holding the others fixed.

## 1. Representation before encryption

Start with:

```console
uv run crypto-lab encode "Hi 🔐" --block-size 2
```

Discuss why characters, encoded bytes, hexadecimal, integers, and blocks are
different views of the same input. Ask students what is lost if leading zero
bytes are converted to an integer without retaining a length.

SDK topics: `bytes_to_int`, `int_to_bytes`, `split_blocks`, `xor_bytes`,
`pkcs7_pad`, and `pkcs7_unpad`.

## 2. Modular arithmetic

Use extended Euclid to connect gcds with inverses, then expose binary
square-and-multiply:

```console
uv run crypto-lab modpow 4 13 497 -vv
```

Exercises:

1. Verify the Bézout identity returned by `extended_gcd`.
2. Identify exactly which exponent bits trigger multiplication.
3. Compare the number of steps with naive repeated multiplication.

## 3. Probable primes and witnesses

Contrast an exact divisor search with three probable-prime tests:

```console
uv run crypto-lab prime 561 --test trial -vv
uv run crypto-lab prime 561 --test fermat --base 2 -vv
uv run crypto-lab prime 561 --test miller-rabin --base 2 -vv
uv run crypto-lab prime 15 --test solovay-strassen --base 2 -vv
```

The Carmichael number `561` is the key misconception test: base-2 Fermat calls
it probably prime, while base-2 Miller-Rabin produces a compositeness witness.
Discuss the difference between “no witness found” and a proof of primality.

SDK topics: `trial_primality_test`, `fermat_test`, `miller_rabin_test`,
`solovay_strassen_test`, `jacobi_symbol`, and `check_primality`.

## 4. Factors, continued fractions, and elliptic curves

Compare trial division and Pollard rho on a modest semiprime, build a
congruence of squares with CFRAC, then use ECM:

```console
uv run crypto-lab factor 1000036000099 -m trial -vv
uv run crypto-lab factor 1000036000099 -m rho --seed 7 -vv
uv run crypto-lab factor 1022117 -m cfrac --cfrac-bound 50 -vv
uv run crypto-lab factor 10097063 -m ecm --seed 11 --ecm-bound 200 -vv
```

For CFRAC, follow `convergent → smooth residue → exponent parity → dependency →
gcd`. The parity-vector dependency makes a product of residues into a square,
producing `x² = y² (mod n)` and the candidates `gcd(x-y,n)` and `gcd(x+y,n)`.

The important ECM observation is that arithmetic modulo a composite may request
an inverse that does not exist. `NonInvertibleError.divisor` exposes the gcd,
turning a failed curve operation into a factor.

Render the trace-backed animation for a 42-digit example:

```console
uv sync --extra animation
uv run --extra animation manim -pql \
  examples/manim_ecm_factorization.py EcmFactorizationScene
```

See `docs/MANIM_ECM.md` for why the state-space circle is schematic and how each
factorization event maps to an animation.

## 5. Textbook RSA as a composition

Use the small classic parameters first:

```console
uv run crypto-lab rsa-demo "Hi" --p 61 --q 53 -e 17 -v
```

Follow the chain `p,q → n,phi(n) → e,d → bytes → message integers → modular
powers → bytes`. Then use `-vv` to reveal that RSA encryption and decryption are
applications of the earlier square-and-multiply lesson.

Security discussion: this implementation has no OAEP, authentication, side-
channel defenses, secure prime generation, or safe key handling. Deterministic
textbook RSA leaks equality and is not a deployable encryption scheme.

## 6. Block-cipher structure and modes

The `ToyFeistelCipher` is intentionally not a standard cipher. Its round
function only demonstrates diffusion-like mixing; Feistel structure makes the
whole network reversible even though the round function is not inverted.

Compare repeated blocks:

```console
uv run crypto-lab feistel-demo "AAAAAAAAAAAAAAAA" --mode ecb
uv run crypto-lab feistel-demo "AAAAAAAAAAAAAAAA" --mode cbc
```

Exercises:

1. Confirm equal ECB plaintext blocks produce equal ciphertext blocks.
2. Trace how each CBC ciphertext block becomes the next chaining input.
3. Change one plaintext bit and count changed ciphertext bits.
4. Corrupt the last ciphertext byte and observe padding validation.

Security discussion: CBC requires an unpredictable IV and does not itself
authenticate ciphertext. The toy network has not been cryptanalyzed and must
never replace AES or an authenticated construction such as AES-GCM.

## Extending the course

Good next modules are classical substitution/transposition ciphers, finite
fields, Diffie–Hellman, ElGamal, hashes/Merkle–Damgård structure, MACs, and
signatures. Each should follow the same contract used here:

- a quiet, typed SDK;
- structured opt-in traces instead of `print` inside algorithms;
- a concise CLI with `-v`, `-vv`, and JSON where useful;
- round-trip, known-answer, invalid-input, and misconception-focused tests;
- an explicit boundary between a teaching construction and secure production
  cryptography.
