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

## 3. Factors and elliptic curves

Compare trial division and Pollard rho on a modest semiprime, then use ECM:

```console
uv run crypto-lab factor 1000036000099 -m trial -vv
uv run crypto-lab factor 1000036000099 -m rho --seed 7 -vv
uv run crypto-lab factor 10097063 -m ecm --seed 11 --ecm-bound 200 -vv
```

The important ECM observation is that arithmetic modulo a composite may request
an inverse that does not exist. `NonInvertibleError.divisor` exposes the gcd,
turning a failed curve operation into a factor.

## 4. Textbook RSA as a composition

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

## 5. Block-cipher structure and modes

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
