# Crypto Classroom: 14-Week Undergraduate Course

This outline maps a first course in cryptography to the inspectable teaching
APIs in this repository. It assumes one lecture and one lab/tutorial per week,
with basic Python and discrete mathematics as prerequisites.

## How to read the map

SDK names below are the actual symbols currently present in `src/crypto_lab`.
For example:

```python
from crypto_lab.number_theory import extended_gcd, mod_inverse, mod_pow
```

The CLI includes the original `encode`, `modpow`, `prime`, `factor`,
`rsa-demo`, and `feistel-demo` commands plus course-wide demonstrations for
classical ciphers, AES, security games, discrete logs, key exchange, sharing,
hashes, authentication, signatures, attacks, simplified TLS, and optional
advanced topics. Use `crypto-lab lessons` to list the catalogue and
`crypto-lab lessons SLUG` to inspect one lesson. Every algorithm accepts an
optional `TraceCallback` where provided;
`TraceEvent` and `TraceCollector` turn a run into a notebook or animation
artifact.

All implementations are academic models. They use small parameters,
deliberately expose intermediate state, and must not protect real data.

## Learning outcomes

By the end of the course, a student should be able to:

1. Move correctly between mathematical objects, bytes, encodings, and protocol
   messages, including length and nonce conventions.
2. Explain and implement modular arithmetic, groups, finite fields, hashes,
   symmetric primitives, public-key primitives, and threshold sharing at toy
   sizes.
3. State a security goal (perfect secrecy, IND-CPA/CCA, collision resistance,
   or EUF-CMA), identify its attacker, and interpret a game result.
4. Trace an algorithm, count its work, and connect an implementation step to
   the underlying proof or assumption.
5. Demonstrate nonce reuse, malleability, padding-oracle, timing, subgroup,
   and signature-nonce failures without confusing an attack with full key
   recovery.
6. Assemble a protocol transcript with authentication, key derivation,
   replay protection, and explicit trust assumptions, then document what the
   toy model omits.
7. Know when to stop using a classroom implementation and select a reviewed,
   maintained cryptographic library.

## Weekly schedule

### Week 1 — Representation and classical ciphers

Concepts: alphabets, UTF-8, hex, integers, blocks, XOR, Caesar and affine
maps, substitution, Vigenère, and Hill matrices. Emphasize that encoding is
not encryption and that a key space is not a security proof.

SDK: `crypto_lab.encoding.bytes_to_int`, `int_to_bytes`, `split_blocks`,
`xor_bytes`, `pkcs7_pad`, `pkcs7_unpad`; `crypto_lab.classical.caesar_encrypt`,
`caesar_decrypt`, `affine_encrypt`, `affine_decrypt`, `substitution_encrypt`,
`substitution_decrypt`, `vigenere_encrypt`, `vigenere_decrypt`,
`hill_encrypt`, and `hill_decrypt`.

CLI (available):

```console
crypto-lab encode 'hello' --block-size 4
```

Lab: encrypt a message with two classical schemes, preserve punctuation and
block lengths, and write down the exact inverse map. Exercise: compare the
number of possible keys with the number of possible plaintexts.

### Week 2 — Cryptanalysis and perfect secrecy

Concepts: frequency analysis, known plaintext, Kasiski examination, one-time
pads, key entropy, priors/posteriors, and Shannon perfect secrecy. Show why
reusing a one-time pad gives `C1 XOR C2 = P1 XOR P2`.

SDK: `letter_counts`, `letter_frequency_analysis`, `frequency_analysis`,
`kasiski_examination`, `kasiski_analysis` from `crypto_lab.classical`;
`otp_encrypt`, `otp_decrypt`, `analyze_otp_key_reuse`,
`otp_key_reuse_attack`, `enumerate_perfect_secrecy`,
`perfect_secrecy_experiment`, `shannon_perfect_secrecy`, and
`is_perfectly_secret` from `crypto_lab.perfect_secrecy`.

CLI: inspect the material with `crypto-lab lessons classical-cryptanalysis`
and `crypto-lab lessons perfect-secrecy`.

Lab: recover a Vigenère key-length candidate and break a reused-pad pair.
Exercise: enumerate a tiny encryption experiment and report the posterior
message distribution for every ciphertext.

### Week 3 — Security definitions and randomness

Concepts: Kerckhoffs's principle, computational versus perfect security,
IND-EAV/CPA/CCA, EUF-CMA, advantage, entropy, CSPRNGs, nonces, IVs, salts,
and KDFs. Students should distinguish a secret from a nonce.

SDK: `run_ind_cpa_equality_game`, `DeterministicXorScheme`,
`RandomNonceXorScheme` from `crypto_lab.security_games`;
`shannon_entropy`, `min_entropy`, `insecure_prng_bytes`,
`secure_random_bytes`, `hkdf_extract`, `hkdf_expand`, `hkdf`, and
`derive_password_key` from `crypto_lab.randomness`.

CLI: run `crypto-lab security-game --scheme deterministic` and compare it
with `--scheme randomized`; inspect the randomness lesson with
`crypto-lab lessons randomness`.

Lab: predict which equality adversary wins against deterministic XOR and
estimate its advantage. Compare a seeded PRNG transcript with system
randomness, then assign a unique purpose to each nonce, IV, and salt.

### Week 4 — Symmetric design and AES internals

Concepts: confusion, diffusion, Feistel networks, substitution-permutation
networks, S-boxes, key expansion, SubBytes, ShiftRows, MixColumns, and
AddRoundKey. Connect AES's byte multiplication to `GF(2^8)`.

SDK: `ToyFeistelCipher` and `FeistelMessage` from `crypto_lab.feistel`;
`AES128`, `SBOX`, `INVERSE_SBOX`, `hamming_distance`,
`gf256_add`, `gf256_multiply`, and `gf256_inverse` from
`crypto_lab.symmetric` and `crypto_lab.algebra`.

CLI (available):

```console
crypto-lab feistel-demo 'class lesson' --mode cbc
```

CLI: `crypto-lab aes-demo 00112233445566778899aabbccddeeff -vv`. Lab: trace one AES-128 block and
measure avalanche with `hamming_distance`; compare one-round and full-round
toy Feistel outputs. Do not describe the toy cipher as secure.

### Week 5 — Modes, stream ciphers, and AEAD

Concepts: ECB, CBC, CTR, padding, IV/counter uniqueness, LFSRs, RC4's
historical bias, ChaCha's ARX quarter-round, GCM authentication, and the
confidentiality/integrity distinction.

SDK: `aes_ctr_transform`, `aes_gcm_encrypt`, `aes_gcm_decrypt`, `GCMMessage`
from `crypto_lab.symmetric`; `LFSR`, `rc4_transform`,
`chacha_quarter_round`, `reused_keystream_xor`, and
`sample_rc4_second_byte_bias` from `crypto_lab.stream_ciphers`.

CLI: use `crypto-lab lessons stream-ciphers` and
`crypto-lab lessons modes-of-operation` for the guided experiments.

Lab: show repeated ECB blocks, flip a CBC bit, reuse a CTR keystream, and
compare authenticated versus unauthenticated decryption. Exercise: state
exactly which nonce reuse breaks each construction.

### Week 6 — Hashes, MACs, and attack labs

Concepts: collision/preimage/second-preimage resistance, birthday bounds,
Merkle-Damgård padding, length extension, HMAC, CBC-MAC, encrypt-then-MAC,
padding oracles, timing leakage, and chosen-ciphertext reasoning.

SDK: `toy_hash`, `toy_compress`, `toy_md_padding`,
`birthday_collision_search`, `length_extension_attack`,
`verify_length_extension`, and `toy_prefix_mac` from `crypto_lab.hashing`;
`hmac_digest`, `hmac_sha256`, `verify_hmac`, `cbc_mac`,
`cbc_mac_length_extension_forgery`, `encrypt_then_mac_encrypt`, and
`encrypt_then_mac_decrypt` from `crypto_lab.authentication`;
`leaking_compare`, `recover_with_prefix_oracle`, `cbc_bitflip`, and
`recover_cbc_last_block` from `crypto_lab.attacks`.

CLI: `crypto-lab hash-demo MESSAGE`, `crypto-lab auth-demo MESSAGE`, and
`crypto-lab attack-demo {timing,padding-oracle}`.

Lab: forge the toy prefix MAC with a length guess, produce a CBC-MAC
variable-length forgery, and recover one padded block from an oracle. Relate
each success to the security goal it violates.

### Week 7 — Number theory, primality, and factoring

Concepts: gcd and Bézout coefficients, modular inverses, square-and-multiply,
Euler's theorem, CRT, trial/Fermat/Miller–Rabin/Solovay–Strassen tests,
Carmichael numbers, Pollard rho, ECM, continued fractions, smooth relations,
and work-factor intuition.

SDK: `extended_gcd`, `mod_inverse`, `mod_pow` from
`crypto_lab.number_theory`; `trial_primality_test`, `fermat_test`,
`miller_rabin_test`, `solovay_strassen_test`, `jacobi_symbol`, and
`check_primality` from `crypto_lab.primality`; `factorize`, `factor_counts`,
`is_probable_prime` from `crypto_lab.factorization`.

CLI (available):

```console
crypto-lab modpow 4 13 497
crypto-lab prime 561 --test fermat --base 2
crypto-lab prime 561 --test miller-rabin --base 2
crypto-lab factor 1022117 -m cfrac --cfrac-bound 50 -vv
```

Lab: explain why base 2 fools Fermat on 561 but not Miller–Rabin; capture
factorization traces and compare trial, rho, ECM, and CFRAC on classroom
inputs. The corresponding catalogue entries are available through
`crypto-lab lessons number-theory`, `primality`, and `factoring`.

### Week 8 — Groups, finite fields, and discrete logarithms

Concepts: groups, subgroups, cyclicity, order, primitive roots, finite fields,
AES polynomial arithmetic, BSGS memory/time trade-offs, Pollard-rho DLP, and
Pohlig–Hellman smooth-order decomposition.

SDK: `chinese_remainder_theorem`, `euler_phi`, `multiplicative_order`,
`is_primitive_root`, `primitive_root`, `gf2m_multiply`, `gf2m_inverse` from
`crypto_lab.algebra`; `baby_step_giant_step`, `pollard_rho_discrete_log`,
and `pohlig_hellman` from `crypto_lab.discrete_log`.

CLI: `crypto-lab dlog BASE TARGET MODULUS --algorithm {bsgs,pohlig-hellman,rho}`.

Lab: find a primitive root modulo a small prime, solve one DLP three ways,
and predict the effect of a smooth versus prime subgroup order. Exercise:
verify every returned exponent by direct exponentiation.

### Week 9 — Diffie–Hellman, ElGamal, and ECDH

Concepts: finite-field DH, explicit subgroup validation, man-in-the-middle
limits, randomized ElGamal, elliptic-curve point addition, scalar
multiplication, point at infinity, base/curve orders, and small-subgroup or
invalid-point failures.

SDK: `DHParameters`, `generate_dh_keypair`, `dh_shared_secret`,
`diffie_hellman`, `validate_dh_public_key`; `ElGamalPublicKey`,
`ElGamalPrivateKey`, `ElGamalCiphertext`, `generate_elgamal_keypair`,
`elgamal_encrypt`, `elgamal_decrypt`; `ECDHParameters`,
`generate_ecdh_keypair`, `ecdh_shared_secret`,
`elliptic_curve_diffie_hellman`, and `demonstrate_small_subgroup_attack`
from `crypto_lab.key_exchange`; `Curve`, `Point`, and `INFINITY` from
`crypto_lab.elliptic`.

CLI: `crypto-lab dh-demo`; the ElGamal and ECDH maps are available through
`crypto-lab lessons elgamal` and `crypto-lab lessons ecc-ecdh`.

Lab: derive the same DH/ECDH secret on both sides, encrypt and decrypt one
field element with ElGamal, reject an identity/public key outside the
subgroup, and recover a victim exponent modulo a tiny subgroup order.

### Week 10 — RSA and hybrid encryption

Concepts: RSA key generation, Euler/CRT reasoning, textbook RSA's weaknesses,
padding intuition, KEM/DEM design, and why public-key operations transport a
key rather than a whole file.

SDK: `RSAKeyPair.from_primes`, `RSAPublicKey.encrypt_int`,
`RSAPublicKey.encrypt_bytes`, `RSAPrivateKey.decrypt_int`,
`RSAPrivateKey.decrypt_bytes` from `crypto_lab.rsa`; `hybrid_encrypt` and
`hybrid_decrypt` from `crypto_lab.protocols`.

CLI (available):

```console
crypto-lab rsa-demo 'hello'
```

CLI: `crypto-lab lessons rsa-hybrid`. Lab: reproduce the
classic 61/53 RSA example, demonstrate deterministic equality leakage, and
inspect a hybrid packet. Require students to label the missing production
padding/authentication guarantees.

### Week 11 — Digital signatures and nonce failures

Concepts: signing versus encryption, verification, EUF-CMA intuition, RSA
hash-and-sign, Lamport one-time signatures, DSA/ECDSA equations, and private
key recovery from nonce reuse.

SDK: `rsa_sign`, `rsa_sign_detailed`, `rsa_verify`, `lamport_keygen`,
`lamport_sign`, `lamport_verify`, `DSAParameters`, `dsa_keygen`, `dsa_sign`,
`dsa_verify`, `dsa_recover_private_key_from_reused_nonce`,
`ECDSAParameters`, `ecdsa_keygen`, `ecdsa_sign`, `ecdsa_verify`, and
`ecdsa_recover_private_key_from_reused_nonce` from `crypto_lab.signatures`.

CLI: `crypto-lab signature-demo MESSAGE --scheme {rsa,lamport,dsa,ecdsa}`.

Lab: sign and verify two messages, mutate the message, and recover a toy DSA
or ECDSA private scalar from two signatures sharing a nonce. Exercise:
explain why a valid signature is authentication, not confidentiality.

### Week 12 — Certificates, PKI, and a TLS-style transcript

Concepts: certificate claims, CA signatures, trust roots, transcript binding,
ephemeral key exchange, HKDF, Finished MACs, forward secrecy, replay
protection, and the authentication gap in bare DH.

SDK: `Certificate`, `TeachingCertificateAuthority`,
`HandshakeTranscript`, `simplified_tls_handshake`, `ReplayCache`,
`hybrid_encrypt`, and `hybrid_decrypt` from `crypto_lab.protocols`; combine
with `hmac_sha256`, `hkdf`, `ECDHParameters`, and signature APIs from prior
weeks.

CLI: `crypto-lab tls-demo` and `crypto-lab lessons certificates-pki-tls`.

Lab: annotate a simplified handshake message by message, break it by removing
certificate verification or replay checks, and repair the transcript binding.

### Week 13 — Shamir sharing and protocol composition

Concepts: threshold secrets, random polynomials, Lagrange interpolation,
dealer assumptions, share privacy, and composing sharing with authentication
and recovery policies.

SDK: `Share`, `shamir_split`, `shamir_recover`,
`lagrange_interpolate_zero`, `polynomial_evaluate` from
`crypto_lab.secret_sharing`; `additive_share`, `reconstruct_additive`, and
`mpc_secure_sum` from `crypto_lab.advanced_topics`.

CLI: `crypto-lab shamir-demo SECRET --threshold 3 --shares 5`.

Lab: split a secret into five shares with a threshold of three, recover from
several subsets, and show that fewer shares do not determine the selected
polynomial. Extend the exercise to a signed share or a replay-resistant
recovery request.

### Week 14 — Capstone, review, and optional frontiers

Use the capstone to integrate representations, randomness, AEAD, key
exchange, signatures/certificates, replay checks, and a traceable adversary.
Optional demonstrations are Schnorr transcripts, tiny LWE, additive MPC, and
BB84; they are enrichment, not prerequisites for the core course.

SDK: `schnorr_public_key`, `schnorr_prove`, `schnorr_verify`,
`simulate_schnorr_transcript`, `lwe_keygen`, `lwe_encrypt_bit`,
`lwe_decrypt_bit`, `mpc_secure_sum`, `reconstruct_additive`, and
`simulate_bb84` from `crypto_lab.advanced_topics`.

CLI: `crypto-lab advanced-demo {zk,lwe,mpc,bb84}`; use `--eve 1.0` with
`bb84` to make intercept-resend disturbance visible.

Capstone deliverable: a small, explicitly educational protocol that negotiates
an ephemeral shared secret, derives keys, authenticates a transcript, encrypts
one message with AEAD, rejects replay, and includes one tested attack. Submit
the protocol diagram, threat model, trace output, tests, complexity notes, and
a “what this does not guarantee” section.

## Assessment suggestions

- 15% weekly prediction questions and mathematical derivations.
- 25% short implementation labs, each with a trace and a verification test.
- 20% midterm: number theory, security games, symmetric design, and a written
  attack analysis.
- 10% code review: identify unsafe assumptions in a deliberately flawed toy
  protocol.
- 30% capstone: protocol design (10%), adversary/threat model (8%), tests and
  traces (6%), and limitations/presentation (6%).

Reward a student for correctly identifying an assumption or limitation even
when a toy attack does not recover a complete key. Do not grade production
security claims from these modules.

## Coverage matrix

| Repository module | Course coverage | Representative symbols / role |
| --- | --- | --- |
| `encoding.py` | 1 | `bytes_to_int`, `int_to_bytes`, `split_blocks`, padding/XOR |
| `classical.py` | 1–2 | Caesar, affine, substitution, Vigenère, Hill, Kasiski |
| `perfect_secrecy.py` | 2 | OTP and exact Shannon experiments |
| `security_games.py` | 3, 6, 11 | IND-CPA equality game models |
| `randomness.py` | 3, 5, 9–12 | entropy, PRNG contrast, HKDF, password KDF |
| `feistel.py` | 4–5 | `ToyFeistelCipher`, block modes, traces |
| `symmetric.py` | 4–5 | `AES128`, CTR, GCM, avalanche |
| `stream_ciphers.py` | 5 | LFSR, RC4, ChaCha, keystream reuse |
| `hashing.py` | 6 | toy Merkle–Damgård, birthday, length extension |
| `authentication.py` | 6, 12 | HMAC, CBC-MAC, encrypt-then-MAC |
| `attacks.py` | 5–6, 9, 11 | bit flipping, padding oracle, timing |
| `number_theory.py` | 7–10 | gcd, inverse, modular exponentiation |
| `primality.py` | 7 | trial, Fermat, Miller–Rabin, Solovay–Strassen |
| `factorization.py` | 7 | trial/rho/ECM/CFRAC factorization |
| `algebra.py` | 7–9 | CRT, φ, orders, primitive roots, binary fields |
| `discrete_log.py` | 8–9 | BSGS, Pollard rho DLP, Pohlig–Hellman |
| `elliptic.py` | 9, 11 | `Curve`, `Point`, `INFINITY` arithmetic |
| `key_exchange.py` | 9 | DH, ECDH, ElGamal, subgroup attack |
| `rsa.py` | 10–11 | textbook RSA key and block operations |
| `signatures.py` | 11–12 | RSA, Lamport, DSA, ECDSA and nonce attacks |
| `protocols.py` | 10, 12–14 | hybrid packets, certificates, TLS model, replay cache |
| `secret_sharing.py` | 13–14 | Shamir polynomials and interpolation |
| `advanced_topics.py` | 13–14 | Schnorr, tiny LWE, MPC, BB84 enrichment |
| `trace.py` | 1–14 | `TraceEvent`, `TraceCallback`, `emit` instrumentation |
| `metrics.py` | 1–14 | `TraceCollector` and reusable experiment evidence |
| `lessons.py` | 1–14 | dependency-ordered `Lesson`, `LESSONS`, `LESSON_INDEX` catalogue |
| `cli.py`, `course_cli.py` | 1–14 | concise, verbose, and JSON course command runners |
| `__init__.py`, `__main__.py` | 1–14 | package-level exports and module entry point |

## Academic-only boundary

The repository intentionally favors visible state over constant-time behavior,
large parameter sizes, robust serialization, authenticated key management, and
side-channel resistance. Textbook RSA, textbook ElGamal, toy hashes, toy
Feistel, RC4, raw CTR, and hand-written protocol composition are lesson
material—not deployable cryptography. For any real application, use a reviewed
library and a protocol with current standards, safe defaults, key lifecycle
controls, secure randomness, and independent security review.
