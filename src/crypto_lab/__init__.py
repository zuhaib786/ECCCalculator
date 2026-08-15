"""Educational cryptography building blocks.

This package favors readable, inspectable algorithms over security or speed.
Nothing in it should protect real data.
"""

from .encoding import (
    bytes_to_int,
    int_to_bytes,
    pkcs7_pad,
    pkcs7_unpad,
    split_blocks,
    xor_bytes,
)
from .advanced_topics import (
    BB84Result,
    LWEKeyPair,
    SchnorrTranscript,
    lwe_decrypt_bit,
    lwe_encrypt_bit,
    lwe_keygen,
    mpc_secure_sum,
    schnorr_prove,
    schnorr_verify,
    simulate_bb84,
)
from .algebra import (
    chinese_remainder_theorem,
    euler_phi,
    gf256_inverse,
    gf256_multiply,
    multiplicative_order,
    primitive_root,
)
from .attacks import cbc_bitflip, recover_cbc_last_block, recover_with_prefix_oracle
from .authentication import EncryptThenMAC, hmac_sha256, verify_hmac
from .classical import (
    affine_decrypt,
    affine_encrypt,
    caesar_decrypt,
    caesar_encrypt,
    hill_decrypt,
    hill_encrypt,
    kasiski_examination,
    substitution_decrypt,
    substitution_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)
from .discrete_log import (
    baby_step_giant_step,
    pohlig_hellman,
    pollard_rho_discrete_log,
)
from .elliptic import Curve, INFINITY, NonInvertibleError, Point
from .feistel import BlockMode, FeistelMessage, ToyFeistelCipher
from .hashing import (
    birthday_collision_search,
    length_extension_attack,
    toy_hash,
    verify_length_extension,
)
from .key_exchange import (
    DHParameters,
    ECDHParameters,
    ElGamalKeyPair,
    diffie_hellman,
    ecdh_shared_secret,
    elgamal_decrypt,
    elgamal_encrypt,
)
from .lessons import LESSONS, Lesson, get_lesson, list_lessons
from .metrics import TraceCollector
from .number_theory import extended_gcd, mod_inverse, mod_pow
from .perfect_secrecy import (
    analyze_otp_key_reuse,
    enumerate_perfect_secrecy,
    otp_decrypt,
    otp_encrypt,
)
from .primality import (
    PrimalityResult,
    check_primality,
    fermat_test,
    jacobi_symbol,
    miller_rabin_test,
    solovay_strassen_test,
    trial_primality_test,
)
from .rsa import RSAEncryptedMessage, RSAKeyPair, RSAPrivateKey, RSAPublicKey
from .protocols import (
    ReplayCache,
    TeachingCertificateAuthority,
    hybrid_decrypt,
    hybrid_encrypt,
    simplified_tls_handshake,
)
from .randomness import (
    derive_password_key,
    hkdf,
    insecure_prng_bytes,
    min_entropy,
    secure_random_bytes,
    shannon_entropy,
)
from .secret_sharing import Share, shamir_recover, shamir_split
from .security_games import (
    DeterministicXorScheme,
    RandomNonceXorScheme,
    run_ind_cpa_equality_game,
)
from .signatures import (
    DSAKeyPair,
    ECDSAKeyPair,
    LamportKeyPair,
    dsa_sign,
    dsa_verify,
    ecdsa_sign,
    ecdsa_verify,
    lamport_sign,
    lamport_verify,
    rsa_sign,
    rsa_verify,
)
from .stream_ciphers import LFSR, chacha_quarter_round, rc4_transform
from .symmetric import (
    AES128,
    GCMMessage,
    aes_ctr_transform,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hamming_distance,
)
from .trace import TraceCallback, TraceEvent
from ecc_factor import factor_counts, factorize, is_probable_prime

EDUCATIONAL_WARNING = (
    "Educational implementation only; do not use it to protect real data."
)

__all__ = [
    "EDUCATIONAL_WARNING",
    "AES128",
    "BB84Result",
    "BlockMode",
    "Curve",
    "DHParameters",
    "DSAKeyPair",
    "DeterministicXorScheme",
    "ECDHParameters",
    "ECDSAKeyPair",
    "ElGamalKeyPair",
    "EncryptThenMAC",
    "FeistelMessage",
    "GCMMessage",
    "INFINITY",
    "LESSONS",
    "LFSR",
    "LWEKeyPair",
    "LamportKeyPair",
    "Lesson",
    "NonInvertibleError",
    "Point",
    "PrimalityResult",
    "RandomNonceXorScheme",
    "ReplayCache",
    "RSAEncryptedMessage",
    "RSAKeyPair",
    "RSAPrivateKey",
    "RSAPublicKey",
    "SchnorrTranscript",
    "TraceCallback",
    "TraceCollector",
    "TraceEvent",
    "TeachingCertificateAuthority",
    "ToyFeistelCipher",
    "affine_decrypt",
    "affine_encrypt",
    "aes_ctr_transform",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "analyze_otp_key_reuse",
    "baby_step_giant_step",
    "birthday_collision_search",
    "bytes_to_int",
    "caesar_decrypt",
    "caesar_encrypt",
    "cbc_bitflip",
    "chacha_quarter_round",
    "check_primality",
    "chinese_remainder_theorem",
    "derive_password_key",
    "diffie_hellman",
    "dsa_sign",
    "dsa_verify",
    "ecdh_shared_secret",
    "ecdsa_sign",
    "ecdsa_verify",
    "elgamal_decrypt",
    "elgamal_encrypt",
    "enumerate_perfect_secrecy",
    "euler_phi",
    "extended_gcd",
    "factor_counts",
    "factorize",
    "fermat_test",
    "get_lesson",
    "gf256_inverse",
    "gf256_multiply",
    "hamming_distance",
    "hill_decrypt",
    "hill_encrypt",
    "hkdf",
    "hmac_sha256",
    "hybrid_decrypt",
    "hybrid_encrypt",
    "insecure_prng_bytes",
    "int_to_bytes",
    "is_probable_prime",
    "jacobi_symbol",
    "kasiski_examination",
    "lamport_sign",
    "lamport_verify",
    "length_extension_attack",
    "list_lessons",
    "lwe_decrypt_bit",
    "lwe_encrypt_bit",
    "lwe_keygen",
    "miller_rabin_test",
    "min_entropy",
    "mod_inverse",
    "mod_pow",
    "mpc_secure_sum",
    "multiplicative_order",
    "otp_decrypt",
    "otp_encrypt",
    "pkcs7_pad",
    "pkcs7_unpad",
    "pohlig_hellman",
    "pollard_rho_discrete_log",
    "primitive_root",
    "rc4_transform",
    "recover_cbc_last_block",
    "recover_with_prefix_oracle",
    "rsa_sign",
    "rsa_verify",
    "run_ind_cpa_equality_game",
    "schnorr_prove",
    "schnorr_verify",
    "secure_random_bytes",
    "shamir_recover",
    "shamir_split",
    "shannon_entropy",
    "Share",
    "simplified_tls_handshake",
    "simulate_bb84",
    "split_blocks",
    "solovay_strassen_test",
    "substitution_decrypt",
    "substitution_encrypt",
    "toy_hash",
    "trial_primality_test",
    "verify_hmac",
    "verify_length_extension",
    "vigenere_decrypt",
    "vigenere_encrypt",
    "xor_bytes",
]

__version__ = "0.4.0"
