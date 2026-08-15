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
from .feistel import FeistelMessage, ToyFeistelCipher
from .number_theory import extended_gcd, mod_inverse, mod_pow
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
from .trace import TraceCallback, TraceEvent
from ecc_factor import factor_counts, factorize, is_probable_prime

EDUCATIONAL_WARNING = (
    "Educational implementation only; do not use it to protect real data."
)

__all__ = [
    "EDUCATIONAL_WARNING",
    "FeistelMessage",
    "PrimalityResult",
    "RSAEncryptedMessage",
    "RSAKeyPair",
    "RSAPrivateKey",
    "RSAPublicKey",
    "TraceCallback",
    "TraceEvent",
    "ToyFeistelCipher",
    "bytes_to_int",
    "check_primality",
    "extended_gcd",
    "factor_counts",
    "factorize",
    "fermat_test",
    "int_to_bytes",
    "is_probable_prime",
    "jacobi_symbol",
    "miller_rabin_test",
    "mod_inverse",
    "mod_pow",
    "pkcs7_pad",
    "pkcs7_unpad",
    "split_blocks",
    "solovay_strassen_test",
    "trial_primality_test",
    "xor_bytes",
]

__version__ = "0.3.0"
