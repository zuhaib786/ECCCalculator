"""Factorization APIs re-exported under the unified teaching namespace."""

from ecc_factor import (
    FactorizationError,
    FactorizationEvent,
    ProgressCallback,
    factor_counts,
    factorize,
    is_probable_prime,
)

__all__ = [
    "FactorizationError",
    "FactorizationEvent",
    "ProgressCallback",
    "factor_counts",
    "factorize",
    "is_probable_prime",
]

