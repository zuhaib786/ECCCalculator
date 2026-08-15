"""Public SDK for integer factorization."""

from .events import FactorizationEvent, ProgressCallback
from .elliptic import Curve, INFINITY, NonInvertibleError, Point
from .factorization import (
    FactorizationError,
    Method,
    factor_counts,
    factorize,
    is_probable_prime,
)

__all__ = [
    "Curve",
    "FactorizationError",
    "FactorizationEvent",
    "INFINITY",
    "Method",
    "NonInvertibleError",
    "Point",
    "ProgressCallback",
    "factor_counts",
    "factorize",
    "is_probable_prime",
]

__version__ = "0.2.0"
