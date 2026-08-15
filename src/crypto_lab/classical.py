"""Classical ciphers and elementary cryptanalysis for classroom use.

The algorithms in this module are intentionally small and deterministic.  They
are useful for demonstrating substitution, transposition, modular arithmetic,
and the statistical attacks that motivated modern cryptography.  They are not
appropriate for protecting real messages.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import gcd
from typing import Mapping, Sequence

from .number_theory import mod_inverse
from .trace import TraceCallback, emit


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"""The 26-letter alphabet used by the teaching ciphers."""

_ALPHABET_SIZE = len(ALPHABET)


def _transform_text(
    text: str,
    transform: callable,
    *,
    preserve_case: bool,
    preserve_nonletters: bool,
) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    output: list[str] = []
    for character in text:
        upper = character.upper()
        if upper in ALPHABET:
            transformed = transform(ALPHABET.index(upper))
            letter = ALPHABET[transformed % _ALPHABET_SIZE]
            output.append(letter if not preserve_case and character.isupper() else (
                letter.lower() if preserve_case and character.islower() else letter
            ))
        elif preserve_nonletters:
            output.append(character)
        else:
            raise ValueError("text contains a non-letter; set preserve_nonletters=True")
    return "".join(output)


def caesar_encrypt(
    plaintext: str,
    shift: int,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Encrypt text by adding ``shift`` modulo 26 to each letter.

    Case and punctuation are retained by default so that the statistical
    structure of a classroom example remains visible.
    """

    if not isinstance(shift, int):
        raise TypeError("shift must be an integer")
    result = _transform_text(
        plaintext,
        lambda value: value + shift,
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
    )
    emit(trace, "classical.caesar", f"Caesar encryption with shift {shift}", shift=shift)
    return result


def caesar_decrypt(
    ciphertext: str,
    shift: int,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Decrypt a Caesar ciphertext by subtracting ``shift`` modulo 26."""

    result = caesar_encrypt(
        ciphertext,
        -shift,
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
        trace=None,
    )
    emit(trace, "classical.caesar", f"Caesar decryption with shift {shift}", shift=shift)
    return result


def _validate_affine_multiplier(multiplier: int) -> int:
    if not isinstance(multiplier, int):
        raise TypeError("affine multiplier must be an integer")
    multiplier %= _ALPHABET_SIZE
    if gcd(multiplier, _ALPHABET_SIZE) != 1:
        raise ValueError("affine multiplier must be coprime with 26")
    return multiplier


def affine_encrypt(
    plaintext: str,
    multiplier: int,
    offset: int,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Encrypt with the affine rule ``E(x) = multiplier*x + offset (mod 26)``."""

    multiplier = _validate_affine_multiplier(multiplier)
    if not isinstance(offset, int):
        raise TypeError("affine offset must be an integer")
    result = _transform_text(
        plaintext,
        lambda value: multiplier * value + offset,
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
    )
    emit(
        trace,
        "classical.affine",
        f"affine encryption with a={multiplier}, b={offset % 26}",
        multiplier=multiplier,
        offset=offset % 26,
    )
    return result


def affine_decrypt(
    ciphertext: str,
    multiplier: int,
    offset: int,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Decrypt an affine ciphertext using the modular inverse of ``multiplier``."""

    multiplier = _validate_affine_multiplier(multiplier)
    if not isinstance(offset, int):
        raise TypeError("affine offset must be an integer")
    inverse = mod_inverse(multiplier, _ALPHABET_SIZE)
    result = _transform_text(
        ciphertext,
        lambda value: inverse * (value - offset),
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
    )
    emit(
        trace,
        "classical.affine",
        f"affine decryption with a^-1={inverse}, b={offset % 26}",
        multiplier=multiplier,
        inverse=inverse,
        offset=offset % 26,
    )
    return result


def _validate_substitution_key(key: str) -> str:
    if not isinstance(key, str):
        raise TypeError("substitution key must be a string")
    normalized = key.upper()
    if len(normalized) != _ALPHABET_SIZE or set(normalized) != set(ALPHABET):
        raise ValueError("substitution key must be a permutation of A-Z")
    return normalized


def substitution_encrypt(
    plaintext: str,
    key: str,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Encrypt using a monoalphabetic substitution permutation of A--Z."""

    normalized = _validate_substitution_key(key)
    result = _transform_text(
        plaintext,
        lambda value: ALPHABET.index(normalized[value]),
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
    )
    emit(trace, "classical.substitution", "substitution encryption", key=normalized)
    return result


def substitution_decrypt(
    ciphertext: str,
    key: str,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Decrypt a monoalphabetic substitution permutation of A--Z."""

    normalized = _validate_substitution_key(key)
    inverse = {letter: index for index, letter in enumerate(normalized)}
    result = _transform_text(
        ciphertext,
        lambda value: inverse[ALPHABET[value]],
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
    )
    emit(trace, "classical.substitution", "substitution decryption", key=normalized)
    return result


def _validate_vigenere_key(key: str) -> str:
    if not isinstance(key, str):
        raise TypeError("Vigenere key must be a string")
    normalized = key.upper()
    if not normalized or any(letter not in ALPHABET for letter in normalized):
        raise ValueError("Vigenere key must contain at least one letter A-Z")
    return normalized


def _vigenere_transform(
    text: str,
    key: str,
    direction: int,
    *,
    preserve_case: bool,
    preserve_nonletters: bool,
    trace: TraceCallback | None,
) -> str:
    normalized_key = _validate_vigenere_key(key)
    key_values = tuple(ALPHABET.index(letter) for letter in normalized_key)
    key_position = 0

    def transform(value: int) -> int:
        nonlocal key_position
        shift = direction * key_values[key_position % len(key_values)]
        key_position += 1
        return value + shift

    result = _transform_text(
        text,
        transform,
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
    )
    emit(
        trace,
        "classical.vigenere",
        f"Vigenere {'encryption' if direction == 1 else 'decryption'}",
        key=normalized_key,
        letters_processed=key_position,
    )
    return result


def vigenere_encrypt(
    plaintext: str,
    key: str,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Encrypt with a repeating Vigenere key, advancing over letters only."""

    return _vigenere_transform(
        plaintext,
        key,
        1,
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
        trace=trace,
    )


def vigenere_decrypt(
    ciphertext: str,
    key: str,
    *,
    preserve_case: bool = True,
    preserve_nonletters: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Decrypt a repeating Vigenere ciphertext."""

    return _vigenere_transform(
        ciphertext,
        key,
        -1,
        preserve_case=preserve_case,
        preserve_nonletters=preserve_nonletters,
        trace=trace,
    )


def _validate_hill_key(key: Sequence[Sequence[int]]) -> tuple[tuple[int, int], tuple[int, int]]:
    try:
        rows = tuple(tuple(row) for row in key)
    except TypeError as error:
        raise TypeError("Hill key must be a 2x2 matrix") from error
    if len(rows) != 2 or any(len(row) != 2 for row in rows):
        raise ValueError("Hill key must be a 2x2 matrix")
    if any(not isinstance(value, int) for row in rows for value in row):
        raise TypeError("Hill key entries must be integers")
    return tuple(tuple(value % _ALPHABET_SIZE for value in row) for row in rows)  # type: ignore[return-value]


def _hill_inverse(key: tuple[tuple[int, int], tuple[int, int]]) -> tuple[tuple[int, int], tuple[int, int]]:
    a, b = key[0]
    c, d = key[1]
    determinant = (a * d - b * c) % _ALPHABET_SIZE
    try:
        determinant_inverse = mod_inverse(determinant, _ALPHABET_SIZE)
    except ValueError as error:
        raise ValueError("Hill key matrix is not invertible modulo 26") from error
    return (
        ((d * determinant_inverse) % 26, (-b * determinant_inverse) % 26),
        ((-c * determinant_inverse) % 26, (a * determinant_inverse) % 26),
    )


def _hill_transform(
    text: str,
    key: Sequence[Sequence[int]],
    *,
    decrypt: bool,
    padding: str | None,
    strip_padding: bool,
    trace: TraceCallback | None,
) -> str:
    matrix = _validate_hill_key(key)
    # Encryption itself is defined for any matrix, but a Hill *cipher* lesson
    # requires an invertible key so that the paired decrypt operation exists.
    if not decrypt:
        _hill_inverse(matrix)
    if decrypt:
        matrix = _hill_inverse(matrix)
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    letters = "".join(character.upper() for character in text if character.upper() in ALPHABET)
    if len(letters) % 2:
        if padding is None:
            raise ValueError("Hill text must contain an even number of letters")
        if not isinstance(padding, str) or len(padding) != 1 or padding.upper() not in ALPHABET:
            raise ValueError("padding must be one letter A-Z or None")
        letters += padding.upper()
    values = [ALPHABET.index(letter) for letter in letters]
    output: list[str] = []
    for block_index in range(0, len(values), 2):
        first, second = values[block_index : block_index + 2]
        output.extend(
            (
                (matrix[0][0] * first + matrix[0][1] * second) % 26,
                (matrix[1][0] * first + matrix[1][1] * second) % 26,
            )
        )
        emit(
            trace,
            "classical.hill.block",
            f"{'decrypted' if decrypt else 'encrypted'} block {block_index // 2}",
            level=2,
            block=block_index // 2,
            input=(first, second),
            output=tuple(output[-2:]),
        )
    result = "".join(ALPHABET[value] for value in output)
    if decrypt and strip_padding and padding is not None and result.endswith(padding.upper()):
        result = result[:-1]
    emit(
        trace,
        "classical.hill.complete",
        f"Hill {'decryption' if decrypt else 'encryption'} complete",
        matrix=matrix,
        letters=len(letters),
        padded=padding is not None and len(letters) > len(
            "".join(character.upper() for character in text if character.upper() in ALPHABET)
        ),
    )
    return result


def hill_encrypt(
    plaintext: str,
    key: Sequence[Sequence[int]],
    *,
    padding: str | None = "X",
    trace: TraceCallback | None = None,
) -> str:
    """Encrypt letters in pairs with an invertible 2x2 Hill matrix."""

    return _hill_transform(
        plaintext,
        key,
        decrypt=False,
        padding=padding,
        strip_padding=False,
        trace=trace,
    )


def hill_decrypt(
    ciphertext: str,
    key: Sequence[Sequence[int]],
    *,
    padding: str | None = "X",
    strip_padding: bool = True,
    trace: TraceCallback | None = None,
) -> str:
    """Decrypt a 2x2 Hill ciphertext, optionally removing its final pad letter."""

    return _hill_transform(
        ciphertext,
        key,
        decrypt=True,
        padding=padding,
        strip_padding=strip_padding,
        trace=trace,
    )


def letter_counts(text: str, *, include_zero: bool = False) -> dict[str, int]:
    """Count alphabetic characters, ignoring case and non-letters."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    counts = Counter(character for character in text.upper() if character in ALPHABET)
    if include_zero:
        return {letter: counts.get(letter, 0) for letter in ALPHABET}
    return {letter: counts[letter] for letter in ALPHABET if counts[letter]}


def letter_frequency_analysis(
    text: str,
    *,
    normalized: bool = False,
    include_zero: bool = False,
) -> dict[str, int | float]:
    """Return letter counts or relative frequencies in alphabetical order.

    Counts are returned by default; pass ``normalized=True`` for proportions
    whose sum is one.  Spaces and punctuation do not contribute to the total.
    """

    counts = letter_counts(text, include_zero=include_zero)
    if not normalized:
        return counts
    total = sum(counts.values())
    if total == 0:
        return {letter: 0.0 for letter in counts}
    return {letter: count / total for letter, count in counts.items()}


def frequency_analysis(
    text: str,
    *,
    normalized: bool = False,
    include_zero: bool = False,
) -> dict[str, int | float]:
    """Alias for :func:`letter_frequency_analysis`."""

    return letter_frequency_analysis(text, normalized=normalized, include_zero=include_zero)


@dataclass(frozen=True, slots=True)
class RepeatedSequence:
    """A repeated ciphertext n-gram and the positions at which it occurs."""

    sequence: str
    positions: tuple[int, ...]

    @property
    def distances(self) -> tuple[int, ...]:
        """All positive pairwise distances between occurrences."""

        return tuple(
            self.positions[right] - self.positions[left]
            for left in range(len(self.positions))
            for right in range(left + 1, len(self.positions))
        )


@dataclass(frozen=True, slots=True)
class KasiskiResult:
    """Inspectable output from a Kasiski repeated-sequence examination."""

    normalized_text: str
    repeated_sequences: tuple[RepeatedSequence, ...]
    distances: tuple[int, ...]
    factor_counts: Mapping[int, int]
    candidate_key_lengths: tuple[int, ...]

    @property
    def repeats(self) -> tuple[RepeatedSequence, ...]:
        """Short alias for :attr:`repeated_sequences`."""

        return self.repeated_sequences

    @property
    def candidate_factors(self) -> tuple[int, ...]:
        """Key-length candidates ordered by factor support and then length."""

        return self.candidate_key_lengths

    @property
    def factor_scores(self) -> Mapping[int, int]:
        """Alias for the factor-support mapping."""

        return self.factor_counts


def kasiski_examination(
    ciphertext: str,
    *,
    min_sequence_length: int = 3,
    max_sequence_length: int = 5,
    trace: TraceCallback | None = None,
) -> KasiskiResult:
    """Find repeated n-grams and rank factors of their distances.

    Kasiski examination is a heuristic for estimating a repeating-key length;
    a candidate is not a proof that the Vigenere key has that length.
    """

    if not isinstance(ciphertext, str):
        raise TypeError("ciphertext must be a string")
    if min_sequence_length < 2:
        raise ValueError("min_sequence_length must be at least 2")
    if max_sequence_length < min_sequence_length:
        raise ValueError("max_sequence_length must be at least min_sequence_length")
    normalized = "".join(character for character in ciphertext.upper() if character in ALPHABET)
    repeated: list[RepeatedSequence] = []
    for length in range(min_sequence_length, max_sequence_length + 1):
        positions_by_sequence: dict[str, list[int]] = {}
        for position in range(0, len(normalized) - length + 1):
            sequence = normalized[position : position + length]
            positions_by_sequence.setdefault(sequence, []).append(position)
        for sequence, positions in positions_by_sequence.items():
            if len(positions) >= 2:
                found = RepeatedSequence(sequence, tuple(positions))
                repeated.append(found)
                emit(
                    trace,
                    "classical.kasiski.repeat",
                    f"{sequence} repeats at {tuple(positions)}",
                    sequence=sequence,
                    positions=tuple(positions),
                    distances=found.distances,
                )
    distances = tuple(distance for item in repeated for distance in item.distances)
    factors = Counter(
        factor
        for distance in distances
        for factor in range(2, distance + 1)
        if distance % factor == 0
    )
    candidate_lengths = tuple(sorted(factors, key=lambda value: (-factors[value], value)))
    emit(
        trace,
        "classical.kasiski.complete",
        f"Kasiski found {len(repeated)} repeated sequences and {len(distances)} distances",
        repeated_sequences=len(repeated),
        distances=distances,
        factor_counts=dict(sorted(factors.items())),
        candidate_key_lengths=candidate_lengths,
    )
    return KasiskiResult(
        normalized,
        tuple(repeated),
        distances,
        dict(sorted(factors.items())),
        candidate_lengths,
    )


def kasiski_analysis(
    ciphertext: str,
    *,
    min_sequence_length: int = 3,
    max_sequence_length: int = 5,
    trace: TraceCallback | None = None,
) -> KasiskiResult:
    """Alias for :func:`kasiski_examination`."""

    return kasiski_examination(
        ciphertext,
        min_sequence_length=min_sequence_length,
        max_sequence_length=max_sequence_length,
        trace=trace,
    )


# Concise names are convenient in notebooks, while the explicit names above
# make a lecture API self-documenting.
caesar = caesar_encrypt
affine = affine_encrypt
substitution = substitution_encrypt
vigenere = vigenere_encrypt
hill = hill_encrypt


__all__ = [
    "ALPHABET",
    "KasiskiResult",
    "RepeatedSequence",
    "affine",
    "affine_decrypt",
    "affine_encrypt",
    "caesar",
    "caesar_decrypt",
    "caesar_encrypt",
    "frequency_analysis",
    "hill",
    "hill_decrypt",
    "hill_encrypt",
    "kasiski_analysis",
    "kasiski_examination",
    "letter_counts",
    "letter_frequency_analysis",
    "substitution",
    "substitution_decrypt",
    "substitution_encrypt",
    "vigenere",
    "vigenere_decrypt",
    "vigenere_encrypt",
]
