"""Deterministic ECM trace used by the Manim example and its tests."""

from __future__ import annotations

from ecc_factor import FactorizationEvent, factorize

SMALL_FACTOR = 1_009
LARGE_PRIME = (1 << 127) - 1
LONG_COMPOSITE = SMALL_FACTOR * LARGE_PRIME


def build_ecm_story() -> tuple[tuple[int, ...], tuple[FactorizationEvent, ...]]:
    """Factor a 42-digit semiprime and retain every animation-ready event."""

    events: list[FactorizationEvent] = []
    factors = factorize(
        LONG_COMPOSITE,
        method="ecm",
        seed=11,
        progress=events.append,
        trial_limit=100,
        ecm_bound=200,
        ecm_curves=50,
    )
    return factors, tuple(events)


if __name__ == "__main__":
    result, trace = build_ecm_story()
    print(f"{LONG_COMPOSITE} = {' * '.join(map(str, result))}")
    for event in trace:
        print(f"[{event.code}] {event.message}")

