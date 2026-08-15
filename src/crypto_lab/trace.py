"""Structured tracing used by the teaching APIs and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One inspectable algorithm step.

    Level 1 events describe conceptual stages or blocks; level 2 events expose
    individual rounds or square-and-multiply steps.
    """

    code: str
    message: str
    level: int = 1
    data: Mapping[str, Any] = field(default_factory=dict)


TraceCallback = Callable[[TraceEvent], None]


def emit(
    callback: TraceCallback | None,
    code: str,
    message: str,
    *,
    level: int = 1,
    **data: object,
) -> None:
    if callback is not None:
        callback(TraceEvent(code, message, level, data))


__all__ = ["TraceCallback", "TraceEvent"]

