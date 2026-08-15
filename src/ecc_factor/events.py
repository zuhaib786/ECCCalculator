"""Progress events shared by the SDK and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


@dataclass(frozen=True, slots=True)
class FactorizationEvent:
    """A structured progress update emitted by a factorization algorithm.

    ``level`` is 1 for milestones and 2 for detailed algorithm progress. SDK
    users can ignore events, collect them, or render them however they want.
    """

    code: str
    message: str
    level: int = 1
    data: Mapping[str, Any] = field(default_factory=dict)


ProgressCallback = Callable[[FactorizationEvent], None]

