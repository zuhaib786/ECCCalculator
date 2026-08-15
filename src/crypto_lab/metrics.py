"""Trace collection, operation counters, and JSONL export for lessons."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Protocol


class EventLike(Protocol):
    code: str
    message: str
    level: int
    data: Any


@dataclass(slots=True)
class TraceCollector:
    """A callback that captures traces without coupling algorithms to rendering."""

    max_level: int = 2
    events: list[EventLike] = field(default_factory=list)
    counts: Counter[str] = field(default_factory=Counter)

    def __call__(self, event: EventLike) -> None:
        self.counts[event.code] += 1
        if event.level <= self.max_level:
            self.events.append(event)

    @property
    def total_operations(self) -> int:
        return sum(self.counts.values())

    def as_dicts(self) -> list[dict[str, Any]]:
        return [
            {
                "code": event.code,
                "message": event.message,
                "level": event.level,
                "data": dict(event.data),
            }
            for event in self.events
        ]

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(record, sort_keys=True, default=str) for record in self.as_dicts()
        )


__all__ = ["EventLike", "TraceCollector"]

