"""Audit sink implementations."""

from __future__ import annotations

import json
import logging
from collections import deque
from typing import Any

from trustrail.models.core import AuditEvent

logger = logging.getLogger("trustrail.audit")


class NullAuditSink:
    """Discards all audit events (useful for testing)."""

    async def emit(self, event: AuditEvent) -> None:
        pass


class LoggingAuditSink:
    """Emits audit events as structured JSON log messages.

    Never logs sensitive content — only metadata.
    """

    def __init__(
        self,
        logger_name: str = "trustrail.audit",
        level: int = logging.INFO,
    ) -> None:
        self._logger = logging.getLogger(logger_name)
        self._level = level

    async def emit(self, event: AuditEvent) -> None:
        record: dict[str, Any] = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "stage": event.stage.value,
            "action": event.action.value,
            "score": event.score,
            "finding_ids": event.finding_ids,
            "finding_categories": event.finding_categories,
            "finding_severities": event.finding_severities,
            "rules_evaluated": event.rules_evaluated,
            "latency_ms": round(event.latency_ms, 2),
            "input_length": event.input_length,
            "request_id": event.request_id,
            "session_id": event.session_id,
            "memory_classification": (
                event.memory_classification.value if event.memory_classification else None
            ),
            "memory_approval_outcome": event.memory_approval_outcome,
            # user_id intentionally omitted from default output for privacy
        }
        self._logger.log(self._level, json.dumps(record))


class MemoryAuditSink:
    """Stores audit events in memory with bounded capacity.

    Primarily for testing and debugging.
    """

    def __init__(self, max_events: int = 1000) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_events)

    async def emit(self, event: AuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)
