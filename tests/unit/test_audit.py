"""Unit tests for audit sinks."""

import pytest

from aiRail.audit.sinks import LoggingAuditSink, MemoryAuditSink, NullAuditSink
from aiRail.models.core import AuditEvent
from aiRail.models.enums import GuardAction, GuardStage


def make_event():
    return AuditEvent(
        stage=GuardStage.USER_INPUT,
        action=GuardAction.ALLOW,
        score=0,
        rules_evaluated=5,
    )


class TestNullAuditSink:
    @pytest.mark.asyncio
    async def test_emit_does_not_raise(self):
        sink = NullAuditSink()
        await sink.emit(make_event())  # Should not raise


class TestMemoryAuditSink:
    @pytest.mark.asyncio
    async def test_stores_events(self):
        sink = MemoryAuditSink()
        event = make_event()
        await sink.emit(event)
        assert len(sink.events) == 1
        assert sink.events[0].event_id == event.event_id

    @pytest.mark.asyncio
    async def test_bounded_capacity(self):
        sink = MemoryAuditSink(max_events=3)
        for _ in range(5):
            await sink.emit(make_event())
        assert len(sink.events) == 3  # Bounded deque

    @pytest.mark.asyncio
    async def test_clear(self):
        sink = MemoryAuditSink()
        await sink.emit(make_event())
        sink.clear()
        assert len(sink.events) == 0

    def test_len(self):
        sink = MemoryAuditSink()
        assert len(sink) == 0


class TestLoggingAuditSink:
    @pytest.mark.asyncio
    async def test_emit_does_not_raise(self):
        sink = LoggingAuditSink()
        await sink.emit(make_event())  # Should not raise
