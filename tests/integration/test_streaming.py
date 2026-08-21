"""Integration tests for streaming support."""

import pytest

from aiRail.guard import Guard
from aiRail.models.enums import GuardAction, GuardStage


class TestStreamScanner:
    def setup_method(self):
        self.guard = Guard.silent()

    def test_safe_stream(self):
        scanner = self.guard.stream(GuardStage.STREAM)
        chunks = ["Hello", ", ", "world", "!"]
        results = [scanner.process_chunk(c) for c in chunks]
        assert all(r.action == GuardAction.ALLOW for r in results)

        final = scanner.finalize()
        assert final.is_allowed

    def test_scanner_reset(self):
        scanner = self.guard.stream(GuardStage.STREAM)
        scanner.process_chunk("hello")
        scanner.reset()
        assert not scanner.is_blocked

    @pytest.mark.asyncio
    async def test_async_chunk_processing(self):
        scanner = self.guard.stream(GuardStage.STREAM)
        result = await scanner.aprocess_chunk("Hello!")
        assert result.action == GuardAction.ALLOW

    @pytest.mark.asyncio
    async def test_async_scan_generator(self):
        async def chunks():
            for chunk in ["Hello", " ", "world"]:
                yield chunk

        scanner = self.guard.stream(GuardStage.STREAM)
        results = []
        async for result in scanner.scan(chunks()):
            results.append(result)

        assert len(results) == 3
        assert all(r.action == GuardAction.ALLOW for r in results)

    def test_finalize_returns_guard_result(self):
        scanner = self.guard.stream(GuardStage.STREAM)
        scanner.process_chunk("Hello!")
        result = scanner.finalize()
        assert result.stage == GuardStage.STREAM

    def test_stream_strips_invisible_unicode_from_safe_chunk(self):
        scanner = self.guard.stream(GuardStage.STREAM)

        result = scanner.process_chunk("public\U000e0061 response\ufe0f")

        assert result.action == GuardAction.ALLOW
        assert result.safe_chunk == "public response"
        assert any(finding.rule_id == "PI-016" for finding in result.findings)
        assert scanner.finalize().value == "public response"

    def test_stream_can_return_empty_sanitized_chunk(self):
        scanner = self.guard.stream(GuardStage.STREAM)

        result = scanner.process_chunk("\U000e0061\ufe0f")

        assert result.safe_chunk == ""

    def test_stream_detects_output_attack_after_unicode_sanitization(self):
        scanner = self.guard.stream(GuardStage.STREAM)

        scanner.process_chunk("<scr\u200b")
        result = scanner.process_chunk("ipt>alert(1)</script>")

        assert result.action == GuardAction.BLOCK
        assert result.safe_chunk == ""
