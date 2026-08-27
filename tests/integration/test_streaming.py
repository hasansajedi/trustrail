"""Integration tests for streaming support."""

import pytest

from trustrail.guard import Guard
from trustrail.models.config import GuardConfig
from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import (
    FailMode,
    GuardAction,
    GuardStage,
    RuleCategory,
    SensitiveDataMode,
    Severity,
)
from trustrail.models.sensitive_data import ProtectedData
from trustrail.rules.base import BaseRule
from trustrail.rules.resource import (
    CumulativeTokenBudgetRule,
    InputLengthRule,
    TokenEstimateRule,
)
from trustrail.streaming import StreamScanner


class FailingStreamRule(BaseRule):
    rule_id = "TEST-STREAM-ERROR"
    rule_name = "Failing stream rule"
    category = RuleCategory.CONTENT_SAFETY

    def evaluate(self, value, context):
        raise RuntimeError("provider unavailable")


class MediumFindingRule(BaseRule):
    rule_id = "TEST-STREAM-SCORE"
    rule_name = "Stream score threshold"
    category = RuleCategory.CONTENT_SAFETY
    default_severity = Severity.MEDIUM

    def evaluate(self, value, context):
        return GuardDecision(
            action=GuardAction.ALLOW,
            finding=self._finding("Medium-risk streamed content"),
            rule_id=self.rule_id,
        )


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
        guard = Guard(config=GuardConfig(max_text_length=5, audit_enabled=False))
        scanner = guard.stream(GuardStage.STREAM)
        assert scanner.process_chunk("hello!").action == GuardAction.BLOCK
        scanner.reset()

        assert not scanner.is_blocked
        assert scanner.findings == []
        assert scanner.total_chars == 0
        assert scanner.total_bytes == 0
        assert scanner.process_chunk("world").action == GuardAction.ALLOW

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

    @pytest.mark.asyncio
    async def test_async_scan_stops_at_cumulative_character_limit(self):
        async def chunks():
            for chunk in ["abcd", "efgh", "ijkl", "not-consumed"]:
                yield chunk

        guard = Guard(config=GuardConfig(max_text_length=10, audit_enabled=False))
        scanner = guard.stream(GuardStage.STREAM)
        results = [result async for result in scanner.scan(chunks())]

        assert [result.action for result in results] == [
            GuardAction.ALLOW,
            GuardAction.ALLOW,
            GuardAction.BLOCK,
        ]
        assert scanner.total_chars == 12
        assert scanner.finalize().input_length == 12

    def test_finalize_returns_guard_result(self):
        scanner = self.guard.stream(GuardStage.STREAM)
        scanner.process_chunk("Hello!")
        result = scanner.finalize()
        assert result.stage == GuardStage.STREAM
        assert result.input_length == len("Hello!")

    def test_cumulative_character_limit_cannot_be_bypassed_with_small_chunks(self):
        guard = Guard(config=GuardConfig(max_text_length=500, audit_enabled=False))
        scanner = guard.stream(GuardStage.STREAM)

        results = [scanner.process_chunk(chr(65 + index) * 100) for index in range(6)]
        final = scanner.finalize()

        assert all(result.action == GuardAction.ALLOW for result in results[:5])
        assert results[5].action == GuardAction.BLOCK
        assert results[5].safe_chunk == ""
        assert scanner.total_chars == 600
        assert final.input_length == 600
        assert final.action == GuardAction.BLOCK
        assert any(
            finding.rule_id == "RL-001" and finding.metadata["char_count"] == 600
            for finding in final.findings
        )

    def test_cumulative_token_estimate_uses_whole_stream(self):
        scanner = StreamScanner(
            rules=[TokenEstimateRule(max_tokens=5)],
            context=GuardContext(stage=GuardStage.STREAM),
        )

        assert scanner.process_chunk("abcd" * 3).action == GuardAction.ALLOW
        assert scanner.process_chunk("efgh" * 2).action == GuardAction.ALLOW
        result = scanner.process_chunk("ijkl")

        assert result.action == GuardAction.BLOCK
        finding = next(finding for finding in result.findings if finding.rule_id == "RL-002")
        assert finding.metadata["estimated_tokens"] == 6

    def test_cumulative_session_token_rule_counts_each_chunk_once(self):
        scanner = StreamScanner(
            rules=[CumulativeTokenBudgetRule(session_budget_tokens=2)],
            context=GuardContext(stage=GuardStage.STREAM, session_id="session-1"),
        )

        assert scanner.process_chunk("abcd").action == GuardAction.ALLOW
        assert scanner.process_chunk("efgh").action == GuardAction.ALLOW
        result = scanner.process_chunk("ijkl")

        assert result.action == GuardAction.BLOCK
        finding = next(finding for finding in result.findings if finding.rule_id == "RL-005")
        assert finding.metadata["session_tokens_used"] == 3

    def test_cumulative_utf8_byte_limit_uses_original_chunks(self):
        scanner = StreamScanner(
            rules=[InputLengthRule(max_chars=100, max_bytes=4)],
            context=GuardContext(stage=GuardStage.STREAM),
        )

        assert scanner.process_chunk("éé").action == GuardAction.ALLOW
        result = scanner.process_chunk("é")

        assert result.action == GuardAction.BLOCK
        assert scanner.total_chars == 3
        assert scanner.total_bytes == 6
        finding = next(finding for finding in result.findings if finding.rule_id == "RL-001")
        assert finding.metadata["byte_count"] == 6

    def test_final_result_reports_total_length_with_bounded_retained_value(self):
        scanner = StreamScanner(
            rules=[InputLengthRule(max_chars=100)],
            context=GuardContext(stage=GuardStage.STREAM),
            buffer_size=8,
            chunk_overlap=4,
        )

        scanner.process_chunk("1234567890")
        final = scanner.finalize()

        assert final.input_length == 10
        assert final.value == "34567890"
        assert len(final.value) <= 8

    @pytest.mark.parametrize(
        ("block_at", "warn_at", "expected_action"),
        [(100, 15, GuardAction.WARN), (15, 5, GuardAction.BLOCK)],
    )
    def test_configured_score_thresholds_apply_to_chunks_and_final_result(
        self,
        block_at,
        warn_at,
        expected_action,
    ):
        guard = Guard(
            config=GuardConfig(block_at=block_at, warn_at=warn_at, audit_enabled=False),
            extra_rules=[MediumFindingRule()],
        )
        scanner = guard.stream(GuardStage.STREAM)

        chunk = scanner.process_chunk("ordinary response")
        final = scanner.finalize()

        assert chunk.action == expected_action
        assert final.action == expected_action
        assert final.score.value == 15
        assert final.score.block_at == block_at
        assert final.score.warn_at == warn_at

    def test_fail_closed_rule_error_matches_non_streaming_guard(self):
        guard = Guard(
            config=GuardConfig(fail_mode=FailMode.CLOSED, audit_enabled=False),
            extra_rules=[FailingStreamRule()],
        )

        regular = guard.check("ordinary response", GuardStage.LLM_RESPONSE)
        scanner = guard.stream(GuardStage.STREAM)
        streamed = scanner.process_chunk("ordinary response")
        final = scanner.finalize()

        assert regular.action == GuardAction.BLOCK
        assert streamed.action == regular.action
        assert final.action == regular.action
        assert streamed.safe_chunk == ""
        assert [finding.rule_id for finding in streamed.findings] == ["TEST-STREAM-ERROR"]
        assert "provider unavailable" not in streamed.findings[0].message

    def test_fail_open_rule_error_matches_non_streaming_guard(self):
        guard = Guard(
            config=GuardConfig(fail_mode=FailMode.OPEN, audit_enabled=False),
            extra_rules=[FailingStreamRule()],
        )

        regular = guard.check("ordinary response", GuardStage.LLM_RESPONSE)
        streamed = guard.stream(GuardStage.STREAM).process_chunk("ordinary response")

        assert regular.action == GuardAction.ALLOW
        assert streamed.action == regular.action
        assert streamed.safe_chunk == "ordinary response"
        assert streamed.findings == []

    @pytest.mark.asyncio
    async def test_async_chunk_fails_closed_on_rule_error(self):
        guard = Guard(
            config=GuardConfig(fail_mode=FailMode.CLOSED, audit_enabled=False),
            extra_rules=[FailingStreamRule()],
        )

        result = await guard.stream(GuardStage.STREAM).aprocess_chunk("ordinary response")

        assert result.action == GuardAction.BLOCK
        assert result.safe_chunk == ""

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

    def test_stream_redacts_pii_before_emission(self):
        scanner = self.guard.stream(GuardStage.STREAM)

        result = scanner.process_chunk("Contact user@example.com")

        assert result.action == GuardAction.REDACT
        assert result.safe_chunk == "Contact [EMAIL]"
        assert "user@example.com" not in scanner.finalize().value

    def test_stream_blocks_sensitive_match_spanning_emitted_boundary(self):
        scanner = self.guard.stream(GuardStage.STREAM)
        scanner.process_chunk("Contact user@")

        result = scanner.process_chunk("example.com")

        assert result.action == GuardAction.BLOCK
        assert result.safe_chunk == ""

    def test_stream_applies_redact_mode_to_provider_tokens(self):
        guard = Guard(config=GuardConfig(sensitive_data_mode=SensitiveDataMode.REDACT))
        scanner = guard.stream(GuardStage.STREAM)
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2"

        result = scanner.process_chunk(f"Token: {token}")

        assert result.action == GuardAction.REDACT
        assert result.safe_chunk == "Token: [REDACTED]"
        assert token not in result.safe_chunk

    def test_stream_checks_application_protected_data(self):
        private_context = "Project Borealis has confidential launch terms."
        scanner = self.guard.stream(
            GuardStage.STREAM,
            protected_data=[ProtectedData(value=private_context)],
        )

        result = scanner.process_chunk(private_context)

        assert result.action == GuardAction.BLOCK
        assert result.safe_chunk == ""
