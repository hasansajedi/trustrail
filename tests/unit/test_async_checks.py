"""Acceptance coverage for async rules and external safety providers."""

from __future__ import annotations

import asyncio
from typing import ClassVar

import pytest

from trustrail import (
    AsyncGuardRequiredError,
    AsyncRuleRegistration,
    Document,
    FailMode,
    Guard,
    GuardAction,
    GuardConfig,
    GuardContext,
    GuardDecision,
    GuardFinding,
    GuardStage,
    MemoryAuditSink,
    ProviderRegistration,
    RuleCategory,
    RuleConfig,
    RulePhase,
    Severity,
)
from trustrail.rules.base import BaseAsyncRule


def _quiet_config(**kwargs: object) -> GuardConfig:
    return GuardConfig(audit_enabled=False, **kwargs)  # type: ignore[arg-type]


def _finding(
    rule_id: str,
    category: RuleCategory,
    *,
    severity: Severity = Severity.HIGH,
) -> GuardFinding:
    return GuardFinding(
        rule_id=rule_id,
        rule_name=f"Test {rule_id}",
        category=category,
        severity=severity,
        message="Test provider finding",
    )


class TransformRule(BaseAsyncRule):
    rule_id: ClassVar[str] = "ASYNC-TRANSFORM"
    rule_name: ClassVar[str] = "Async transform"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.TRANSFORM

    async def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        del context
        return GuardDecision(
            action=GuardAction.TRANSFORM,
            transformed_value=value.replace("raw", "normalized"),
            rule_id=self.rule_id,
        )


class FindingRule(BaseAsyncRule):
    rule_id: ClassVar[str] = "ASYNC-FINDING"
    rule_name: ClassVar[str] = "Async finding"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY

    async def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        del value, context
        return self._block("Detected by async rule", confidence=0.9)


class RecordingModerationProvider:
    def __init__(
        self,
        *,
        findings: list[GuardFinding] | None = None,
        delay: float = 0.0,
    ) -> None:
        self.findings = findings or []
        self.delay = delay
        self.calls: list[str] = []

    async def check(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        del context
        self.calls.append(text)
        await asyncio.sleep(self.delay)
        return self.findings


class RecordingSensitiveDataProvider:
    def __init__(self) -> None:
        self.detected_values: list[str] = []

    async def detect(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        del context
        self.detected_values.append(text)
        if "PRIVATE" not in text:
            return []
        return [
            _finding(
                "DLP-TEST",
                RuleCategory.SENSITIVE_DATA,
                severity=Severity.MEDIUM,
            )
        ]

    async def redact(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> str:
        del context
        return text.replace("PRIVATE", "[PRIVATE]")


class RecordingGroundingVerifier:
    def __init__(self) -> None:
        self.documents: list[Document] | None = None

    async def verify(
        self,
        response: str,
        documents: list[Document],
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        del response, context
        self.documents = documents
        return []


class RecordingPromptInjectionProvider:
    def __init__(self) -> None:
        self.context: GuardContext | None = None

    async def check(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        del text
        self.context = context
        return []


def test_sync_check_rejects_applicable_async_configuration() -> None:
    guard = Guard(
        _quiet_config(),
        content_safety_providers=[RecordingModerationProvider()],
    )

    with pytest.raises(AsyncGuardRequiredError, match=r"await guard\.acheck"):
        guard.check("safe", GuardStage.FINAL_OUTPUT)

    # The synchronous API remains available at stages where the provider is not active.
    assert guard.check("safe", GuardStage.SYSTEM_PROMPT).is_allowed


@pytest.mark.asyncio
async def test_provider_io_does_not_block_the_event_loop() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    class WaitingProvider:
        async def check(
            self,
            text: str,
            context: GuardContext | None = None,
        ) -> list[GuardFinding]:
            del text, context
            started.set()
            await release.wait()
            return []

    guard = Guard(_quiet_config(), content_safety_providers=[WaitingProvider()])
    task = asyncio.create_task(guard.acheck("safe", GuardStage.FINAL_OUTPUT))

    await asyncio.wait_for(started.wait(), timeout=1)
    await asyncio.sleep(0)
    assert not task.done()

    release.set()
    assert (await task).is_allowed


@pytest.mark.asyncio
async def test_async_rule_configuration_is_enforced() -> None:
    guard = Guard(
        _quiet_config(
            rule_overrides={
                "ASYNC-FINDING": RuleConfig(
                    action=GuardAction.WARN,
                    severity_override=Severity.LOW,
                    threshold=0.8,
                )
            }
        ),
        async_rules=[FindingRule()],
    )

    result = await guard.acheck("safe", GuardStage.FINAL_OUTPUT)

    assert result.action == GuardAction.WARN
    assert result.findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_transform_and_dlp_run_before_independent_providers() -> None:
    dlp = RecordingSensitiveDataProvider()
    moderation = RecordingModerationProvider()
    guard = Guard(
        _quiet_config(),
        async_rules=[TransformRule()],
        sensitive_data_providers=[dlp],
        content_safety_providers=[moderation],
    )

    result = await guard.acheck("raw PRIVATE", GuardStage.FINAL_OUTPUT)

    assert dlp.detected_values == ["normalized PRIVATE"]
    assert moderation.calls == ["normalized [PRIVATE]"]
    assert result.output_value == "normalized [PRIVATE]"
    assert result.action == GuardAction.REDACT


@pytest.mark.asyncio
async def test_findings_keep_registration_order_when_completion_order_differs() -> None:
    slow = RecordingModerationProvider(
        findings=[_finding("PROVIDER-SLOW", RuleCategory.CONTENT_SAFETY)],
        delay=0.03,
    )
    fast = RecordingModerationProvider(
        findings=[_finding("PROVIDER-FAST", RuleCategory.CONTENT_SAFETY)],
        delay=0.0,
    )
    guard = Guard(
        _quiet_config(),
        content_safety_providers=[
            ProviderRegistration("slow", slow),
            ProviderRegistration("fast", fast),
        ],
    )

    result = await guard.acheck("safe", GuardStage.FINAL_OUTPUT)

    provider_ids = [
        finding.rule_id for finding in result.findings if finding.rule_id.startswith("PROVIDER-")
    ]
    assert provider_ids == ["PROVIDER-SLOW", "PROVIDER-FAST"]
    assert result.action == GuardAction.BLOCK


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fail_mode", "expected_action", "expected_severity"),
    [
        (FailMode.CLOSED, GuardAction.BLOCK, Severity.HIGH),
        (FailMode.OPEN, GuardAction.WARN, Severity.INFO),
    ],
)
async def test_per_provider_timeout_honors_fail_mode(
    fail_mode: FailMode,
    expected_action: GuardAction,
    expected_severity: Severity,
) -> None:
    guard = Guard(
        _quiet_config(provider_timeout_seconds=1),
        content_safety_providers=[
            ProviderRegistration(
                "slow-moderation",
                RecordingModerationProvider(delay=0.2),
                timeout_seconds=0.01,
                fail_mode=fail_mode,
            )
        ],
    )

    result = await guard.acheck("safe", GuardStage.FINAL_OUTPUT)

    assert result.action == expected_action
    failure = next(finding for finding in result.findings if finding.rule_id.endswith(":error"))
    assert failure.severity == expected_severity
    assert failure.metadata["error_type"] == "timeout"


@pytest.mark.asyncio
async def test_provider_exception_is_sanitized_in_result_and_audit() -> None:
    class FailingProvider:
        async def check(
            self,
            text: str,
            context: GuardContext | None = None,
        ) -> list[GuardFinding]:
            del text, context
            raise RuntimeError("sk-live-provider-secret")

    sink = MemoryAuditSink()
    guard = Guard(
        GuardConfig(audit_enabled=True),
        audit_sink=sink,
        content_safety_providers=[
            ProviderRegistration("moderation", FailingProvider(), fail_mode=FailMode.CLOSED)
        ],
    )

    result = await guard.acheck("safe", GuardStage.FINAL_OUTPUT)

    assert result.is_blocked
    assert "sk-live-provider-secret" not in result.model_dump_json()
    assert result.findings[-1].metadata == {
        "check_id": "moderation",
        "check_kind": "content_safety",
        "error_type": "exception",
    }
    assert "sk-live-provider-secret" not in sink.events[0].model_dump_json()


@pytest.mark.asyncio
async def test_caller_cancellation_reaches_provider() -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class CancellableProvider:
        async def check(
            self,
            text: str,
            context: GuardContext | None = None,
        ) -> list[GuardFinding]:
            del text, context
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
            return []

    guard = Guard(_quiet_config(), content_safety_providers=[CancellableProvider()])
    task = asyncio.create_task(guard.acheck("safe", GuardStage.FINAL_OUTPUT))
    await asyncio.wait_for(started.wait(), timeout=1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(cancelled.wait(), timeout=1)


@pytest.mark.asyncio
async def test_provider_concurrency_is_bounded() -> None:
    active = 0
    maximum = 0
    lock = asyncio.Lock()

    class TrackedProvider:
        async def check(
            self,
            text: str,
            context: GuardContext | None = None,
        ) -> list[GuardFinding]:
            nonlocal active, maximum
            del text, context
            async with lock:
                active += 1
                maximum = max(maximum, active)
            await asyncio.sleep(0.01)
            async with lock:
                active -= 1
            return []

    guard = Guard(
        _quiet_config(max_async_concurrency=2),
        content_safety_providers=[TrackedProvider() for _ in range(6)],
    )

    result = await guard.acheck("safe", GuardStage.FINAL_OUTPUT)

    assert result.is_allowed
    assert maximum == 2


@pytest.mark.asyncio
async def test_whole_check_timeout_cancels_provider_and_honors_global_fail_mode() -> None:
    cancelled = asyncio.Event()

    class SlowProvider:
        async def check(
            self,
            text: str,
            context: GuardContext | None = None,
        ) -> list[GuardFinding]:
            del text, context
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
            return []

    guard = Guard(
        _quiet_config(
            timeout_seconds=0.1,
            provider_timeout_seconds=1,
            fail_mode=FailMode.OPEN,
        ),
        content_safety_providers=[SlowProvider()],
    )

    result = await guard.acheck("safe", GuardStage.FINAL_OUTPUT)

    assert result.action == GuardAction.WARN
    assert result.findings[0].rule_id == "SYS-001"
    await asyncio.wait_for(cancelled.wait(), timeout=1)


@pytest.mark.asyncio
async def test_grounding_verifier_receives_rag_documents() -> None:
    verifier = RecordingGroundingVerifier()
    documents = [Document(content="The supported fact.", source="knowledge-base")]
    guard = Guard(_quiet_config(), grounding_verifiers=[verifier])

    result = await guard.acheck(
        "The supported fact.",
        GuardStage.LLM_RESPONSE,
        documents=documents,
    )

    assert result.is_allowed
    assert verifier.documents == documents


@pytest.mark.asyncio
async def test_async_rag_helpers_preserve_document_provenance() -> None:
    provider = RecordingPromptInjectionProvider()
    document = Document(
        id="authoritative-id",
        content="Reviewed context",
        source="reviewed-source",
        metadata={"source": "attacker-source", "custom": "document-value"},
    )
    caller = GuardContext(metadata={"custom": "caller-value"})
    guard = Guard(
        _quiet_config(),
        prompt_injection_providers=[
            ProviderRegistration(
                "document-injection",
                provider,
                stages=[GuardStage.RAG_DOCUMENT],
            )
        ],
    )

    envelope = await guard.abuild_rag_context([document], context=caller)
    rendered = await guard.aprotect_rag_context(envelope, context=caller)

    assert "authoritative-id" in rendered
    assert provider.context is not None
    assert provider.context.metadata["document_id"] == "authoritative-id"
    assert provider.context.metadata["source"] == "reviewed-source"
    assert provider.context.metadata["custom"] == "caller-value"
    assert provider.context.metadata["document_metadata"]["source"] == "attacker-source"


@pytest.mark.asyncio
async def test_missing_grounding_documents_honors_registration_fail_mode() -> None:
    verifier = RecordingGroundingVerifier()
    guard = Guard(
        _quiet_config(),
        grounding_verifiers=[ProviderRegistration("grounding", verifier, fail_mode=FailMode.OPEN)],
    )

    result = await guard.acheck("claim", GuardStage.LLM_RESPONSE)

    assert result.action == GuardAction.WARN
    assert result.findings[-1].metadata["check_kind"] == "grounding"


def test_async_registration_validates_ids_and_timeouts() -> None:
    with pytest.raises(ValueError, match="async check ID"):
        ProviderRegistration("contains a space", RecordingModerationProvider())
    with pytest.raises(ValueError, match="positive and finite"):
        AsyncRuleRegistration(FindingRule(), timeout_seconds=0)
