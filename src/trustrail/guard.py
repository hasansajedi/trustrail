"""trustrail Guard Engine.

The central entry point for all guardrail evaluation.
"""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal, TypeVar

if TYPE_CHECKING:
    from trustrail.agents.session import AgentSession

from trustrail.audit import AuditEvent, LoggingAuditSink, NullAuditSink
from trustrail.exceptions import ApprovalRequiredError, GuardrailBlockedError, ResourceLimitError
from trustrail.models.config import GuardConfig
from trustrail.models.core import (
    Document,
    GuardContext,
    GuardDecision,
    GuardFinding,
    GuardResult,
    Message,
    RiskScore,
)
from trustrail.models.enums import (
    FailMode,
    GuardAction,
    GuardStage,
    RuleCategory,
    SensitiveDataMode,
    Severity,
    TrustLevel,
)
from trustrail.models.prompt import (
    PromptScanResult,
    PromptSegment,
    PromptSegmentResult,
    PromptSource,
)
from trustrail.models.rag import RAGContextEnvelope
from trustrail.models.sensitive_data import ProtectedData
from trustrail.policies.agent import AgentPolicy
from trustrail.policies.content_safety import ContentSafetyPolicy
from trustrail.policies.memory import MemoryPolicy
from trustrail.policies.output import OutputSafetyPolicy
from trustrail.policies.prompt_injection import PromptInjectionPolicy
from trustrail.policies.rag import RAGPolicy
from trustrail.policies.resource import ResourcePolicy
from trustrail.policies.sensitive_data import SensitiveDataPolicy
from trustrail.policies.supply_chain import SupplyChainPolicy
from trustrail.policies.tools import ToolPolicy
from trustrail.protocols import ApprovalProvider, AuditSink
from trustrail.rules.base import BaseRule
from trustrail.rules.prompt_injection import InvisibleUnicodeRule
from trustrail.rules.prompt_injection.boundary import CrossBoundaryInjectionRule
from trustrail.rules.sensitive_data import ProtectedDataDisclosureRule
from trustrail.streaming import StreamScanner

F = TypeVar("F", bound=Callable[..., Any])


class _AlertCallback:
    """Internal alert callback registration."""

    def __init__(self, severity: Severity, callback: Callable[[GuardResult], None]) -> None:
        self.severity = severity
        self.callback = callback


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_PROMPT_SOURCE_STAGES: dict[PromptSource, GuardStage] = {
    PromptSource.SYSTEM: GuardStage.SYSTEM_PROMPT,
    PromptSource.USER: GuardStage.USER_INPUT,
    PromptSource.RAG: GuardStage.RAG_DOCUMENT,
    PromptSource.TOOL: GuardStage.TOOL_RESPONSE,
    PromptSource.MEMORY: GuardStage.MEMORY_READ,
    PromptSource.EXTERNAL: GuardStage.EXTERNAL_CONTENT,
    PromptSource.MULTIMODAL: GuardStage.EXTERNAL_CONTENT,
}


class GuardSession:
    """Async context manager for a guard session."""

    def __init__(self, guard: Guard, context: GuardContext) -> None:
        self._guard = guard
        self._context = context

    async def check(self, value: str, stage: GuardStage, **kwargs: Any) -> GuardResult:
        return await self._guard.acheck(value, stage, context=self._context, **kwargs)

    async def protect(self, value: str, stage: GuardStage, **kwargs: Any) -> str:
        return await self._guard.aprotect(value, stage, context=self._context, **kwargs)

    async def __aenter__(self) -> GuardSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


class Guard:
    """Main guardrail engine.

    Evaluates text at various LLM pipeline stages using a configurable
    set of policies and rules.
    """

    def __init__(
        self,
        config: GuardConfig | None = None,
        audit_sink: AuditSink | None = None,
        extra_rules: list[BaseRule] | None = None,
        approval_provider: ApprovalProvider | None = None,
    ) -> None:
        self._config = config if config is not None else GuardConfig.default()
        self._audit_sink = audit_sink if audit_sink is not None else LoggingAuditSink()
        self._extra_rules = extra_rules if extra_rules is not None else []
        self._approval_provider = approval_provider
        self._alert_callbacks: list[_AlertCallback] = []
        self._policies = self._build_policies()

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def default(cls, extra_rules: list[BaseRule] | None = None) -> Guard:
        """Sensible defaults, low false-positive rate."""
        return cls(config=GuardConfig.default(), extra_rules=extra_rules)

    @classmethod
    def balanced(cls, extra_rules: list[BaseRule] | None = None) -> Guard:
        """Balanced security/usability."""
        return cls(config=GuardConfig.balanced(), extra_rules=extra_rules)

    @classmethod
    def strict(cls, extra_rules: list[BaseRule] | None = None) -> Guard:
        """Maximum security, higher false-positive rate."""
        return cls(config=GuardConfig.strict(), extra_rules=extra_rules)

    @classmethod
    def from_profile(cls, name: str) -> Guard:
        """Load guard from a named profile."""
        profiles: dict[str, GuardConfig] = {
            "default": GuardConfig.default(),
            "balanced": GuardConfig.balanced(),
            "strict": GuardConfig.strict(),
            "paranoid": GuardConfig(
                fail_mode=FailMode.CLOSED,
                block_at=20,
                warn_at=5,
            ),
            "permissive": GuardConfig(
                fail_mode=FailMode.OPEN,
                block_at=95,
                warn_at=70,
            ),
        }
        config = profiles.get(name)
        if config is None:
            from trustrail.exceptions import ConfigurationError

            raise ConfigurationError(f"Unknown profile: '{name}'. Valid profiles: {list(profiles)}")
        return cls(config=config)

    @classmethod
    def silent(cls) -> Guard:
        """Guard with no audit output (for testing)."""
        return cls(audit_sink=NullAuditSink())

    # ── Policy building ───────────────────────────────────────────────────────

    def _build_policies(self) -> dict[str, Any]:
        cfg = self._config
        return {
            "prompt_injection": PromptInjectionPolicy(),
            "sensitive_data": SensitiveDataPolicy(),
            "supply_chain": SupplyChainPolicy(),
            "output_safety": OutputSafetyPolicy(),
            "content_safety": ContentSafetyPolicy(),
            "resource": ResourcePolicy(
                max_chars=cfg.max_text_length,
            ),
            "rag": RAGPolicy(require_context_labels=cfg.require_rag_context_labels),
            "memory": MemoryPolicy(require_approval=cfg.require_memory_write_approval),
            "tools": ToolPolicy(),
            "agent": AgentPolicy(),
        }

    # ── Core evaluation ───────────────────────────────────────────────────────

    def _get_rules_for_stage(
        self,
        stage: GuardStage,
        protected_data: list[ProtectedData] | None = None,
    ) -> list[BaseRule]:
        """Return the rules applicable to a given pipeline stage."""
        rules: list[BaseRule] = []

        # Resource limits apply everywhere
        resource_policy = self._policies["resource"]
        rules.extend(resource_policy.get_rules())

        # Sanitize invisible instruction/exfiltration channels at every text
        # boundary before stage-specific detection rules evaluate the value.
        if self._config.strip_invisible_unicode:
            rules.append(InvisibleUnicodeRule())

        if stage in (
            GuardStage.USER_INPUT,
            GuardStage.LLM_REQUEST,
        ):
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())
            # Also check URLs in user input for SSRF
            from trustrail.rules.url import (
                EmbeddedCredentialRule,
                MetadataServiceRule,
                PrivateIpRule,
                SchemeValidationRule,
            )

            rules.extend(
                [
                    SchemeValidationRule(),
                    PrivateIpRule(),
                    MetadataServiceRule(),
                    EmbeddedCredentialRule(),
                ]
            )

        elif stage in (GuardStage.SYSTEM_PROMPT,):
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage in (
            GuardStage.LLM_RESPONSE,
            GuardStage.FINAL_OUTPUT,
            GuardStage.STREAM,
        ):
            rules.extend(self._policies["output_safety"].get_rules())
            rules.extend(self._policies["content_safety"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage in (
            GuardStage.RAG_DOCUMENT,
            GuardStage.EXTERNAL_CONTENT,
            GuardStage.RAG_CONTEXT,
        ):
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["rag"].get_rules())
            rules.extend(self._policies["supply_chain"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage in (GuardStage.TOOL_REQUEST,):
            rules.extend(self._policies["tools"].get_rules())
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage in (GuardStage.TOOL_RESPONSE,):
            rules.extend(self._policies["supply_chain"].get_rules())
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["output_safety"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage in (GuardStage.AGENT_ACTION,):
            rules.extend(self._policies["agent"].get_rules())
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage == GuardStage.MEMORY_READ:
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())

        elif stage == GuardStage.MEMORY_WRITE:
            rules.extend(self._policies["prompt_injection"].get_rules())
            rules.extend(self._policies["sensitive_data"].get_rules())
            rules.extend(self._policies["memory"].get_rules())

        # Add extra rules always
        rules.extend(self._extra_rules)
        if protected_data:
            rules.append(ProtectedDataDisclosureRule(protected_data))

        return rules

    def _evaluate_rules(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext,
        protected_data: list[ProtectedData] | None = None,
    ) -> GuardResult:
        """Synchronous rule evaluation."""
        rules = self._get_rules_for_stage(stage, protected_data)
        findings: list[GuardFinding] = []
        transformed_value: str | None = None
        current_value = value
        start = time.perf_counter()
        rule_blocked = False  # Track if any rule explicitly requested BLOCK
        rule_warned = False  # Track if any rule explicitly requested WARN
        rule_redacted = False
        rule_requires_approval = False
        policy_handled_finding_ids: set[int] = set()

        for rule in rules:
            if not rule.enabled:
                continue
            try:
                decision = rule.timed_evaluate(current_value, context)
                policy_handled = self._apply_sensitive_data_mode(decision)
                if decision.finding is not None:
                    findings.append(decision.finding)
                    if policy_handled:
                        policy_handled_finding_ids.add(id(decision.finding))

                # Track explicit BLOCK decisions from rules
                if decision.action == GuardAction.BLOCK:
                    rule_blocked = True
                elif decision.action == GuardAction.WARN:
                    rule_warned = True
                elif decision.action == GuardAction.REDACT:
                    rule_redacted = True
                elif decision.action == GuardAction.REQUIRE_APPROVAL:
                    rule_requires_approval = True

                # Apply transformations
                if (
                    decision.action in (GuardAction.REDACT, GuardAction.TRANSFORM)
                    and decision.transformed_value is not None
                ):
                    transformed_value = decision.transformed_value
                    current_value = decision.transformed_value

                # Critical and resource-limit findings fail closed immediately.
                if (
                    decision.finding
                    and decision.finding.severity == Severity.CRITICAL
                    and not policy_handled
                ) or (
                    decision.action == GuardAction.BLOCK
                    and decision.finding is not None
                    and decision.finding.category == RuleCategory.RESOURCE
                ):
                    break

            except Exception as exc:
                if self._config.fail_mode == FailMode.CLOSED:
                    rule_blocked = True
                    findings.append(
                        GuardFinding(
                            rule_id=rule.rule_id,
                            rule_name=rule.rule_name,
                            category=rule.category,
                            severity=Severity.HIGH,
                            message=f"Rule evaluation failed (fail-closed): {type(exc).__name__}",
                        )
                    )
                # OPEN: continue silently

        latency_ms = (time.perf_counter() - start) * 1000
        score = RiskScore.from_findings(
            findings,
            block_at=self._config.block_at,
            warn_at=self._config.warn_at,
        )

        action = self._determine_action(
            score,
            findings,
            rule_blocked,
            rule_warned,
            rule_redacted,
            rule_requires_approval,
            policy_handled_finding_ids,
        )

        return GuardResult(
            action=action,
            findings=findings,
            score=score,
            value=value,
            transformed_value=transformed_value,
            input_length=len(value),
            stage=stage,
            context=context,
            latency_ms=latency_ms,
            rules_evaluated=len(rules),
        )

    def _determine_action(
        self,
        score: RiskScore,
        findings: list[GuardFinding],
        rule_blocked: bool = False,
        rule_warned: bool = False,
        rule_redacted: bool = False,
        rule_requires_approval: bool = False,
        policy_handled_finding_ids: set[int] | None = None,
    ) -> GuardAction:
        """Determine final action from score, findings, and rule decisions."""
        handled_ids = policy_handled_finding_ids or set()
        actionable_findings = [finding for finding in findings if id(finding) not in handled_ids]

        # Check for critical findings — always block
        for f in actionable_findings:
            if f.severity == Severity.CRITICAL:
                return GuardAction.BLOCK

        # If any rule explicitly requested BLOCK, honor it
        if rule_blocked:
            return GuardAction.BLOCK

        actionable_score = RiskScore.from_findings(
            actionable_findings,
            block_at=score.block_at,
            warn_at=score.warn_at,
        )
        if actionable_score.should_block:
            return GuardAction.BLOCK

        if rule_requires_approval:
            return GuardAction.REQUIRE_APPROVAL

        if actionable_score.should_warn or rule_warned:
            return GuardAction.WARN

        # Check if any HIGH finding warrants a warning
        for f in actionable_findings:
            if f.severity == Severity.HIGH:
                return GuardAction.WARN

        if rule_redacted:
            return GuardAction.REDACT

        return GuardAction.ALLOW

    def _apply_sensitive_data_mode(self, decision: GuardDecision) -> bool:
        """Apply the configured disclosure policy and report explicit handling."""
        finding = decision.finding
        if finding is None or finding.category not in (
            RuleCategory.SENSITIVE_DATA,
            RuleCategory.SECRET,
        ):
            return False

        mode = self._config.sensitive_data_mode
        if mode == SensitiveDataMode.DEFAULT:
            return False
        if mode == SensitiveDataMode.BLOCK:
            decision.action = GuardAction.BLOCK
            return False
        if mode == SensitiveDataMode.REDACT:
            # A detector that cannot produce a safe replacement fails closed.
            decision.action = (
                GuardAction.REDACT if decision.transformed_value is not None else GuardAction.BLOCK
            )
            return decision.action == GuardAction.REDACT

        decision.action = GuardAction.ALLOW
        decision.transformed_value = None
        return True

    # ── Public synchronous API ────────────────────────────────────────────────

    def check(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext | None = None,
        protected_data: list[ProtectedData] | None = None,
        **kwargs: Any,
    ) -> GuardResult:
        """Check a value at the given stage. Returns GuardResult."""
        ctx = context or self._make_context(stage, **kwargs)
        result = self._evaluate_rules(value, stage, ctx, protected_data)
        self._fire_alerts(result)
        if self._config.audit_enabled:
            self._emit_audit_sync(result)
        return result

    def protect(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext | None = None,
        protected_data: list[ProtectedData] | None = None,
        **kwargs: Any,
    ) -> str:
        """Check and raise GuardrailBlockedError if blocked, else return value."""
        result = self.check(
            value,
            stage,
            context=context,
            protected_data=protected_data,
            **kwargs,
        )
        if result.is_blocked:
            raise GuardrailBlockedError(
                f"Content blocked at stage '{stage.value}'",
                stage=stage,
                findings=result.findings,
                score=result.score.value,
            )
        if result.action == GuardAction.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(
                f"Approval required at stage '{stage.value}'",
                stage=stage,
                findings=result.findings,
                request_id=result.context.request_id if result.context else None,
            )
        return result.output_value

    def check_document(
        self,
        document: Document,
        stage: GuardStage = GuardStage.RAG_DOCUMENT,
        context: GuardContext | None = None,
    ) -> GuardResult:
        """Check a document with authoritative provenance and caller identity."""
        ctx = self._document_context(document, stage=stage, context=context)
        return self.check(document.content, stage, context=ctx)

    def check_prompt_segments(self, segments: list[PromptSegment]) -> PromptScanResult:
        """Scan a composed prompt without discarding source and trust boundaries.

        Every segment is evaluated at the stage associated with its source. The
        cross-boundary pass then detects payloads that become malicious only
        after separately safe segments are concatenated.
        """
        if not segments:
            raise ValueError("segments must contain at least one prompt segment")
        if len(segments) > self._config.max_prompt_segments:
            raise ResourceLimitError(
                f"Prompt contains {len(segments)} segments; "
                f"limit is {self._config.max_prompt_segments}"
            )

        segment_results: list[PromptSegmentResult] = []
        for segment in segments:
            stage = _PROMPT_SOURCE_STAGES[segment.source]
            if segment.source == PromptSource.SYSTEM and segment.trust_level != TrustLevel.TRUSTED:
                stage = GuardStage.EXTERNAL_CONTENT
            metadata: dict[str, Any] = {
                **segment.metadata,
                "prompt_segment_id": segment.segment_id,
                "prompt_source": segment.source.value,
            }
            context = GuardContext(
                stage=stage,
                trust_level=segment.trust_level,
                metadata=metadata,
            )
            segment_results.append(
                PromptSegmentResult(
                    segment=segment, result=self.check(segment.content, stage, context)
                )
            )

        boundary_rule = CrossBoundaryInjectionRule(window_chars=self._config.prompt_boundary_window)
        boundary_context = GuardContext(
            stage=GuardStage.LLM_REQUEST,
            metadata={"prompt_segment_count": len(segments)},
        )
        boundary_findings: list[GuardFinding] = []
        boundary_checks = 0
        scanned_segments = [item.output_segment for item in segment_results]
        for left_index, left in enumerate(scanned_segments):
            for right in scanned_segments[left_index + 1 :]:
                if left.trust_level == right.trust_level == TrustLevel.TRUSTED:
                    continue
                boundary_checks += 1
                decision = boundary_rule.evaluate_segments(left, right, boundary_context)
                if decision.finding is not None:
                    boundary_findings.append(decision.finding)
                    break
            if boundary_findings:
                break

        if boundary_findings:
            boundary_result = GuardResult(
                action=GuardAction.BLOCK,
                findings=boundary_findings,
                score=RiskScore.from_findings(
                    boundary_findings,
                    block_at=self._config.block_at,
                    warn_at=self._config.warn_at,
                ),
                value="",
                stage=GuardStage.LLM_REQUEST,
                context=boundary_context,
                rules_evaluated=boundary_checks,
            )
            self._fire_alerts(boundary_result)
            if self._config.audit_enabled:
                self._emit_audit_sync(boundary_result)

        action = self._prompt_scan_action(segment_results, boundary_findings)
        return PromptScanResult(
            action=action,
            segment_results=segment_results,
            boundary_findings=boundary_findings,
        )

    def protect_prompt_segments(self, segments: list[PromptSegment]) -> list[PromptSegment]:
        """Return downstream-safe prompt segments or raise when any boundary is unsafe."""
        result = self.check_prompt_segments(segments)
        if result.is_blocked:
            raise GuardrailBlockedError(
                "Structured prompt blocked by guardrail",
                stage=GuardStage.LLM_REQUEST,
                findings=result.findings,
            )
        if result.action == GuardAction.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(
                "Structured prompt requires approval",
                stage=GuardStage.LLM_REQUEST,
            )
        return result.output_segments

    def _prompt_scan_action(
        self,
        segment_results: list[PromptSegmentResult],
        boundary_findings: list[GuardFinding],
    ) -> GuardAction:
        if boundary_findings or any(item.result.is_blocked for item in segment_results):
            return GuardAction.BLOCK
        if any(item.result.requires_approval for item in segment_results):
            return GuardAction.REQUIRE_APPROVAL
        if any(item.result.action == GuardAction.WARN for item in segment_results):
            return GuardAction.WARN
        return GuardAction.ALLOW

    def build_rag_context(
        self,
        documents: list[Document],
        *,
        context: GuardContext | None = None,
        require_provenance: bool = True,
    ) -> RAGContextEnvelope:
        """Scan documents with request context and assemble a labeled envelope."""
        safe_documents: list[Document] = []
        for document in documents:
            result = self.check_document(document, context=context)
            if result.is_blocked:
                raise GuardrailBlockedError(
                    "Retrieved document blocked before RAG context assembly",
                    stage=GuardStage.RAG_DOCUMENT,
                    findings=result.findings,
                    score=result.score.value,
                )
            safe_documents.append(document.model_copy(update={"content": result.output_value}))
        return RAGContextEnvelope.from_documents(
            safe_documents,
            require_provenance=require_provenance,
        )

    def check_rag_context(
        self,
        envelope: RAGContextEnvelope,
        context: GuardContext | None = None,
    ) -> GuardResult:
        """Check an envelope using its provenance and caller correlation context."""
        return self.check(
            envelope.render(),
            GuardStage.RAG_CONTEXT,
            context=envelope.guard_context(context),
        )

    def protect_rag_context(
        self,
        envelope: RAGContextEnvelope,
        context: GuardContext | None = None,
    ) -> str:
        """Return safe RAG data while preserving caller audit correlation."""
        result = self.check_rag_context(envelope, context=context)
        if result.is_blocked:
            raise GuardrailBlockedError(
                "RAG context blocked by guardrail",
                stage=GuardStage.RAG_CONTEXT,
                findings=result.findings,
                score=result.score.value,
            )
        return result.output_value

    def check_memory_write(
        self,
        value: str,
        *,
        persistent: bool = True,
        context: GuardContext | None = None,
    ) -> GuardResult:
        """Classify and scan a proposed memory write without authorizing it."""
        ctx = self._memory_write_context(context, persistent=persistent)
        return self.check(value, GuardStage.MEMORY_WRITE, context=ctx)

    def protect_messages(
        self,
        messages: list[Message],
        context: GuardContext | None = None,
    ) -> list[Message]:
        """Check all messages in a conversation. Returns safe messages."""
        safe = []
        for msg in messages:
            stage = (
                GuardStage.USER_INPUT
                if msg.role == "user"
                else GuardStage.SYSTEM_PROMPT
                if msg.role == "system"
                else GuardStage.LLM_RESPONSE
            )
            ctx = context or self._make_context(stage, metadata={"message_count": len(messages)})
            result = self.check(msg.content, stage, context=ctx)
            if not result.is_blocked:
                # Update content if transformed
                if result.transformed_value is not None:
                    msg = Message(
                        role=msg.role,
                        content=result.output_value,
                        name=msg.name,
                        tool_call_id=msg.tool_call_id,
                        metadata=msg.metadata,
                    )
                safe.append(msg)
        return safe

    def validate_output(
        self,
        value: str,
        context: GuardContext | None = None,
    ) -> GuardResult:
        """Convenience method for validating LLM output."""
        return self.check(value, GuardStage.LLM_RESPONSE, context=context)

    # ── Async API ─────────────────────────────────────────────────────────────

    async def acheck(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext | None = None,
        protected_data: list[ProtectedData] | None = None,
        **kwargs: Any,
    ) -> GuardResult:
        """Async check. Runs synchronous rules in a thread pool."""
        ctx = context or self._make_context(stage, **kwargs)
        result = await asyncio.to_thread(
            self._evaluate_rules,
            value,
            stage,
            ctx,
            protected_data,
        )
        self._fire_alerts(result)
        if self._config.audit_enabled:
            await self._emit_audit(result)
        return result

    async def aprotect(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext | None = None,
        protected_data: list[ProtectedData] | None = None,
        **kwargs: Any,
    ) -> str:
        """Async protect. Raises GuardrailBlockedError if blocked."""
        result = await self.acheck(
            value,
            stage,
            context=context,
            protected_data=protected_data,
            **kwargs,
        )
        if result.is_blocked:
            raise GuardrailBlockedError(
                f"Content blocked at stage '{stage.value}'",
                stage=stage,
                findings=result.findings,
                score=result.score.value,
            )
        if result.action == GuardAction.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(
                f"Approval required at stage '{stage.value}'",
                stage=stage,
                findings=result.findings,
                request_id=result.context.request_id if result.context else None,
            )
        return result.output_value

    async def authorize_memory_write(
        self,
        value: str,
        *,
        persistent: bool = True,
        context: GuardContext | None = None,
    ) -> str:
        """Return a safe write value only after required out-of-band approval."""
        ctx = self._memory_write_context(context, persistent=persistent)
        result = await self.acheck(value, GuardStage.MEMORY_WRITE, context=ctx)
        if result.is_blocked:
            raise GuardrailBlockedError(
                "Memory write blocked by guardrail",
                stage=GuardStage.MEMORY_WRITE,
                findings=result.findings,
                score=result.score.value,
            )
        if result.action != GuardAction.REQUIRE_APPROVAL:
            return result.output_value
        if self._approval_provider is None:
            await self._emit_memory_approval_audit(
                result,
                action=GuardAction.BLOCK,
                outcome="missing_provider",
            )
            raise ApprovalRequiredError(
                "Persistent memory write requires an approval provider",
                stage=GuardStage.MEMORY_WRITE,
                findings=result.findings,
                request_id=ctx.request_id,
            )

        classification = next(
            (
                str(finding.metadata.get("classification", "unclassified"))
                for finding in result.findings
                if finding.rule_id == "MEM-001"
            ),
            "unclassified",
        )
        try:
            approved = await self._approval_provider.request_approval(
                result.output_value,
                context=ctx,
                reason=f"Persistent memory write classified as {classification}",
            )
        except Exception as exc:
            await self._emit_memory_approval_audit(
                result,
                action=GuardAction.BLOCK,
                outcome="provider_error",
            )
            raise ApprovalRequiredError(
                "Memory write approval provider failed; write not authorized",
                stage=GuardStage.MEMORY_WRITE,
                findings=result.findings,
                request_id=ctx.request_id,
                provider_error=type(exc).__name__,
            ) from exc
        if not approved:
            await self._emit_memory_approval_audit(
                result,
                action=GuardAction.BLOCK,
                outcome="denied",
            )
            raise GuardrailBlockedError(
                "Persistent memory write approval denied",
                stage=GuardStage.MEMORY_WRITE,
                findings=result.findings,
                score=result.score.value,
            )
        await self._emit_memory_approval_audit(
            result,
            action=GuardAction.ALLOW,
            outcome="approved",
        )
        return result.output_value

    # ── Streaming ─────────────────────────────────────────────────────────────

    def stream(
        self,
        stage: GuardStage = GuardStage.STREAM,
        context: GuardContext | None = None,
        protected_data: list[ProtectedData] | None = None,
    ) -> StreamScanner:
        """Create a StreamScanner for real-time chunk processing."""
        ctx = context or self._make_context(stage)
        rules = self._get_rules_for_stage(stage, protected_data)
        return StreamScanner(
            rules=rules,
            context=ctx,
            sensitive_data_mode=self._config.sensitive_data_mode,
            fail_mode=self._config.fail_mode,
            block_at=self._config.block_at,
            warn_at=self._config.warn_at,
        )

    # ── Session context managers ──────────────────────────────────────────────

    @asynccontextmanager
    async def session(self, context: GuardContext) -> AsyncIterator[GuardSession]:
        """Async context manager for a guard session."""
        sess = GuardSession(self, context)
        yield sess

    @asynccontextmanager
    async def agent_session(
        self,
        context: GuardContext,
        max_steps: int = 50,
        max_tool_calls: int = 100,
        max_depth: int = 10,
        max_duration_seconds: float = 300.0,
    ) -> AsyncIterator[AgentSession]:
        """Async context manager for an agent session."""
        from trustrail.agents.session import AgentSession as _AgentSession

        sess = _AgentSession(
            guard=self,
            context=context,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            max_depth=max_depth,
            max_duration_seconds=max_duration_seconds,
        )
        async with sess:
            yield sess

    # ── Alert hooks ───────────────────────────────────────────────────────────

    def on(self, severity: Severity, callback: Callable[[GuardResult], None]) -> None:
        """Register an alert callback for findings at or above the given severity."""
        self._alert_callbacks.append(_AlertCallback(severity=severity, callback=callback))

    def _fire_alerts(self, result: GuardResult) -> None:
        """Fire registered callbacks if findings meet threshold."""
        for cb in self._alert_callbacks:
            min_level = _SEVERITY_ORDER[cb.severity]
            if any(_SEVERITY_ORDER.get(f.severity, 0) >= min_level for f in result.findings):
                import contextlib

                with contextlib.suppress(Exception):
                    cb.callback(result)

    # ── Decorators ────────────────────────────────────────────────────────────

    def input(
        self,
        stage: GuardStage = GuardStage.USER_INPUT,
        raise_on_block: bool = True,
    ) -> Callable[[F], F]:
        """Decorator that checks the first string argument as user input."""

        def decorator(func: F) -> F:
            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    # Find first string arg
                    text = _first_string(args, kwargs)
                    if text is not None:
                        result = await self.acheck(text, stage)
                        if result.is_blocked and raise_on_block:
                            raise GuardrailBlockedError(
                                "Input blocked by guardrail",
                                stage=stage,
                                findings=result.findings,
                            )
                    return await func(*args, **kwargs)

                return async_wrapper  # type: ignore[return-value]
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    text = _first_string(args, kwargs)
                    if text is not None:
                        result = self.check(text, stage)
                        if result.is_blocked and raise_on_block:
                            raise GuardrailBlockedError(
                                "Input blocked by guardrail",
                                stage=stage,
                                findings=result.findings,
                            )
                    return func(*args, **kwargs)

                return sync_wrapper  # type: ignore[return-value]

        return decorator

    def output(
        self,
        stage: GuardStage = GuardStage.LLM_RESPONSE,
        raise_on_block: bool = True,
    ) -> Callable[[F], F]:
        """Decorator that checks the return value of a function."""

        def decorator(func: F) -> F:
            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    ret = await func(*args, **kwargs)
                    if isinstance(ret, str):
                        result = await self.acheck(ret, stage)
                        if result.is_blocked and raise_on_block:
                            raise GuardrailBlockedError(
                                "Output blocked by guardrail",
                                stage=stage,
                                findings=result.findings,
                            )
                        return result.output_value
                    return ret

                return async_wrapper  # type: ignore[return-value]
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    ret = func(*args, **kwargs)
                    if isinstance(ret, str):
                        result = self.check(ret, stage)
                        if result.is_blocked and raise_on_block:
                            raise GuardrailBlockedError(
                                "Output blocked by guardrail",
                                stage=stage,
                                findings=result.findings,
                            )
                        return result.output_value
                    return ret

                return sync_wrapper  # type: ignore[return-value]

        return decorator

    def tool(
        self,
        policy: str = "default",
        raise_on_block: bool = True,
    ) -> Callable[[F], F]:
        """Decorator that validates tool call arguments."""

        def decorator(func: F) -> F:
            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    func_name = func.__name__
                    ctx = GuardContext(
                        stage=GuardStage.TOOL_REQUEST,
                        metadata={
                            "tool_name": func_name,
                            "tool_args": kwargs,
                        },
                    )
                    result = await self.acheck(func_name, GuardStage.TOOL_REQUEST, context=ctx)
                    if result.is_blocked and raise_on_block:
                        raise GuardrailBlockedError(
                            f"Tool call '{func_name}' blocked",
                            stage=GuardStage.TOOL_REQUEST,
                            findings=result.findings,
                        )
                    return await func(*args, **kwargs)

                return async_wrapper  # type: ignore[return-value]
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    func_name = func.__name__
                    ctx = GuardContext(
                        stage=GuardStage.TOOL_REQUEST,
                        metadata={
                            "tool_name": func_name,
                            "tool_args": kwargs,
                        },
                    )
                    result = self.check(func_name, GuardStage.TOOL_REQUEST, context=ctx)
                    if result.is_blocked and raise_on_block:
                        raise GuardrailBlockedError(
                            f"Tool call '{func_name}' blocked",
                            stage=GuardStage.TOOL_REQUEST,
                            findings=result.findings,
                        )
                    return func(*args, **kwargs)

                return sync_wrapper  # type: ignore[return-value]

        return decorator

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_context(
        self,
        stage: GuardStage,
        trust_level: TrustLevel = TrustLevel.UNTRUSTED,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> GuardContext:
        return GuardContext(
            stage=stage,
            trust_level=trust_level,
            metadata=metadata or {},
        )

    def _document_context(
        self,
        document: Document,
        *,
        stage: GuardStage,
        context: GuardContext | None,
    ) -> GuardContext:
        """Merge caller correlation with immutable document provenance.

        Caller metadata wins ordinary flat-key collisions. Reserved document
        fields and the complete ``document_metadata`` namespace are always
        derived from the Document object.
        """
        base = context or GuardContext()
        metadata: dict[str, Any] = {
            **document.metadata,
            **base.metadata,
            "document_id": document.id,
            "source": document.source,
            "source_url": document.source_url,
            "document_metadata": dict(document.metadata),
        }
        return base.model_copy(
            update={
                "stage": stage,
                "trust_level": document.trust_level,
                "metadata": metadata,
            }
        )

    def _memory_write_context(
        self,
        context: GuardContext | None,
        *,
        persistent: bool,
    ) -> GuardContext:
        """Copy caller context while applying authoritative write metadata."""
        if context is None:
            return self._make_context(
                GuardStage.MEMORY_WRITE,
                metadata={"persistent": persistent},
            )
        return context.model_copy(
            update={
                "stage": GuardStage.MEMORY_WRITE,
                "metadata": {**context.metadata, "persistent": persistent},
            }
        )

    async def _emit_audit(self, result: GuardResult) -> None:
        import contextlib

        event = AuditEvent.from_result(result)
        with contextlib.suppress(Exception):
            await self._audit_sink.emit(event)

    async def _emit_memory_approval_audit(
        self,
        result: GuardResult,
        *,
        action: GuardAction,
        outcome: Literal["approved", "denied", "missing_provider", "provider_error"],
    ) -> None:
        """Emit a content-free terminal event for the approval decision."""
        if not self._config.audit_enabled:
            return
        import contextlib

        event = AuditEvent.from_result(result.model_copy(update={"action": action}))
        event.memory_approval_outcome = outcome
        with contextlib.suppress(Exception):
            await self._audit_sink.emit(event)

    def _emit_audit_sync(self, result: GuardResult) -> None:
        import contextlib

        event = AuditEvent.from_result(result)
        with contextlib.suppress(Exception):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._audit_sink.emit(event))  # noqa: RUF006
            except RuntimeError:
                asyncio.run(self._audit_sink.emit(event))


def _first_string(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    """Find the first string argument in args or kwargs."""
    for arg in args:
        if isinstance(arg, str):
            return arg
    for val in kwargs.values():
        if isinstance(val, str):
            return val
    return None
