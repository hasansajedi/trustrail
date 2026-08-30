"""trustrail Guard Engine.

The central entry point for all guardrail evaluation.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import queue
import threading
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from pathlib import PurePath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, TypeVar, get_type_hints

from pydantic import BaseModel, TypeAdapter, ValidationError

if TYPE_CHECKING:
    from trustrail.agents.session import AgentSession

from trustrail.audit import AuditEvent, LoggingAuditSink, NullAuditSink
from trustrail.exceptions import (
    ApprovalRequiredError,
    ConfigurationError,
    GuardrailBlockedError,
    ResourceLimitError,
)
from trustrail.models.config import GuardConfig, GuardPolicy, RuleConfig
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
from trustrail.policies.base import BasePolicy
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
ArgumentNameSelection = str | Sequence[str]
ArgumentSelector = ArgumentNameSelection | Callable[[Mapping[str, Any]], ArgumentNameSelection]
ArgumentSerializer = Callable[[Any], str]
ArgumentDeserializer = Callable[[str], Any]

_DEFAULT_DECORATOR_MAX_CHARS = 10_000
_DECORATOR_MAX_DEPTH = 8
_DECORATOR_MAX_ITEMS = 1_000


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

_MESSAGE_ROLE_STAGES: dict[str, GuardStage] = {
    "system": GuardStage.SYSTEM_PROMPT,
    "developer": GuardStage.SYSTEM_PROMPT,
    "user": GuardStage.USER_INPUT,
    "assistant": GuardStage.LLM_RESPONSE,
    "tool": GuardStage.TOOL_RESPONSE,
}

_SAFE_MESSAGE_ACTIONS = {
    GuardAction.ALLOW,
    GuardAction.WARN,
    GuardAction.REDACT,
    GuardAction.TRANSFORM,
}


@dataclass
class _RuleOverride:
    """Merged policy and rule controls for one runtime rule instance."""

    enabled: bool | None = None
    action: GuardAction | None = None
    severity: Severity | None = None
    threshold: float | None = None
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _ArgumentTarget:
    """Location of one selected value within inspect.BoundArguments."""

    parameter: str
    item: int | str | None = None


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
        self._policy_fail_modes: dict[str, FailMode] = {}
        self._policies = self._build_policies()
        self._policy_rules: dict[str, tuple[BaseRule, ...]] = {}
        self._standalone_rules: tuple[BaseRule, ...] = ()
        self._configured_extra_rules: tuple[BaseRule, ...] = ()
        self._build_rule_cache()

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

    def _build_policies(self) -> dict[str, BasePolicy]:
        cfg = self._config
        definitions: dict[str, tuple[type[BasePolicy], dict[str, Any]]] = {
            "prompt_injection": (PromptInjectionPolicy, {}),
            "sensitive_data": (SensitiveDataPolicy, {}),
            "supply_chain": (SupplyChainPolicy, {}),
            "output_safety": (OutputSafetyPolicy, {}),
            "content_safety": (ContentSafetyPolicy, {}),
            "resource": (ResourcePolicy, {"max_chars": cfg.max_text_length}),
            "rag": (RAGPolicy, {"require_context_labels": cfg.require_rag_context_labels}),
            "memory": (MemoryPolicy, {"require_approval": cfg.require_memory_write_approval}),
            "tools": (ToolPolicy, {}),
            "agent": (AgentPolicy, {}),
        }
        unknown = sorted(set(cfg.policies) - set(definitions))
        if unknown:
            raise ConfigurationError(
                f"Unknown policy ID(s): {', '.join(unknown)}. "
                f"Valid policy IDs: {', '.join(definitions)}"
            )

        policies: dict[str, BasePolicy] = {}
        for policy_id, (policy_type, defaults) in definitions.items():
            policy_config = cfg.policies.get(policy_id, GuardPolicy())
            params = self._validate_params(
                policy_type.__init__,
                policy_config.params,
                label=f"policy '{policy_id}'",
                excluded={"enabled"},
            )
            kwargs = {**defaults, **params, "enabled": policy_config.enabled}
            try:
                policies[policy_id] = policy_type(**kwargs)
            except Exception as exc:
                raise ConfigurationError(
                    f"Invalid parameters for policy '{policy_id}': {exc}"
                ) from exc
            self._policy_fail_modes[policy_id] = (
                policy_config.fail_mode
                if "fail_mode" in policy_config.model_fields_set
                else cfg.fail_mode
            )
        return policies

    def _validate_params(
        self,
        target: Callable[..., Any],
        params: dict[str, Any],
        *,
        label: str,
        excluded: set[str] | None = None,
    ) -> dict[str, Any]:
        """Reject unsupported parameters and validate annotated values."""
        signature = inspect.signature(target)
        excluded = excluded or set()
        allowed = {
            name
            for name, parameter in signature.parameters.items()
            if name not in {"self", *excluded}
            and parameter.kind
            not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        }
        unsupported = sorted(set(params) - allowed)
        if unsupported:
            raise ConfigurationError(
                f"Unsupported parameter(s) for {label}: {', '.join(unsupported)}. "
                f"Supported parameters: {', '.join(sorted(allowed)) or 'none'}"
            )

        try:
            hints = get_type_hints(target)
        except (NameError, TypeError):
            hints = {}
        validated: dict[str, Any] = {}
        for name, value in params.items():
            annotation = hints.get(name, signature.parameters[name].annotation)
            if annotation is inspect.Parameter.empty:
                validated[name] = value
                continue
            try:
                validated[name] = TypeAdapter(annotation).validate_python(value)
            except ValidationError as exc:
                raise ConfigurationError(
                    f"Invalid value for {label} parameter '{name}': {value!r}"
                ) from exc
        return validated

    def _merge_rule_override(
        self,
        policy_config: GuardPolicy | None,
        rule_id: str,
    ) -> _RuleOverride:
        merged = _RuleOverride()
        if policy_config is not None and "default_action" in policy_config.model_fields_set:
            merged.action = policy_config.default_action
        configs: list[RuleConfig] = []
        if policy_config is not None and rule_id in policy_config.rules:
            configs.append(policy_config.rules[rule_id])
        if rule_id in self._config.rule_overrides:
            configs.append(self._config.rule_overrides[rule_id])
        for rule_config in configs:
            fields = rule_config.model_fields_set
            if "enabled" in fields:
                merged.enabled = rule_config.enabled
            if "action" in fields:
                merged.action = rule_config.action
            if "severity_override" in fields:
                merged.severity = rule_config.severity_override
            if "threshold" in fields:
                merged.threshold = rule_config.threshold
            if "params" in fields:
                merged.params.update(rule_config.params)
        return merged

    def _rebuild_rule(
        self,
        rule: BaseRule,
        params: dict[str, Any],
    ) -> BaseRule:
        if not params:
            return rule
        constructor = type(rule).__init__
        validated = self._validate_params(
            constructor,
            params,
            label=f"rule '{rule.rule_id}'",
            excluded={"enabled"},
        )
        signature = inspect.signature(constructor)
        kwargs: dict[str, Any] = {}
        if "enabled" in signature.parameters:
            kwargs["enabled"] = rule.enabled
        for name, parameter in signature.parameters.items():
            if name in {"self", "enabled"} or name in validated:
                continue
            if hasattr(rule, name):
                kwargs[name] = getattr(rule, name)
            elif parameter.default is inspect.Parameter.empty:
                raise ConfigurationError(
                    f"Rule '{rule.rule_id}' parameter '{name}' cannot be overridden safely"
                )
        kwargs.update(validated)
        try:
            return type(rule)(**kwargs)
        except Exception as exc:
            raise ConfigurationError(
                f"Invalid parameters for rule '{rule.rule_id}': {exc}"
            ) from exc

    def _configure_rule(
        self,
        rule: BaseRule,
        *,
        policy_id: str | None = None,
    ) -> BaseRule:
        policy_config = self._config.policies.get(policy_id) if policy_id else None
        override = self._merge_rule_override(policy_config, rule.rule_id)
        rule = self._rebuild_rule(rule, override.params)
        if override.enabled is not None:
            rule.enabled = override.enabled
        rule.configure(
            action=override.action,
            severity=override.severity,
            threshold=override.threshold,
            fail_mode=(
                self._policy_fail_modes[policy_id]
                if policy_id is not None
                else self._config.fail_mode
            ),
        )
        return rule

    def _category_enabled(self, category: RuleCategory) -> bool:
        enabled = self._config.enabled_categories
        if enabled is not None and category not in enabled:
            return False
        return category not in self._config.disabled_categories

    def _build_rule_cache(self) -> None:
        """Build and configure every reusable rule instance exactly once."""
        known_rule_ids: set[str] = set()
        for policy_id, policy in self._policies.items():
            policy_config = self._config.policies.get(policy_id)
            raw_rules = policy.get_rules()
            policy_rule_ids = {rule.rule_id for rule in raw_rules}
            if policy_config is not None:
                unknown = sorted(set(policy_config.rules) - policy_rule_ids)
                if unknown:
                    raise ConfigurationError(
                        f"Unknown or inactive rule ID(s) for policy '{policy_id}': "
                        f"{', '.join(unknown)}. Active rule IDs: "
                        f"{', '.join(sorted(policy_rule_ids)) or 'none'}"
                    )
            configured = tuple(
                self._configure_rule(rule, policy_id=policy_id) for rule in raw_rules
            )
            self._policy_rules[policy_id] = tuple(
                rule
                for rule in configured
                if policy.enabled and self._category_enabled(rule.category)
            )
            known_rule_ids.update(rule.rule_id for rule in configured)

        standalone: list[BaseRule] = []
        if self._config.strip_invisible_unicode:
            standalone.append(InvisibleUnicodeRule())
        from trustrail.rules.url import (
            EmbeddedCredentialRule,
            MetadataServiceRule,
            PrivateIpRule,
            SchemeValidationRule,
        )

        standalone.extend(
            [
                SchemeValidationRule(),
                PrivateIpRule(),
                MetadataServiceRule(),
                EmbeddedCredentialRule(),
            ]
        )
        configured_standalone = tuple(self._configure_rule(rule) for rule in standalone)
        self._standalone_rules = tuple(
            rule for rule in configured_standalone if self._category_enabled(rule.category)
        )
        known_rule_ids.update(rule.rule_id for rule in configured_standalone)
        configured_extra = tuple(self._configure_rule(rule) for rule in self._extra_rules)
        self._configured_extra_rules = tuple(
            rule for rule in configured_extra if self._category_enabled(rule.category)
        )
        known_rule_ids.update(rule.rule_id for rule in configured_extra)
        # SD-017 is constructed per request because its protected values are
        # caller supplied; its runtime controls are still validated here.
        known_rule_ids.add("SD-017")
        unknown_global = sorted(set(self._config.rule_overrides) - known_rule_ids)
        if unknown_global:
            raise ConfigurationError(
                f"Unknown or inactive rule ID(s): {', '.join(unknown_global)}. "
                f"Active rule IDs: {', '.join(sorted(known_rule_ids))}"
            )
        dynamic_override = self._config.rule_overrides.get("SD-017")
        if dynamic_override and dynamic_override.params:
            raise ConfigurationError("Rule 'SD-017' does not support configurable parameters")

    # ── Core evaluation ───────────────────────────────────────────────────────

    def _get_rules_for_stage(
        self,
        stage: GuardStage,
        protected_data: list[ProtectedData] | None = None,
    ) -> list[BaseRule]:
        """Return the rules applicable to a given pipeline stage."""
        rules = list(self._policy_rules["resource"])
        invisible_rules = [rule for rule in self._standalone_rules if rule.rule_id == "PI-016"]
        rules.extend(invisible_rules)

        def add_policy(policy_id: str) -> None:
            rules.extend(self._policy_rules[policy_id])

        if stage in (
            GuardStage.USER_INPUT,
            GuardStage.LLM_REQUEST,
        ):
            add_policy("prompt_injection")
            add_policy("sensitive_data")
            rules.extend(
                rule for rule in self._standalone_rules if rule.category == RuleCategory.URL_SSRF
            )

        elif stage in (GuardStage.SYSTEM_PROMPT,):
            add_policy("sensitive_data")

        elif stage in (
            GuardStage.LLM_RESPONSE,
            GuardStage.FINAL_OUTPUT,
            GuardStage.STREAM,
        ):
            add_policy("output_safety")
            add_policy("content_safety")
            add_policy("sensitive_data")

        elif stage in (
            GuardStage.RAG_DOCUMENT,
            GuardStage.EXTERNAL_CONTENT,
            GuardStage.RAG_CONTEXT,
        ):
            add_policy("prompt_injection")
            add_policy("rag")
            add_policy("supply_chain")
            add_policy("sensitive_data")

        elif stage in (GuardStage.TOOL_REQUEST,):
            add_policy("tools")
            add_policy("prompt_injection")
            add_policy("sensitive_data")

        elif stage in (GuardStage.TOOL_RESPONSE,):
            add_policy("supply_chain")
            add_policy("prompt_injection")
            add_policy("output_safety")
            add_policy("sensitive_data")

        elif stage in (GuardStage.AGENT_ACTION,):
            add_policy("agent")
            add_policy("prompt_injection")
            add_policy("sensitive_data")

        elif stage == GuardStage.MEMORY_READ:
            add_policy("prompt_injection")
            add_policy("sensitive_data")

        elif stage == GuardStage.MEMORY_WRITE:
            add_policy("prompt_injection")
            add_policy("sensitive_data")
            add_policy("memory")

        rules.extend(self._configured_extra_rules)
        if protected_data:
            dynamic_rule = self._configure_rule(ProtectedDataDisclosureRule(protected_data))
            if self._category_enabled(dynamic_rule.category):
                rules.append(dynamic_rule)

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
        requested_actions: set[GuardAction] = set()
        handled_finding_ids: set[int] = set()

        for rule in rules:
            if not rule.enabled:
                continue
            try:
                decision = rule.timed_evaluate(current_value, context)
                policy_handled = decision.suppress_risk or self._apply_sensitive_data_mode(decision)
                if decision.finding is not None:
                    findings.append(decision.finding)
                    if policy_handled:
                        handled_finding_ids.add(id(decision.finding))
                if decision.action != GuardAction.TRANSFORM or decision.suppress_risk:
                    requested_actions.add(decision.action)

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
                if (rule.fail_mode or self._config.fail_mode) == FailMode.CLOSED:
                    requested_actions.add(GuardAction.BLOCK)
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
            requested_actions,
            handled_finding_ids,
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
        requested_actions: set[GuardAction] | None = None,
        handled_finding_ids: set[int] | None = None,
    ) -> GuardAction:
        """Determine final action from score, findings, and rule decisions."""
        handled_ids = handled_finding_ids or set()
        actions = requested_actions or set()
        actionable_findings = [finding for finding in findings if id(finding) not in handled_ids]

        # Check for critical findings — always block
        for f in actionable_findings:
            if f.severity == Severity.CRITICAL:
                return GuardAction.BLOCK

        # If any rule explicitly requested BLOCK, honor it
        if GuardAction.BLOCK in actions:
            return GuardAction.BLOCK

        actionable_score = RiskScore.from_findings(
            actionable_findings,
            block_at=score.block_at,
            warn_at=score.warn_at,
        )
        if actionable_score.should_block:
            return GuardAction.BLOCK

        if GuardAction.QUARANTINE in actions:
            return GuardAction.QUARANTINE

        if GuardAction.REQUIRE_APPROVAL in actions:
            return GuardAction.REQUIRE_APPROVAL

        if GuardAction.RETRY in actions:
            return GuardAction.RETRY

        if actionable_score.should_warn or GuardAction.WARN in actions:
            return GuardAction.WARN

        # Check if any HIGH finding warrants a warning
        for f in actionable_findings:
            if f.severity == Severity.HIGH:
                return GuardAction.WARN

        if GuardAction.REDACT in actions:
            return GuardAction.REDACT

        if GuardAction.TRANSFORM in actions:
            return GuardAction.TRANSFORM

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

    def _timeout_result(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext,
        started_at: float,
    ) -> GuardResult:
        fail_closed = self._config.fail_mode == FailMode.CLOSED
        finding = GuardFinding(
            rule_id="SYS-001",
            rule_name="Evaluation timeout",
            category=RuleCategory.RESOURCE,
            severity=Severity.HIGH,
            message=(
                "Guard evaluation timed out (fail-closed)"
                if fail_closed
                else "Guard evaluation timed out (fail-open)"
            ),
            metadata={"timeout_seconds": self._config.timeout_seconds},
        )
        return GuardResult(
            action=GuardAction.BLOCK if fail_closed else GuardAction.WARN,
            findings=[finding],
            score=RiskScore.from_findings(
                [finding],
                block_at=self._config.block_at,
                warn_at=self._config.warn_at,
            ),
            value=value,
            input_length=len(value),
            stage=stage,
            context=context,
            latency_ms=(time.perf_counter() - started_at) * 1000,
        )

    def _evaluate_with_timeout(
        self,
        value: str,
        stage: GuardStage,
        context: GuardContext,
        protected_data: list[ProtectedData] | None = None,
    ) -> GuardResult:
        """Run one complete evaluation with a hard caller-facing deadline."""
        started_at = time.perf_counter()
        outcomes: queue.Queue[tuple[bool, GuardResult | BaseException]] = queue.Queue(maxsize=1)

        def evaluate() -> None:
            try:
                outcomes.put((True, self._evaluate_rules(value, stage, context, protected_data)))
            except BaseException as exc:  # propagate unexpected engine failures
                outcomes.put((False, exc))

        worker = threading.Thread(target=evaluate, name="trustrail-evaluation", daemon=True)
        worker.start()
        try:
            succeeded, outcome = outcomes.get(timeout=self._config.timeout_seconds)
        except queue.Empty:
            return self._timeout_result(value, stage, context, started_at)
        if succeeded:
            if not isinstance(outcome, GuardResult):
                raise RuntimeError("Invalid guard evaluation result")
            return outcome
        if isinstance(outcome, BaseException):
            raise outcome
        raise RuntimeError("Invalid guard evaluation failure")

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
        result = self._evaluate_with_timeout(value, stage, ctx, protected_data)
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
        *,
        role_stages: Mapping[str, GuardStage] | None = None,
    ) -> list[Message]:
        """Return an order-preserving safe conversation or reject it atomically.

        Supported roles have fixed security boundaries. Unknown roles require an
        explicit ``role_stages`` entry. No partial list is returned when a
        message is blocked or requires approval.
        """
        protected: list[Message] = []
        base_context = context or GuardContext()
        for index, message in enumerate(messages):
            stage = self._message_stage(message.role, index=index, role_stages=role_stages)
            result = self.check(
                message.content,
                stage,
                context=self._message_context(
                    message,
                    index=index,
                    message_count=len(messages),
                    stage=stage,
                    base_context=base_context,
                ),
            )
            if result.action == GuardAction.REQUIRE_APPROVAL:
                raise ApprovalRequiredError(
                    f"Conversation message at index {index} with role "
                    f"'{message.role}' requires approval",
                    stage=stage,
                    request_id=result.context.request_id if result.context else None,
                    message_index=index,
                    message_role=message.role,
                    tool_call_id=message.tool_call_id,
                    findings=result.findings,
                )
            if result.action not in _SAFE_MESSAGE_ACTIONS:
                raise GuardrailBlockedError(
                    f"Conversation message at index {index} with role '{message.role}' blocked",
                    stage=stage,
                    findings=result.findings,
                    score=result.score.value,
                    message_index=index,
                    message_role=message.role,
                    tool_call_id=message.tool_call_id,
                    action=result.action.value,
                )
            protected.append(self._transformed_message(message, result))
        return protected

    def filter_messages(
        self,
        messages: list[Message],
        context: GuardContext | None = None,
        *,
        role_stages: Mapping[str, GuardStage] | None = None,
    ) -> list[Message]:
        """Explicitly omit rejected messages and return transformed safe entries.

        Filtering can break conversation semantics and tool-call relationships;
        use ``protect_messages`` unless partial-conversation behavior is an
        intentional, reviewed application policy.
        """
        filtered: list[Message] = []
        base_context = context or GuardContext()
        for index, message in enumerate(messages):
            stage = self._message_stage(message.role, index=index, role_stages=role_stages)
            result = self.check(
                message.content,
                stage,
                context=self._message_context(
                    message,
                    index=index,
                    message_count=len(messages),
                    stage=stage,
                    base_context=base_context,
                ),
            )
            if result.action in _SAFE_MESSAGE_ACTIONS:
                filtered.append(self._transformed_message(message, result))
        return filtered

    def _message_stage(
        self,
        role: str,
        *,
        index: int,
        role_stages: Mapping[str, GuardStage] | None,
    ) -> GuardStage:
        built_in = _MESSAGE_ROLE_STAGES.get(role)
        supplied = role_stages.get(role) if role_stages is not None else None
        supplied_stage: GuardStage | None = None
        if supplied is not None:
            try:
                supplied_stage = GuardStage(supplied)
            except ValueError as exc:
                raise ConfigurationError(
                    f"Invalid guard stage for message role '{role}': {supplied!r}"
                ) from exc
        if built_in is not None:
            if supplied_stage is not None and supplied_stage != built_in:
                raise ConfigurationError(
                    f"Built-in message role '{role}' must map to stage '{built_in.value}'"
                )
            return built_in
        if supplied_stage is None:
            raise ConfigurationError(
                f"Unknown message role '{role}' at index {index}; provide an explicit "
                "role_stages mapping"
            )
        return supplied_stage

    def _message_context(
        self,
        message: Message,
        *,
        index: int,
        message_count: int,
        stage: GuardStage,
        base_context: GuardContext,
    ) -> GuardContext:
        metadata: dict[str, Any] = {
            **base_context.metadata,
            **message.metadata,
            "message_metadata": dict(message.metadata),
            "message_count": message_count,
            "message_index": index,
            "message_role": message.role,
        }
        if message.name is not None:
            metadata["message_name"] = message.name
        if message.tool_call_id is not None:
            metadata["tool_call_id"] = message.tool_call_id
        return base_context.model_copy(update={"stage": stage, "metadata": metadata})

    def _transformed_message(self, message: Message, result: GuardResult) -> Message:
        if result.output_value == message.content:
            return message
        return message.model_copy(update={"content": result.output_value})

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
            self._evaluate_with_timeout,
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
        *,
        selector: ArgumentSelector | None = None,
        serializer: ArgumentSerializer | None = None,
        deserializer: ArgumentDeserializer | None = None,
        max_serialized_chars: int = _DEFAULT_DECORATOR_MAX_CHARS,
    ) -> Callable[[F], F]:
        """Validate a bound input argument and forward its safe transformed value.

        By default the first string value is selected after binding positional,
        keyword, variadic, and defaulted arguments. ``selector`` can name one or
        more parameters, or derive those names from the bound argument mapping.
        Structured selections require a ``deserializer`` whenever a guard rule
        transforms their serialized representation.
        """

        _validate_decorator_limit(max_serialized_chars)

        def decorator(func: F) -> F:
            signature = inspect.signature(func)

            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = _bind_decorator_arguments(signature, args, kwargs)
                    targets = _select_input_targets(signature, bound, selector)
                    if targets:
                        payload = _selection_payload(bound, targets)
                        text = _serialize_decorator_payload(
                            payload,
                            serializer=serializer,
                            max_chars=max_serialized_chars,
                        )
                        result = await self.acheck(text, stage)
                        self._enforce_decorator_result(
                            result,
                            stage=stage,
                            message="Input blocked by guardrail",
                            raise_on_block=raise_on_block,
                        )
                        _apply_decorator_transformation(
                            bound,
                            targets,
                            payload=payload,
                            serialized=text,
                            transformed=result.output_value,
                            serializer=serializer,
                            deserializer=deserializer,
                        )
                    return await func(*bound.args, **bound.kwargs)

                return async_wrapper  # type: ignore[return-value]
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = _bind_decorator_arguments(signature, args, kwargs)
                    targets = _select_input_targets(signature, bound, selector)
                    if targets:
                        payload = _selection_payload(bound, targets)
                        text = _serialize_decorator_payload(
                            payload,
                            serializer=serializer,
                            max_chars=max_serialized_chars,
                        )
                        result = self.check(text, stage)
                        self._enforce_decorator_result(
                            result,
                            stage=stage,
                            message="Input blocked by guardrail",
                            raise_on_block=raise_on_block,
                        )
                        _apply_decorator_transformation(
                            bound,
                            targets,
                            payload=payload,
                            serialized=text,
                            transformed=result.output_value,
                            serializer=serializer,
                            deserializer=deserializer,
                        )
                    return func(*bound.args, **bound.kwargs)

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
                        self._enforce_decorator_result(
                            result,
                            stage=stage,
                            message="Output blocked by guardrail",
                            raise_on_block=raise_on_block,
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
                        self._enforce_decorator_result(
                            result,
                            stage=stage,
                            message="Output blocked by guardrail",
                            raise_on_block=raise_on_block,
                        )
                        return result.output_value
                    return ret

                return sync_wrapper  # type: ignore[return-value]

        return decorator

    def tool(
        self,
        policy: str = "default",
        raise_on_block: bool = True,
        *,
        max_serialized_chars: int = _DEFAULT_DECORATOR_MAX_CHARS,
    ) -> Callable[[F], F]:
        """Decorator that validates fully bound tool call arguments.

        ``default`` is a backwards-compatible alias for the configured
        ``tools`` policy. Any other policy name is rejected during decoration.
        """

        _validate_decorator_limit(max_serialized_chars)
        policy_id = self._resolve_tool_decorator_policy(policy)

        def decorator(func: F) -> F:
            signature = inspect.signature(func)

            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = _bind_decorator_arguments(signature, args, kwargs)
                    func_name = func.__name__
                    ctx = GuardContext(
                        stage=GuardStage.TOOL_REQUEST,
                        metadata={
                            "tool_name": func_name,
                            "tool_args": _bound_tool_arguments(
                                signature,
                                bound,
                                max_chars=max_serialized_chars,
                            ),
                            "tool_policy": policy_id,
                        },
                    )
                    result = await self.acheck(func_name, GuardStage.TOOL_REQUEST, context=ctx)
                    self._enforce_decorator_result(
                        result,
                        stage=GuardStage.TOOL_REQUEST,
                        message=f"Tool call '{func_name}' blocked",
                        raise_on_block=raise_on_block,
                    )
                    return await func(*args, **kwargs)

                return async_wrapper  # type: ignore[return-value]
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    bound = _bind_decorator_arguments(signature, args, kwargs)
                    func_name = func.__name__
                    ctx = GuardContext(
                        stage=GuardStage.TOOL_REQUEST,
                        metadata={
                            "tool_name": func_name,
                            "tool_args": _bound_tool_arguments(
                                signature,
                                bound,
                                max_chars=max_serialized_chars,
                            ),
                            "tool_policy": policy_id,
                        },
                    )
                    result = self.check(func_name, GuardStage.TOOL_REQUEST, context=ctx)
                    self._enforce_decorator_result(
                        result,
                        stage=GuardStage.TOOL_REQUEST,
                        message=f"Tool call '{func_name}' blocked",
                        raise_on_block=raise_on_block,
                    )
                    return func(*args, **kwargs)

                return sync_wrapper  # type: ignore[return-value]

        return decorator

    def _resolve_tool_decorator_policy(self, policy: str) -> str:
        policy_id = "tools" if policy == "default" else policy
        selected = self._policies.get(policy_id)
        if policy_id != "tools" or not isinstance(selected, ToolPolicy):
            raise ConfigurationError(
                f"Unknown tool decorator policy: '{policy}'. "
                "Use 'default' or the configured 'tools' policy."
            )
        return policy_id

    def _enforce_decorator_result(
        self,
        result: GuardResult,
        *,
        stage: GuardStage,
        message: str,
        raise_on_block: bool,
    ) -> None:
        if result.action == GuardAction.REQUIRE_APPROVAL:
            raise ApprovalRequiredError(
                message.replace("blocked", "requires approval"),
                stage=stage,
                findings=result.findings,
                request_id=result.context.request_id if result.context else None,
            )
        if not raise_on_block:
            return
        if result.action in (GuardAction.BLOCK, GuardAction.QUARANTINE, GuardAction.RETRY):
            raise GuardrailBlockedError(
                message,
                stage=stage,
                findings=result.findings,
                score=result.score.value,
            )

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

        event = AuditEvent.from_result(
            result,
            include_metadata=self._config.audit_include_metadata,
        )
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

        event = AuditEvent.from_result(
            result.model_copy(update={"action": action}),
            include_metadata=self._config.audit_include_metadata,
        )
        event.memory_approval_outcome = outcome
        with contextlib.suppress(Exception):
            await self._audit_sink.emit(event)

    def _emit_audit_sync(self, result: GuardResult) -> None:
        import contextlib

        event = AuditEvent.from_result(
            result,
            include_metadata=self._config.audit_include_metadata,
        )
        with contextlib.suppress(Exception):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._audit_sink.emit(event))  # noqa: RUF006
            except RuntimeError:
                asyncio.run(self._audit_sink.emit(event))


def _validate_decorator_limit(max_chars: int) -> None:
    if max_chars < 1:
        raise ConfigurationError("max_serialized_chars must be at least 1")


def _bind_decorator_arguments(
    signature: inspect.Signature,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> inspect.BoundArguments:
    """Bind a call exactly as Python will and materialize declared defaults."""
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    return bound


def _select_input_targets(
    signature: inspect.Signature,
    bound: inspect.BoundArguments,
    selector: ArgumentSelector | None,
) -> list[_ArgumentTarget]:
    if selector is None:
        for name, parameter in signature.parameters.items():
            if name in {"self", "cls"}:
                continue
            value = bound.arguments[name]
            if isinstance(value, str):
                return [_ArgumentTarget(name)]
            if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                for index, item in enumerate(value):
                    if isinstance(item, str):
                        return [_ArgumentTarget(name, index)]
            elif parameter.kind == inspect.Parameter.VAR_KEYWORD:
                for key in sorted(value):
                    if isinstance(value[key], str):
                        return [_ArgumentTarget(name, key)]
        return []

    public_arguments = MappingProxyType(
        {name: value for name, value in bound.arguments.items() if name not in {"self", "cls"}}
    )
    selected = selector(public_arguments) if callable(selector) else selector
    if isinstance(selected, str):
        names = [selected]
    elif isinstance(selected, Sequence) and not isinstance(selected, (bytes, bytearray)):
        names = list(selected)
    else:
        raise ConfigurationError("input selector must return a parameter name or sequence of names")
    if not names or any(not isinstance(name, str) for name in names):
        raise ConfigurationError("input selector must choose at least one valid parameter name")

    targets: list[_ArgumentTarget] = []
    for name in names:
        if name in {"self", "cls"}:
            raise ConfigurationError(f"input selector cannot select '{name}'")
        if name in bound.arguments:
            targets.append(_ArgumentTarget(name))
            continue
        variadic_keyword = next(
            (
                parameter_name
                for parameter_name, parameter in signature.parameters.items()
                if parameter.kind == inspect.Parameter.VAR_KEYWORD
                and name in bound.arguments[parameter_name]
            ),
            None,
        )
        if variadic_keyword is None:
            raise ConfigurationError(f"input selector chose unknown argument '{name}'")
        targets.append(_ArgumentTarget(variadic_keyword, name))
    if len({(target.parameter, target.item) for target in targets}) != len(targets):
        raise ConfigurationError("input selector returned duplicate argument names")
    return targets


def _target_label(target: _ArgumentTarget) -> str:
    return target.item if isinstance(target.item, str) else target.parameter


def _target_value(bound: inspect.BoundArguments, target: _ArgumentTarget) -> Any:
    value = bound.arguments[target.parameter]
    return value if target.item is None else value[target.item]


def _selection_payload(
    bound: inspect.BoundArguments,
    targets: list[_ArgumentTarget],
) -> Any:
    if len(targets) == 1:
        return _target_value(bound, targets[0])
    return {_target_label(target): _target_value(bound, target) for target in targets}


def _serialize_decorator_payload(
    payload: Any,
    *,
    serializer: ArgumentSerializer | None,
    max_chars: int,
) -> str:
    if serializer is not None:
        try:
            serialized = serializer(payload)
        except Exception as exc:
            raise ConfigurationError(f"input serializer failed: {type(exc).__name__}") from exc
        if not isinstance(serialized, str):
            raise ConfigurationError("input serializer must return str")
    elif isinstance(payload, str):
        serialized = payload
    else:
        normalized = _bounded_decorator_value(payload, max_chars=max_chars)
        serialized = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    if len(serialized) > max_chars:
        raise ResourceLimitError(
            f"Decorator payload contains {len(serialized)} characters; limit is {max_chars}"
        )
    return serialized


def _bounded_decorator_value(
    value: Any,
    *,
    max_chars: int,
    depth: int = 0,
    budget: list[int] | None = None,
) -> Any:
    """Create a deterministic JSON-compatible value under strict bounds."""
    if budget is None:
        budget = [_DECORATOR_MAX_ITEMS]
    budget[0] -= 1
    if budget[0] < 0:
        raise ResourceLimitError(f"Decorator payload exceeds the {_DECORATOR_MAX_ITEMS}-item limit")
    if depth > _DECORATOR_MAX_DEPTH:
        raise ResourceLimitError(
            f"Decorator payload exceeds the maximum depth of {_DECORATOR_MAX_DEPTH}"
        )
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > max_chars:
            raise ResourceLimitError(
                f"Decorator string contains {len(value)} characters; limit is {max_chars}"
            )
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Enum):
        return _bounded_decorator_value(
            value.value,
            max_chars=max_chars,
            depth=depth + 1,
            budget=budget,
        )
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif is_dataclass(value) and not isinstance(value, type):
        value = {item.name: getattr(value, item.name) for item in fields(value)}
    if isinstance(value, Mapping):
        normalized_items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, (str, int, float, bool, Enum)):
                raise ConfigurationError(
                    "Decorator mappings require scalar keys; provide an explicit serializer"
                )
            normalized_key = str(key.value if isinstance(key, Enum) else key)
            normalized_items.append(
                (
                    normalized_key,
                    _bounded_decorator_value(
                        item,
                        max_chars=max_chars,
                        depth=depth + 1,
                        budget=budget,
                    ),
                )
            )
        normalized_items.sort(key=lambda item: item[0])
        if len({key for key, _ in normalized_items}) != len(normalized_items):
            raise ConfigurationError("Decorator mapping keys collide after normalization")
        return dict(normalized_items)
    if isinstance(value, (list, tuple, set, frozenset)):
        normalized = [
            _bounded_decorator_value(
                item,
                max_chars=max_chars,
                depth=depth + 1,
                budget=budget,
            )
            for item in value
        ]
        if isinstance(value, (set, frozenset)):
            normalized.sort(
                key=lambda item: json.dumps(
                    item,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        return normalized
    raise ConfigurationError(
        f"Cannot serialize decorator argument of type {type(value).__name__}; "
        "provide an explicit serializer"
    )


def _replace_argument_target(
    bound: inspect.BoundArguments,
    target: _ArgumentTarget,
    replacement: Any,
) -> None:
    if target.item is None:
        bound.arguments[target.parameter] = replacement
        return
    container = bound.arguments[target.parameter]
    if isinstance(target.item, int):
        positional_values = list(container)
        positional_values[target.item] = replacement
        bound.arguments[target.parameter] = tuple(positional_values)
    else:
        keyword_values = dict(container)
        keyword_values[target.item] = replacement
        bound.arguments[target.parameter] = keyword_values


def _apply_decorator_transformation(
    bound: inspect.BoundArguments,
    targets: list[_ArgumentTarget],
    *,
    payload: Any,
    serialized: str,
    transformed: str,
    serializer: ArgumentSerializer | None,
    deserializer: ArgumentDeserializer | None,
) -> None:
    if transformed == serialized:
        return
    if len(targets) == 1 and serializer is None and isinstance(payload, str):
        _replace_argument_target(bound, targets[0], transformed)
        return
    if deserializer is None:
        raise ConfigurationError(
            "A deserializer is required to apply transformed structured or multi-field input"
        )
    try:
        replacement = deserializer(transformed)
    except Exception as exc:
        raise ConfigurationError(f"input deserializer failed: {type(exc).__name__}") from exc
    if len(targets) == 1:
        _replace_argument_target(bound, targets[0], replacement)
        return
    if not isinstance(replacement, Mapping):
        raise ConfigurationError("multi-field input deserializer must return a mapping")
    for target in targets:
        label = _target_label(target)
        if label not in replacement:
            raise ConfigurationError(
                f"multi-field input deserializer omitted selected argument '{label}'"
            )
        _replace_argument_target(bound, target, replacement[label])


def _bound_tool_arguments(
    signature: inspect.Signature,
    bound: inspect.BoundArguments,
    *,
    max_chars: int,
) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        if name in {"self", "cls"}:
            continue
        value = bound.arguments[name]
        if parameter.kind == inspect.Parameter.VAR_KEYWORD:
            for key in sorted(value):
                arguments[key] = value[key]
        else:
            arguments[name] = value
    normalized = _bounded_decorator_value(arguments, max_chars=max_chars)
    if not isinstance(normalized, dict):
        raise RuntimeError("Bound tool arguments did not normalize to a mapping")
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized) > max_chars:
        raise ResourceLimitError(
            f"Tool arguments contain {len(serialized)} characters; limit is {max_chars}"
        )
    return normalized
