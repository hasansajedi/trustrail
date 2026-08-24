"""Persistent memory classification and approval rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import (
    GuardAction,
    GuardStage,
    MemoryWriteClassification,
    RuleCategory,
    RulePhase,
    Severity,
)
from trustrail.rules.base import BaseRule, registry


@dataclass(frozen=True)
class MemoryWriteAssessment:
    """Privacy-safe classification of a proposed memory write."""

    classification: MemoryWriteClassification
    severity: Severity
    reason_codes: tuple[str, ...]
    requires_approval: bool


@registry.register
class PersistentMemoryWriteRule(BaseRule):
    """Classifies persistent writes and requires an out-of-band decision."""

    rule_id: ClassVar[str] = "MEM-001"
    rule_name: ClassVar[str] = "Persistent Memory Write Approval"
    category: ClassVar[RuleCategory] = RuleCategory.MEMORY
    phase: ClassVar[RulePhase] = RulePhase.POLICY
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.REQUIRE_APPROVAL
    description: ClassVar[str] = (
        "Classifies persistent memory writes and requires out-of-band approval."
    )
    owasp: ClassVar[list[str]] = ["LLM01:2025", "LLM04:2025"]

    _SENSITIVE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:password|passcode|api[ _-]?key|access[ _-]?token|refresh[ _-]?token|"
        r"private[ _-]?key|secret|credential|recovery[ _-]?(?:code|phrase)|seed phrase)\b",
        re.IGNORECASE,
    )
    _INSTRUCTION_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:instruction|directive|system prompt|from now on|always (?:answer|respond|do)|"
        r"never (?:reveal|mention|follow)|when .{0,80} then|must (?:obey|follow|execute))\b",
        re.IGNORECASE,
    )
    _PROFILE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:my name is|i am (?:located|based|living)|i live (?:at|in)|my (?:address|"
        r"employer|birthday|account|phone|email)|user (?:name|address|profile|identity))\b",
        re.IGNORECASE,
    )
    _PREFERENCE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:i prefer|my preference|my favou?rite|i (?:like|love|dislike|hate)|"
        r"preferred (?:language|format|style|tone)|remember that i)\b",
        re.IGNORECASE,
    )

    @classmethod
    def classify(cls, value: str, *, persistent: bool = True) -> MemoryWriteAssessment:
        """Classify without retaining or returning the proposed memory content."""
        if cls._SENSITIVE_RE.search(value):
            return MemoryWriteAssessment(
                classification=MemoryWriteClassification.SENSITIVE,
                severity=Severity.CRITICAL,
                reason_codes=("credential_or_secret_marker",),
                requires_approval=False,
            )
        if cls._INSTRUCTION_RE.search(value):
            classification = MemoryWriteClassification.INSTRUCTION
            severity = Severity.HIGH
            reasons = ("persistent_behavioral_instruction",)
        elif cls._PROFILE_RE.search(value):
            classification = MemoryWriteClassification.PROFILE
            severity = Severity.HIGH
            reasons = ("personal_profile_attribute",)
        elif cls._PREFERENCE_RE.search(value):
            classification = MemoryWriteClassification.PREFERENCE
            severity = Severity.MEDIUM
            reasons = ("user_preference",)
        else:
            classification = MemoryWriteClassification.GENERAL
            severity = Severity.LOW
            reasons = ("general_memory",)

        return MemoryWriteAssessment(
            classification=classification,
            severity=severity,
            reason_codes=reasons,
            requires_approval=persistent,
        )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        if context.stage != GuardStage.MEMORY_WRITE:
            return self._allow()

        persistent = context.metadata.get("persistent", True) is not False
        if not persistent:
            return self._allow()
        assessment = self.classify(value, persistent=persistent)

        if assessment.classification == MemoryWriteClassification.SENSITIVE:
            return self._block(
                "Sensitive material must not be stored in persistent memory",
                severity=assessment.severity,
                action=GuardAction.BLOCK,
                classification=assessment.classification.value,
                persistent=persistent,
                reason_codes=list(assessment.reason_codes),
                requires_approval=assessment.requires_approval,
            )
        if assessment.requires_approval:
            return self._block(
                f"Persistent {assessment.classification.value} memory write requires approval",
                severity=assessment.severity,
                action=GuardAction.REQUIRE_APPROVAL,
                classification=assessment.classification.value,
                persistent=persistent,
                reason_codes=list(assessment.reason_codes),
                requires_approval=assessment.requires_approval,
            )
        return self._allow()
