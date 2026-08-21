"""RAG-specific security rules."""

from __future__ import annotations

import re
from typing import ClassVar

from pydantic import ValidationError

from aiRail.models.core import GuardContext, GuardDecision
from aiRail.models.enums import (
    GuardAction,
    GuardStage,
    RuleCategory,
    RulePhase,
    Severity,
    TrustLevel,
)
from aiRail.models.rag import RAGContextEnvelope
from aiRail.rules.base import BaseRule, registry

# Commands in retrieved documents
_INSTRUCTION_IN_DOC_RE = re.compile(
    r"""
    (?:
        (?:AI|assistant|bot|model|LLM|GPT|Claude)\s*[,:]\s*
        (?:please|do|execute|run|perform|follow|ignore|forget|disregard)
        |
        (?:important|urgent)\s+(?:note|instruction)\s+(?:for|to)\s+(?:AI|assistant|LLM|you)
        |
        when\s+you\s+(?:read|process|see)\s+this
        |
        (?:ignore|forget|disregard)\s+(?:previous|prior|above|all)\s+instructions?
        |
        (?:your|the\s+AI's)\s+(?:new|updated|actual|real)\s+instructions?\s+are
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Trust level keywords in document source URLs
_SUSPICIOUS_SOURCE_PATTERNS = re.compile(
    r"""
    (?:
        pastebin\.com|
        hastebin\.com|
        ghostbin\.com|
        raw\.githubusercontent\.com|
        gist\.github\.com
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


@registry.register
class MissingProvenanceRule(BaseRule):
    """Warns when RAG documents lack source provenance."""

    rule_id: ClassVar[str] = "RAG-001"
    rule_name: ClassVar[str] = "Missing Provenance"
    category: ClassVar[RuleCategory] = RuleCategory.RAG
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.LOW
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Warns when RAG documents lack source provenance."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        # Check if we're processing a RAG document
        is_rag = context.stage in (GuardStage.RAG_DOCUMENT, GuardStage.EXTERNAL_CONTENT)
        if not is_rag:
            return self._allow()

        # Look for provenance in metadata
        source = context.metadata.get("source") or context.metadata.get("source_url")
        if not source:
            return self._block(
                "RAG document lacks source provenance",
                severity=Severity.LOW,
                action=GuardAction.WARN,
            )
        return self._allow()


@registry.register
class UntrustedInstructionRule(BaseRule):
    """Detects instructions embedded in retrieved documents (indirect injection)."""

    rule_id: ClassVar[str] = "RAG-002"
    rule_name: ClassVar[str] = "Untrusted Instruction in Document"
    category: ClassVar[RuleCategory] = RuleCategory.RAG
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects AI-directed instructions embedded in retrieved documents."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        m = _INSTRUCTION_IN_DOC_RE.search(text)
        if m:
            return self._block(
                "AI-directed instruction found in retrieved document",
                severity=Severity.CRITICAL,
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


@registry.register
class SourceTrustRule(BaseRule):
    """Validates that RAG document sources meet the required trust level."""

    rule_id: ClassVar[str] = "RAG-003"
    rule_name: ClassVar[str] = "Source Trust Validation"
    category: ClassVar[RuleCategory] = RuleCategory.RAG
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Validates the trust level of document sources."

    def __init__(
        self,
        required_trust: TrustLevel = TrustLevel.SEMI_TRUSTED,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.required_trust = required_trust

    _TRUST_ORDER: ClassVar[dict[TrustLevel, int]] = {
        TrustLevel.UNTRUSTED: 0,
        TrustLevel.SEMI_TRUSTED: 1,
        TrustLevel.TRUSTED: 2,
    }

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        # Check context trust level
        doc_trust = context.trust_level
        required_level = self._TRUST_ORDER[self.required_trust]
        doc_level = self._TRUST_ORDER[doc_trust]

        if doc_level < required_level:
            return self._block(
                f"Document trust level '{doc_trust.value}' below required "
                f"'{self.required_trust.value}'",
                severity=Severity.MEDIUM,
                action=GuardAction.WARN,
                doc_trust=doc_trust.value,
                required_trust=self.required_trust.value,
            )

        # Also check for suspicious source URLs
        source_url = context.metadata.get("source_url", "")
        if source_url and _SUSPICIOUS_SOURCE_PATTERNS.search(str(source_url)):
            return self._block(
                "Document source matches a restricted content-hosting pattern",
                severity=Severity.MEDIUM,
                action=GuardAction.WARN,
                source_class="public_content_host",
            )

        return self._allow()


@registry.register
class RAGContextLabelRule(BaseRule):
    """Requires assembled RAG context to preserve structural security labels."""

    rule_id: ClassVar[str] = "RAG-004"
    rule_name: ClassVar[str] = "RAG Context Provenance Labels"
    category: ClassVar[RuleCategory] = RuleCategory.RAG
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Rejects RAG context that is not structurally separated and provenance-labeled."
    )
    owasp: ClassVar[list[str]] = ["LLM01:2026"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        if context.stage != GuardStage.RAG_CONTEXT:
            return self._allow()

        try:
            RAGContextEnvelope.model_validate_json(value)
        except (ValidationError, ValueError):
            return self._block(
                "RAG context lacks a valid provenance-labeled data envelope",
                severity=Severity.HIGH,
                reason="invalid_or_missing_envelope",
            )

        return self._allow()


@registry.register
class RagContextTamperingRule(BaseRule):
    """Detects signs of tampered or poisoned RAG augmentation data.

    Flags documents injected with adversarial instructions masquerading as
    retrieved context: role-switch headers, fake citations, conflicting
    confidence claims, or embedded command overrides. Covers OWASP LLM04
    (Data and Model Poisoning) via the RAG retrieval pipeline.
    """

    rule_id: ClassVar[str] = "DP-001"
    rule_name: ClassVar[str] = "RAG Context Tampering"
    category: ClassVar[RuleCategory] = RuleCategory.RAG
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects tampered or poisoned content injected into RAG augmentation data."
    )
    owasp: ClassVar[list[str]] = ["LLM04"]

    _TAMPER_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above)"
            r"\s+(?:instructions?|context|documents?|rules?)",
            re.IGNORECASE,
        ),
        re.compile(
            r"<\s*(?:context|document|retrieved)\s*>\s*"
            r"(?:ignore|override|new\s+instruction)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\[(?:INJECTED|ADVERSARIAL|FAKE|POISONED)\s*(?:CONTEXT|DATA|DOCUMENT)?\]",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:source|citation|reference)\s*:\s*(?:N/A|none|unknown|internal|classified|FAKE)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:confidence|relevance|score)\s*[:=]\s*(?:100|1\.0|perfect|guaranteed|certain)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:do\s+not\s+use|ignore)\s+(?:this|the\s+(?:above|following))\s+"
            r"(?:context|document|retrieved\s+content)",
            re.IGNORECASE,
        ),
        re.compile(
            r"new\s+(?:task|objective|instruction|directive)\s*:\s*"
            r"(?:instead|rather|now)\s+(?:of\s+)?",
            re.IGNORECASE,
        ),
    ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        if context.stage not in (
            GuardStage.RAG_DOCUMENT,
            GuardStage.EXTERNAL_CONTENT,
            GuardStage.TOOL_RESPONSE,
        ):
            return self._allow()

        text = value[:20_000]
        for pattern in self._TAMPER_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    "RAG context tampering detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_pattern=m.group(0)[:80],
                )
        return self._allow()
