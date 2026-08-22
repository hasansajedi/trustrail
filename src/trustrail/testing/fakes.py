"""Fake providers for testing trustrail integrations.

These never call external APIs and do not require paid services.
"""

from __future__ import annotations

from typing import Any

from trustrail.models.core import Document, GuardContext, GuardFinding
from trustrail.models.enums import RuleCategory, Severity


class FakePromptInjectionProvider:
    """Fake prompt injection provider for testing.

    Returns configurable findings based on keywords.
    """

    def __init__(
        self,
        trigger_keywords: list[str] | None = None,
        default_finding: GuardFinding | None = None,
    ) -> None:
        self.trigger_keywords = trigger_keywords or ["INJECT", "OVERRIDE", "JAILBREAK"]
        self.default_finding = default_finding
        self.calls: list[str] = []

    async def check(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        self.calls.append(text)
        for keyword in self.trigger_keywords:
            if keyword.lower() in text.lower():
                finding = self.default_finding or GuardFinding(
                    rule_id="FAKE-PI-001",
                    rule_name="Fake Prompt Injection",
                    category=RuleCategory.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    message=f"Fake injection detected (keyword: {keyword})",
                    confidence=1.0,
                )
                return [finding]
        return []


class FakeModerationProvider:
    """Fake content moderation provider for testing."""

    def __init__(
        self,
        blocked_categories: list[str] | None = None,
        trigger_keywords: list[str] | None = None,
    ) -> None:
        self.blocked_categories = blocked_categories or []
        self.trigger_keywords = trigger_keywords or ["HARMFUL", "UNSAFE", "EXPLICIT"]
        self.calls: list[str] = []

    async def check(
        self,
        text: str,
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        self.calls.append(text)
        findings = []
        for keyword in self.trigger_keywords:
            if keyword.lower() in text.lower():
                findings.append(
                    GuardFinding(
                        rule_id="FAKE-CS-001",
                        rule_name="Fake Content Safety",
                        category=RuleCategory.CONTENT_SAFETY,
                        severity=Severity.HIGH,
                        message=f"Fake moderation trigger (keyword: {keyword})",
                    )
                )
        return findings


class FakeGroundingVerifier:
    """Fake grounding verifier for testing RAG pipelines."""

    def __init__(
        self,
        always_grounded: bool = True,
        ungrounded_phrases: list[str] | None = None,
    ) -> None:
        self.always_grounded = always_grounded
        self.ungrounded_phrases = ungrounded_phrases or ["hallucination", "made up"]
        self.calls: list[tuple[str, int]] = []

    async def verify(
        self,
        response: str,
        documents: list[Document],
        context: GuardContext | None = None,
    ) -> list[GuardFinding]:
        self.calls.append((response[:50], len(documents)))

        if self.always_grounded:
            return []

        for phrase in self.ungrounded_phrases:
            if phrase.lower() in response.lower():
                return [
                    GuardFinding(
                        rule_id="FAKE-GR-001",
                        rule_name="Fake Grounding Verifier",
                        category=RuleCategory.GROUNDING,
                        severity=Severity.MEDIUM,
                        message=f"Response not grounded in documents (phrase: {phrase})",
                        confidence=0.8,
                    )
                ]
        return []


class FakeApprovalProvider:
    """Fake approval provider for testing human-in-the-loop flows."""

    def __init__(self, default_approved: bool = True) -> None:
        self.default_approved = default_approved
        self.requests: list[dict[str, Any]] = []

    async def request_approval(
        self,
        value: str,
        context: GuardContext | None = None,
        reason: str = "",
    ) -> bool:
        self.requests.append(
            {
                "value_preview": value[:50],
                "reason": reason,
                "approved": self.default_approved,
            }
        )
        return self.default_approved
