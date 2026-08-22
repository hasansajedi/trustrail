"""ASI09: Human-Agent Trust Exploitation rules."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.confirmation import (
    ConfirmationPrompt,
)
from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry


@registry.register
class ConfirmationPromptRule(BaseRule):
    """Generates risk-aware confirmation prompts for high-impact actions (ASI09-001)."""

    rule_id = "ASI09-001"
    rule_name = "Risk-Aware Confirmation Prompt"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.MEDIUM
    default_action = GuardAction.WARN
    description = (
        "Generates confirmation prompts with action, target, side effects, "
        "data exposure, and reversibility details."
    )
    owasp = ("ASI09",)

    def __init__(
        self,
        enabled: bool = True,
        high_risk_actions: list[str] | None = None,
    ) -> None:
        super().__init__(enabled=enabled)
        self.high_risk_actions = high_risk_actions or [
            "delete",
            "drop",
            "truncate",
            "execute",
            "deploy",
            "modify",
            "update",
            "transfer",
            "pay",
            "send",
            "grant",
            "revoke",
        ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check if action requires confirmation prompt."""
        value_lower = value.lower()

        # Check if this is a high-risk action
        detected_actions = [action for action in self.high_risk_actions if action in value_lower]

        if not detected_actions:
            return self._allow()

        # Extract action details from context metadata
        action_data = context.metadata.get("action", {})
        if isinstance(action_data, str):
            action_data = {"description": action_data}

        # Generate confirmation prompt
        confirmation = ConfirmationPrompt(
            action=action_data.get("description", detected_actions[0]),
            target=action_data.get("target"),
            side_effects=action_data.get("side_effects", []),
            data_exposure=action_data.get("data_exposure", []),
            is_reversible=action_data.get("is_reversible", False),
            approval_rationale=f"This action involves: {', '.join(detected_actions)}",
            risk_level=action_data.get("risk_level", "high"),
        )

        return self._block(
            f"High-risk action requires confirmation: {confirmation.action}",
            confidence=0.8,
            action=GuardAction.WARN,
            severity=Severity.MEDIUM,
            detected_action=detected_actions[0],
            confirmation_prompt=confirmation.to_prompt_text(),
        )


@registry.register
class EvidenceRequirementRule(BaseRule):
    """Requires evidence for high-impact recommendations (ASI09-002)."""

    rule_id = "ASI09-002"
    rule_name = "Evidence Requirement"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = (
        "Demands sources, provenance, confidence levels, and uncertainty "
        "statements for high-impact recommendations."
    )
    owasp = ("ASI09",)

    def __init__(
        self,
        enabled: bool = True,
        impact_categories: list[str] | None = None,
        min_confidence: float = 0.7,
    ) -> None:
        super().__init__(enabled=enabled)
        self.impact_categories = impact_categories or [
            "financial",
            "legal",
            "medical",
            "security",
            "operational",
        ]
        self.min_confidence = min_confidence

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check if recommendation has required evidence."""
        # Check if this is a recommendation requiring evidence
        evidence_data = context.metadata.get("evidence", {})
        impact_category = context.metadata.get("impact_category")

        # If no impact category specified, check for keywords
        if not impact_category:
            value_lower = value.lower()
            for category in self.impact_categories:
                if category in value_lower:
                    impact_category = category
                    break

        if not impact_category:
            return self._allow()

        # Validate evidence requirements
        sources = evidence_data.get("sources", [])
        confidence = evidence_data.get("confidence_level", 0.0)

        missing_requirements = []
        if not sources:
            missing_requirements.append("sources/references")
        if confidence < self.min_confidence:
            missing_requirements.append(f"confidence >= {self.min_confidence}")
        if not evidence_data.get("uncertainty_statement"):
            missing_requirements.append("uncertainty statement")

        if missing_requirements:
            missing_str = ", ".join(missing_requirements)
            return self._block(
                f"High-impact {impact_category} recommendation missing: {missing_str}",
                impact_category=impact_category,
                missing=missing_requirements,
                provided_confidence=confidence,
            )

        return self._allow()


@registry.register
class ContentOriginMarkingRule(BaseRule):
    """Marks agent-generated content and external claims (ASI09-003)."""

    rule_id = "ASI09-003"
    rule_name = "Content Origin Marking"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.MEDIUM
    default_action = GuardAction.WARN
    description = "Preserves content origin and distinguishes model-generated vs. external content."
    owasp = ("ASI09",)

    CONTENT_TYPES: ClassVar[set[str]] = {
        "model_generated",
        "retrieved_evidence",
        "tool_result",
        "external_claim",
        "verified_fact",
    }

    def __init__(self, enabled: bool = True, require_marking: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.require_marking = require_marking

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check if content has proper origin marking."""
        content_origin = context.metadata.get("content_origin")

        if not content_origin and self.require_marking:
            return self._block(
                "Content missing origin marking",
                confidence=0.9,
                action=GuardAction.WARN,
                severity=Severity.MEDIUM,
                suggestion=(
                    "Add content_origin to metadata with type, source, and verification status"
                ),
            )

        if content_origin:
            content_type = content_origin.get("content_type")
            if content_type not in self.CONTENT_TYPES:
                return self._block(
                    f"Invalid content type: {content_type}",
                    confidence=1.0,
                    action=GuardAction.WARN,
                    severity=Severity.LOW,
                    valid_types=list(self.CONTENT_TYPES),
                )

        return self._allow()


@registry.register
class ManipulativeLanguageRule(BaseRule):
    """Detects manipulative approval and urgency language (ASI09-004)."""

    rule_id = "ASI09-004"
    rule_name = "Manipulative Language Detection"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = (
        "Flags output pressuring users through false urgency, authority "
        "claims, or risk concealment."
    )
    owasp = ("ASI09",)

    def __init__(
        self,
        enabled: bool = True,
        custom_patterns: list[str] | None = None,
    ) -> None:
        super().__init__(enabled=enabled)

        # Manipulative language patterns
        self.urgency_patterns = [
            r"\bimmediately\b",
            r"\bright now\b",
            r"\burgent(?:ly)?\b",
            r"\btime[- ]sensitive\b",
            r"\basap\b",
            r"\bquickly\b",
            r"\bhurry\b",
            r"\bdon'?t wait\b",
            r"\bact now\b",
        ]

        self.authority_patterns = [
            r"\btrust me\b",
            r"\bi'?m an? expert\b",
            r"\bbelieve me\b",
            r"\byou (?:must|should|need to) trust\b",
            r"\bauthorized\b",
            r"\bofficial\b",
            r"\bcertified\b",
        ]

        self.pressure_patterns = [
            r"\bno (?:need|time) to (?:review|check|verify)\b",
            r"\bjust (?:approve|accept|click)\b",
            r"\bskip (?:the )?(?:review|verification)\b",
            r"\bbypass\b",
            r"\bdon'?t worry about\b",
            r"\bignore (?:the )?(?:warning|risk)\b",
        ]

        self.emotional_patterns = [
            r"\byou'?ll regret\b",
            r"\bmiss out\b",
            r"\bfear of missing out\b",
            r"\bfomo\b",
            r"\bworried\b",
            r"\banxious\b",
        ]

        if custom_patterns:
            self.urgency_patterns.extend(custom_patterns)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect manipulative language patterns."""
        value_lower = value.lower()
        detected_patterns: dict[str, list[str]] = {
            "urgency": [],
            "authority": [],
            "pressure": [],
            "emotional": [],
        }

        # Check all pattern categories
        for pattern in self.urgency_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                detected_patterns["urgency"].append(pattern)

        for pattern in self.authority_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                detected_patterns["authority"].append(pattern)

        for pattern in self.pressure_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                detected_patterns["pressure"].append(pattern)

        for pattern in self.emotional_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                detected_patterns["emotional"].append(pattern)

        # Filter out empty categories
        detected_patterns = {k: v for k, v in detected_patterns.items() if v}

        if detected_patterns:
            severity = Severity.HIGH if len(detected_patterns) > 1 else Severity.MEDIUM
            return self._block(
                f"Detected manipulative language: {', '.join(detected_patterns.keys())}",
                patterns=detected_patterns,
                pattern_count=sum(len(v) for v in detected_patterns.values()),
                severity=severity,
            )

        return self._allow()


@registry.register
class DecisionEscalationRule(BaseRule):
    """Escalates uncertain high-risk decisions to human review (ASI09-005)."""

    rule_id = "ASI09-005"
    rule_name = "Decision Escalation"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Blocks autonomous completion of uncertain or conflicting high-impact decisions."
    owasp = ("ASI09",)

    def __init__(
        self,
        enabled: bool = True,
        confidence_threshold: float = 0.8,
        conflict_threshold: int = 2,
    ) -> None:
        super().__init__(enabled=enabled)
        self.confidence_threshold = confidence_threshold
        self.conflict_threshold = conflict_threshold

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check if decision should be escalated to human review."""
        decision_data = context.metadata.get("decision", {})

        if not decision_data:
            return self._allow()

        is_high_impact = decision_data.get("is_high_impact", False)
        confidence = decision_data.get("confidence", 1.0)
        conflicting_options = decision_data.get("conflicting_options", [])
        uncertainty_level = decision_data.get("uncertainty_level", "low")

        should_escalate = False
        reasons = []

        # Escalate if high-impact and low confidence
        if is_high_impact and confidence < self.confidence_threshold:
            should_escalate = True
            reasons.append(f"Low confidence ({confidence:.2f} < {self.confidence_threshold})")

        # Escalate if multiple conflicting options
        if len(conflicting_options) >= self.conflict_threshold:
            should_escalate = True
            reasons.append(f"Multiple conflicting options ({len(conflicting_options)})")

        # Escalate if high uncertainty level
        if uncertainty_level in ("high", "critical"):
            should_escalate = True
            reasons.append(f"High uncertainty level ({uncertainty_level})")

        if should_escalate:
            return self._block(
                f"Decision requires human review: {'; '.join(reasons)}",
                reasons=reasons,
                confidence=confidence,
                conflicting_options=conflicting_options,
                escalation_required=True,
            )

        return self._allow()
