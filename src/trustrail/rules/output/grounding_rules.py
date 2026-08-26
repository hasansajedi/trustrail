"""Grounding and overreliance detection rules — OWASP LLM09."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry

# Phrases that signal the model is uncertain or potentially hallucinating
_HALLUCINATION_PHRASES: list[re.Pattern[str]] = [
    re.compile(
        r"\b(?:as of my (?:knowledge|training|last update)|"
        r"i (?:believe|think|assume|recall|seem to recall)|"
        r"(?:i'?m|i am) not (?:entirely |completely |fully )?(?:sure|certain|positive)|"
        r"(?:to the best of my|from my) (?:knowledge|recollection|memory)|"
        r"this (?:may|might|could) (?:not be|be incorrect|have changed)|"
        r"please (?:verify|double[- ]check|confirm) this)\b",
        re.IGNORECASE,
    ),
]

# Overconfident absolute-claim phrases in high-stakes output
_ABSOLUTE_CLAIM_RE = re.compile(
    r"\b(?:"
    r"(?:100|one hundred)\s*(?:percent|%)\s*(?:sure|certain|accurate|correct|guaranteed|safe)|"
    r"(?:absolutely|definitely|undoubtedly|unquestionably)\s+(?:certain|true|correct|accurate|safe|works?|will)|"
    r"(?:i am|i'm)\s+(?:absolutely|completely|totally|100%?)\s+(?:certain|sure|positive)|"
    r"guaranteed\s+(?:to\s+)?(?:work|be\s+correct|be\s+accurate|be\s+safe)|"
    r"(?:there is|there are)\s+no\s+(?:doubt|question|risk|chance of error)|"
    r"(?:always|never)\s+(?:works?|true|accurate|correct|safe)"
    r")\b",
    re.IGNORECASE,
)


def contains_absolute_claim(value: str) -> bool:
    """Return whether bounded output contains overconfident absolute language."""
    return _ABSOLUTE_CLAIM_RE.search(value[:100_000]) is not None


# Patterns consistent with hallucinated academic/web references
_INVENTED_CITATION_RE = re.compile(
    r"""
    (?:
        # DOI-like pattern
        \bdoi\s*:\s*10\.\d{4,}/[^\s,;]{3,40}
        |
        # arXiv ID
        \barxiv\s*:\s*\d{4}\.\d{4,5}(?:v\d+)?
        |
        # Author (et al.) YYYY citation — with or without brackets
        (?:\[\s*)?[A-Z][a-z]+(?:\s+et\s+al\.?)?\s*,\s*(?:19|20)\d{2}(?:\s*\])?
        |
        # "Published in <Journal> (YYYY)" pattern inside prose
        (?:published|appeared)\s+in\s+[""]?[A-Z][^""\n]{5,60}[""]?\s*\(\s*(?:19|20)\d{2}\s*\)
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def contains_citation_candidate(value: str) -> bool:
    """Return whether output contains a citation-like identifier to validate."""
    return _INVENTED_CITATION_RE.search(value[:100_000]) is not None


@registry.register
class HallucinationIndicatorRule(BaseRule):
    """Warns when LLM output contains phrases that signal uncertain or potentially
    hallucinated content.

    These phrases indicate the model is hedging around facts it may have fabricated.
    Default action is WARN so downstream consumers can decide how to surface this.
    """

    rule_id: ClassVar[str] = "GR-001"
    rule_name: ClassVar[str] = "Hallucination Indicator"
    category: ClassVar[RuleCategory] = RuleCategory.GROUNDING
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = (
        "Detects uncertainty phrases that signal potentially hallucinated LLM output."
    )
    owasp: ClassVar[list[str]] = ["LLM09:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        for pattern in _HALLUCINATION_PHRASES:
            match = pattern.search(value)
            if match:
                return self._block(
                    f"Hallucination indicator detected: '{match.group(0)[:80]}'",
                    action=GuardAction.WARN,
                    severity=Severity.MEDIUM,
                    offset_start=match.start(),
                    offset_end=match.end(),
                    confidence=0.75,
                    matched_phrase=match.group(0)[:80],
                )
        return self._allow()


@registry.register
class AbsoluteClaimRule(BaseRule):
    """Warns when LLM output makes absolute, unqualified claims of certainty.

    Overconfident language in medical, legal, or financial contexts is a key
    risk factor for user overreliance on LLM output (OWASP LLM09).
    """

    rule_id: ClassVar[str] = "GR-002"
    rule_name: ClassVar[str] = "Absolute Claim"
    category: ClassVar[RuleCategory] = RuleCategory.GROUNDING
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = (
        "Detects overconfident absolute claims in LLM output that could cause overreliance."
    )
    owasp: ClassVar[list[str]] = ["LLM09:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        match = _ABSOLUTE_CLAIM_RE.search(value)
        if match:
            return self._block(
                f"Absolute claim detected: '{match.group(0)[:80]}'",
                action=GuardAction.WARN,
                severity=Severity.MEDIUM,
                offset_start=match.start(),
                offset_end=match.end(),
                confidence=0.8,
                matched_phrase=match.group(0)[:80],
            )
        return self._allow()


@registry.register
class InventedCitationRule(BaseRule):
    """Warns when LLM output contains citation-like patterns that may be hallucinated.

    LLMs frequently fabricate plausible-looking DOIs, arXiv IDs, and author-year
    citations. This rule flags such patterns for human verification.
    """

    rule_id: ClassVar[str] = "GR-003"
    rule_name: ClassVar[str] = "Invented Citation"
    category: ClassVar[RuleCategory] = RuleCategory.GROUNDING
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.LOW
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = (
        "Flags citation-like patterns (DOI, arXiv, author-year) that may be hallucinated."
    )
    owasp: ClassVar[list[str]] = ["LLM09:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        match = _INVENTED_CITATION_RE.search(value)
        if match:
            return self._block(
                f"Possible invented citation detected: '{match.group(0)[:80]}'",
                action=GuardAction.WARN,
                severity=Severity.LOW,
                offset_start=match.start(),
                offset_end=match.end(),
                confidence=0.6,
                citation_snippet=match.group(0)[:80],
            )
        return self._allow()


# ── High-risk domain advice ───────────────────────────────────────────────────
# Patterns that indicate the model is giving specific medical, legal, or
# financial advice — not just mentioning the topic.

_MEDICAL_ADVICE_RE = re.compile(
    r"\b(?:"
    r"you (?:likely|probably|definitely|may) have\b|"
    r"take (?:ibuprofen|aspirin|acetaminophen|paracetamol|amoxicillin|\d+\s*mg)|"
    r"dosage of \d+\s*mg|"
    r"(?:prescribe|prescribed|diagnose(?:d)?) (?:you |with )?|"
    r"stop taking your (?:medication|meds|pills)|"
    r"you (?:should|need to) (?:take|stop|start) (?:this )?medication"
    r")\b",
    re.IGNORECASE,
)

_LEGAL_ADVICE_RE = re.compile(
    r"\b(?:"
    r"you should (?:sue|file (?:a )?lawsuit|press charges)|"
    r"under (?:section|article|subsection) \d+|"
    r"you have (?:a )?(?:legal )?(?:claim|case|grounds) (?:against|to sue)|"
    r"(?:your employer|they) (?:is|are) (?:liable|in violation of)|"
    r"file (?:a )?(?:complaint|lawsuit) (?:in|with) (?:court|the )"
    r")\b",
    re.IGNORECASE,
)

_FINANCIAL_ADVICE_RE = re.compile(
    r"\b(?:"
    r"(?:you should |i recommend )?"
    r"(?:buy|sell|short|invest in) (?:[A-Z]{1,5}|this stock|those shares)|"
    r"(?:put|move) (?:your )?(?:savings|money|funds|retirement) into|"
    r"this is a (?:good|great|excellent|sure) (?:investment|time to buy|opportunity)|"
    r"guaranteed (?:returns?|profit|gains?)"
    r")\b",
    re.IGNORECASE,
)

_DISCLAIMER_RE = re.compile(
    r"\b(?:"
    r"not (?:medical|legal|financial|professional|tax) advice|"
    r"consult (?:a |your )?(?:doctor|physician|specialist|lawyer|attorney|"
    r"financial advisor|professional|expert)|"
    r"i (?:am|'m) not (?:a |your )?(?:doctor|physician|lawyer|attorney|financial advisor)|"
    r"seek (?:professional|medical|legal|financial) (?:advice|help|assistance|counsel)|"
    r"this (?:is|does) not (?:constitute|replace) (?:medical|legal|financial|professional)"
    r")\b",
    re.IGNORECASE,
)

_HIGH_RISK_RULES: list[tuple[re.Pattern[str], str]] = [
    (_MEDICAL_ADVICE_RE, "medical"),
    (_LEGAL_ADVICE_RE, "legal"),
    (_FINANCIAL_ADVICE_RE, "financial"),
]


def detect_high_risk_domain(value: str) -> str | None:
    """Return the first heuristic high-impact advice domain in bounded output."""
    text = value[:100_000]
    for pattern, domain in _HIGH_RISK_RULES:
        if pattern.search(text):
            return domain
    return None


@registry.register
class HighRiskDomainAdviceRule(BaseRule):
    """Warns when LLM output gives specific medical, legal, or financial advice
    without an appropriate disclaimer.

    Providing actionable professional advice without disclaimers increases
    liability risk and can directly harm users (OWASP LLM09).
    """

    rule_id: ClassVar[str] = "GR-004"
    rule_name: ClassVar[str] = "High-Risk Domain Advice"
    category: ClassVar[RuleCategory] = RuleCategory.GROUNDING
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = (
        "Warns when LLM gives specific medical, legal, or financial advice without a disclaimer."
    )
    owasp: ClassVar[list[str]] = ["LLM09:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:  # GR-004
        text = value[:50_000]
        has_disclaimer = bool(_DISCLAIMER_RE.search(text))
        if has_disclaimer:
            return self._allow()
        domain = detect_high_risk_domain(text)
        if domain is not None:
            return self._block(
                f"High-risk {domain} advice detected without disclaimer",
                action=GuardAction.WARN,
                severity=Severity.HIGH,
                confidence=0.85,
                domain=domain,
            )
        return self._allow()


# ── Sycophancy detection ──────────────────────────────────────────────────────
# Detect unconditional validation phrases and known false-premise agreement
# patterns.  These are leading indicators of overreliance risk (OWASP LLM09).

_SYCOPHANCY_RE = re.compile(
    r"\b(?:"
    # Unconditional agreement openers
    r"you\s+are\s+(?:absolutely|completely|totally|100\s*%?|entirely|perfectly)\s+(?:right|correct)|"
    r"that\s+is\s+(?:absolutely|completely|entirely|totally|100\s*%?)\s+(?:correct|true|right|accurate)|"
    r"(?:exactly|precisely),?\s+(?:you\s+are\s+right|that\s+is\s+correct)|"
    r"i\s+(?:completely|fully|totally|absolutely)\s+agree\s+with\s+(?:you|that)|"
    # False scientific consensus validations
    r"(?:vaccines?\s+(?:do|can|have\s+been\s+shown\s+to)\s+cause\s+autism)|"
    r"(?:the\s+earth\s+is\s+(?:flat|not\s+round|not\s+a\s+sphere))|"
    r"(?:climate\s+change\s+(?:is\s+not\s+real|is\s+a\s+hoax|is\s+fake))|"
    r"(?:the\s+(?:moon\s+landing|apollo\s+mission)\s+was\s+(?:faked|staged|a\s+hoax))"
    r")\b",
    re.IGNORECASE,
)


@registry.register
class SycophancyRule(BaseRule):
    """Detects sycophantic or factually contradictory LLM output.

    Flags unconditional validation phrases (``"You are absolutely right"``) and
    known false-premise agreements (vaccines causing autism, flat earth, etc.).
    These patterns indicate the model is reinforcing user beliefs rather than
    providing accurate information — a key overreliance risk (OWASP LLM09).
    """

    rule_id: ClassVar[str] = "GR-005"
    rule_name: ClassVar[str] = "Sycophancy / Factual Contradiction"
    category: ClassVar[RuleCategory] = RuleCategory.GROUNDING
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = (
        "Detects sycophantic validation phrases and known false-premise agreements."
    )
    owasp: ClassVar[list[str]] = ["LLM09:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _SYCOPHANCY_RE.search(text)
        if m:
            return self._block(
                f"Sycophantic or contradictory response detected: '{m.group(0)[:80]}'",
                action=GuardAction.WARN,
                severity=Severity.HIGH,
                offset_start=m.start(),
                offset_end=m.end(),
                confidence=0.8,
                matched_phrase=m.group(0)[:80],
            )
        return self._allow()
