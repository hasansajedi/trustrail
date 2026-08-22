"""Content safety rules: toxicity, hate speech, and profanity filtering."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry

# ── CS-001 Toxicity and hate speech ──────────────────────────────────────────
# Focus on dehumanising language, explicit threats, and slurs targeting
# protected groups.  Pattern design avoids false-positive collateral on
# educational, journalistic, or counter-speech contexts by requiring the
# most unambiguous forms.

_DEHUMANISING_RE = re.compile(
    r"\b(?:"
    r"(?:all\s+)?(?:jews?|muslims?|christians?|blacks?|whites?|asians?|"
    r"latinos?|hispanics?|immigrants?|refugees?|gays?|lesbians?|trans(?:gender)?s?)\s+"
    r"(?:are\s+)?(?:subhuman|vermin|parasites?|animals?|filth|trash|garbage|evil|inferior)|"
    r"(?:should\s+(?:be\s+)?(?:exterminated|eliminated|killed|deported|removed|wiped\s+out))|"
    r"(?:death\s+to\s+(?:all\s+)?(?:jews?|muslims?|blacks?|gays?|immigrants?))"
    r")\b",
    re.IGNORECASE,
)

_THREAT_RE = re.compile(
    r"\b(?:"
    r"i\s+(?:will|am\s+going\s+to|'m\s+going\s+to)\s+(?:kill|murder|hurt|attack|rape|shoot|stab)\s+you|"
    r"you\s+(?:will|are\s+going\s+to)\s+(?:die|be\s+killed|regret\s+this)|"
    r"(?:i\s+know\s+where\s+you\s+live)|"
    r"(?:watch\s+your\s+back)"
    r")\b",
    re.IGNORECASE,
)

_SLUR_RE = re.compile(
    r"\b(?:"
    r"n[i1]gg(?:er|a|ers?)|"
    r"f[a4]gg?(?:ot|ots?)|"
    r"ch[i1]nk|"
    r"sp[i1]c|"
    r"k[i1]ke|"
    r"w[e3]tb[a4]ck|"
    r"tr[a4]nny|"
    r"r[e3]t[a4]rd"
    r")\b",
    re.IGNORECASE,
)

_TOXICITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_DEHUMANISING_RE, "dehumanising language"),
    (_THREAT_RE, "explicit threat"),
    (_SLUR_RE, "hate-speech slur"),
]


@registry.register
class ToxicityRule(BaseRule):
    """Detects hate speech, dehumanising language, explicit threats, and slurs
    in LLM output.

    Targets the most unambiguous forms of harmful content to minimise
    false positives on educational or journalistic text.
    Default action is ``BLOCK`` with ``CRITICAL`` severity.
    """

    rule_id: ClassVar[str] = "CS-001"
    rule_name: ClassVar[str] = "Toxicity / Hate Speech"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects hate speech, dehumanising language, explicit threats, and slurs."
    )
    owasp: ClassVar[list[str]] = ["LLM02"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern, label in _TOXICITY_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"Toxic content detected: {label}",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    toxicity_type=label,
                )
        return self._allow()


# ── CS-002 Profanity and explicit sexual content ──────────────────────────────
# Simpler word-list approach for acceptable-use policy enforcement.
# Designed for deployments where profanity filtering is required independently
# of hate-speech detection (e.g. educational, workplace, customer-facing tools).

_PROFANITY_RE = re.compile(
    r"\b(?:"
    r"f+u+c+k+(?:ing|er|ed|s)?|"
    r"sh[i1]t(?:ty|ter|s)?|"
    r"a+s+s+h+o+l+e+s?|"
    r"b[i1]tch(?:es)?|"
    r"c+u+n+t+s?|"
    r"d[i1]ck(?:s|head)?|"
    r"p[i1]ss(?:ed|ing)?|"
    r"bastards?|"
    r"wh[o0]re(?:s|d)?|"
    r"bulls+h[i1]t"
    r")\b",
    re.IGNORECASE,
)

_EXPLICIT_SEXUAL_RE = re.compile(
    r"\b(?:"
    r"(?:having|had|perform(?:ing|ed)?)\s+sex(?:\s+with)?|"
    r"sexual\s+intercourse|"
    r"genitali[ae]|"
    r"penis(?:es)?|"
    r"vagina(?:s|l)?|"
    r"masturbat(?:e|ing|ion)|"
    r"porn(?:ography|ographic)?|"
    r"nude\s+(?:photo|image|video|content)"
    r")\b",
    re.IGNORECASE,
)

_PROFANITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_PROFANITY_RE, "profanity"),
    (_EXPLICIT_SEXUAL_RE, "explicit sexual content"),
]


@registry.register
class ProfanityRule(BaseRule):
    """Detects profanity and explicit sexual content in LLM output.

    Enforces acceptable-use policies for customer-facing, educational,
    or workplace deployments.  For hate-speech detection use CS-001.
    Default action is ``BLOCK`` with ``HIGH`` severity.
    """

    rule_id: ClassVar[str] = "CS-002"
    rule_name: ClassVar[str] = "Profanity / Explicit Content"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects profanity and explicit sexual content for acceptable-use enforcement."
    )
    owasp: ClassVar[list[str]] = ["LLM02"]

    def __init__(
        self,
        check_profanity: bool = True,
        check_explicit: bool = True,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.check_profanity = check_profanity
        self.check_explicit = check_explicit

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        checks: list[tuple[re.Pattern[str], str]] = []
        if self.check_profanity:
            checks.append((_PROFANITY_RE, "profanity"))
        if self.check_explicit:
            checks.append((_EXPLICIT_SEXUAL_RE, "explicit sexual content"))
        for pattern, label in checks:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"Prohibited content detected: {label}",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    content_type=label,
                )
        return self._allow()
