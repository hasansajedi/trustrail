"""Content safety policy — toxicity, hate speech, and profanity filtering."""

from __future__ import annotations

from aiRail.policies.base import BasePolicy
from aiRail.rules.base import BaseRule
from aiRail.rules.output.content_safety import ProfanityRule, ToxicityRule


class ContentSafetyPolicy(BasePolicy):
    """Policy for content safety: toxicity/hate speech and profanity filtering.

    Applies ``ToxicityRule`` (CS-001) and ``ProfanityRule`` (CS-002) to detect
    and block harmful content in LLM output.  Both rules can be toggled
    independently.
    """

    def __init__(
        self,
        enabled: bool = True,
        include_toxicity: bool = True,
        include_profanity: bool = True,
        check_profanity: bool = True,
        check_explicit: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.include_toxicity = include_toxicity
        self.include_profanity = include_profanity
        self.check_profanity = check_profanity
        self.check_explicit = check_explicit

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = []
        if self.include_toxicity:
            rules.append(ToxicityRule())
        if self.include_profanity:
            rules.append(
                ProfanityRule(
                    check_profanity=self.check_profanity,
                    check_explicit=self.check_explicit,
                )
            )
        return rules + self._rules
