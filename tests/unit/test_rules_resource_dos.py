"""Tests for OWASP LLM04 enhanced resource / DoS rules."""

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.resource.limits import CumulativeTokenBudgetRule, RepetitivePatternRule


def _ctx(session_id: str | None = None) -> GuardContext:
    return GuardContext(stage=GuardStage.USER_INPUT, session_id=session_id)


class TestRepetitivePatternRule:
    def test_allows_normal_text(self):
        rule = RepetitivePatternRule()
        text = " ".join(["the quick brown fox jumped over the lazy dog"] * 3)
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_blocks_highly_repetitive_input(self):
        rule = RepetitivePatternRule(ngram_size=2, max_repetition_ratio=0.3, min_words=50)
        # Repeat the same 2-word sequence 50 times → bigram repetition well above 30%
        repeated = " ".join(["hello world"] * 50)
        result = rule.evaluate(repeated, _ctx())
        assert result.action == GuardAction.BLOCK

    def test_ignores_short_input(self):
        rule = RepetitivePatternRule(min_words=50)
        text = " ".join(["repeat"] * 20)
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_configurable_ratio(self):
        rule = RepetitivePatternRule(ngram_size=2, max_repetition_ratio=0.9, min_words=10)
        # Even a repetitive input should pass at 90% threshold
        repeated = " ".join(["hello world"] * 20)
        result = rule.evaluate(repeated, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_finding_contains_ratio(self):
        rule = RepetitivePatternRule(ngram_size=3, max_repetition_ratio=0.3, min_words=20)
        repeated = " ".join(["same words here"] * 20)
        result = rule.evaluate(repeated, _ctx())
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert "repetition_ratio" in result.finding.metadata


class TestCumulativeTokenBudgetRule:
    def test_allows_within_budget(self):
        rule = CumulativeTokenBudgetRule(session_budget_tokens=1000)
        ctx = _ctx(session_id="s1")
        result = rule.evaluate("hello world", ctx)
        assert result.action == GuardAction.ALLOW

    def test_blocks_when_budget_exceeded(self):
        rule = CumulativeTokenBudgetRule(session_budget_tokens=10)
        ctx = _ctx(session_id="s2")
        # Each char ~0.25 tokens; 60 chars ≈ 15 tokens → exceeds budget of 10
        result = rule.evaluate("a" * 60, ctx)
        assert result.action == GuardAction.BLOCK

    def test_accumulates_across_calls(self):
        rule = CumulativeTokenBudgetRule(session_budget_tokens=15)
        ctx = _ctx(session_id="s3")
        # 10 calls of 10 chars each = 2 tokens each = 20 total → exceeds budget of 15
        for _ in range(10):
            result = rule.evaluate("a" * 10, ctx)
        assert result.action == GuardAction.BLOCK

    def test_isolates_sessions(self):
        rule = CumulativeTokenBudgetRule(session_budget_tokens=5)
        ctx_a = _ctx(session_id="sess-a")
        ctx_b = _ctx(session_id="sess-b")
        # Exhaust session A
        rule.evaluate("a" * 40, ctx_a)
        # Session B should still be within budget
        result = rule.evaluate("hi", ctx_b)
        assert result.action == GuardAction.ALLOW

    def test_finding_reports_session_total(self):
        rule = CumulativeTokenBudgetRule(session_budget_tokens=1)
        ctx = _ctx(session_id="s4")
        result = rule.evaluate("a" * 20, ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert "session_tokens_used" in result.finding.metadata


class TestRecursivePromptExpansionRule:
    def setup_method(self):
        from aiRail.rules.resource.limits import RecursivePromptExpansionRule

        self.rule = RecursivePromptExpansionRule()

    def _ctx(self):
        from aiRail.models.core import GuardContext
        from aiRail.models.enums import GuardStage

        return GuardContext(stage=GuardStage.USER_INPUT)

    def test_detects_repeat_n_times(self):
        d = self.rule.evaluate("Repeat this prompt 1000 times", self._ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_recursive_keyword(self):
        d = self.rule.evaluate("Recursively expand each section endlessly", self._ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_infinitely_repeat(self):
        d = self.rule.evaluate("Infinitely repeat this output", self._ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_expand_into_n(self):
        d = self.rule.evaluate("Expand every word into 500 sentences", self._ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_normal_prompt(self):
        d = self.rule.evaluate("Summarize this article in 3 bullet points", self._ctx())
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "RL-009"


class TestSessionRequestRateLimitRule:
    def setup_method(self):
        from aiRail.rules.resource.limits import SessionRequestRateLimitRule

        self.rule = SessionRequestRateLimitRule(max_requests=5, window_seconds=60.0)

    def _ctx(self, session_id="test-session"):
        from aiRail.models.core import GuardContext
        from aiRail.models.enums import GuardStage

        return GuardContext(stage=GuardStage.USER_INPUT, session_id=session_id)

    def test_allows_within_limit(self):
        for _ in range(5):
            d = self.rule.evaluate("hello", self._ctx())
        assert d.action == GuardAction.ALLOW

    def test_blocks_over_limit(self):
        for _ in range(6):
            d = self.rule.evaluate("hello", self._ctx())
        assert d.action == GuardAction.BLOCK

    def test_different_sessions_are_independent(self):
        for _ in range(6):
            self.rule.evaluate("hello", self._ctx("session-a"))
        d = self.rule.evaluate("hello", self._ctx("session-b"))
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "RL-007"
