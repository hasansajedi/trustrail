"""System-prompt construction validation and generated-output leakage detection."""

from __future__ import annotations

import re

from trustrail.exceptions import SystemPromptLeakageError, SystemPromptValidationError
from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction, GuardStage, Severity
from trustrail.models.system_prompt import (
    SystemPromptLeakageCode,
    SystemPromptLeakageFinding,
    SystemPromptLeakagePolicy,
    SystemPromptLeakageResult,
    SystemPromptPolicy,
    SystemPromptReference,
    SystemPromptTemplate,
    SystemPromptValidationCode,
    SystemPromptValidationFinding,
    SystemPromptValidationResult,
    ValidatedSystemPrompt,
)
from trustrail.normalization import TextNormalizer
from trustrail.policies.sensitive_data import SensitiveDataPolicy
from trustrail.rules.prompt_injection.extraction_rules import SystemPromptVerbatimEchoRule

_PLACEHOLDER_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
_SENTENCE_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+|[\r\n]+")
_WHITESPACE_RE = re.compile(r"\s+")
_AUTHORIZATION_LOGIC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:role|permission|privilege|oauth\s+scope)\s+"
        r"(?:is|equals?|grants?|allows?|permits?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:if|when|unless)\s+(?:the\s+)?user\s+"
        r"(?:is|has|holds?)\s+(?:an?\s+)?(?:role|permission|scope|admin|owner)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:authorize|allow|deny|approve|reject)\s+(?:the\s+)?"
        r"(?:request|action|operation|transaction)\s+(?:if|when|unless)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:admin|administrator|superuser|owner)\s+"
        r"(?:can|may|is\s+allowed\s+to)\s+"
        r"(?:access|read|write|delete|modify|approve|transfer|withdraw)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:transaction|transfer|withdrawal|loan|spending)\s+limit\s*(?:is|=|:)",
        re.IGNORECASE,
    ),
)


class SystemPromptValidator:
    """Render only explicitly classified, non-sensitive system-prompt data."""

    def __init__(self, policy: SystemPromptPolicy | None = None) -> None:
        self._policy = (policy or SystemPromptPolicy()).model_copy(deep=True)
        self._sensitive_rules = tuple(SensitiveDataPolicy().get_rules())

    @property
    def policy(self) -> SystemPromptPolicy:
        """Return a defensive copy of the active validation policy."""
        return self._policy.model_copy(deep=True)

    def validate(self, prompt: SystemPromptTemplate) -> SystemPromptValidationResult:
        """Validate and render a template without exposing rejected content."""
        findings = self._structural_findings(prompt)
        findings.extend(self._content_findings(prompt.template))
        if findings:
            return self._blocked(findings)

        variables = {variable.name: variable.value for variable in prompt.variables}
        rendered = _PLACEHOLDER_RE.sub(lambda match: variables[match.group(1)], prompt.template)
        if len(rendered) > self._policy.max_prompt_chars:
            findings.append(
                self._finding(
                    SystemPromptValidationCode.PROMPT_TOO_LARGE,
                    "Rendered system prompt exceeds the configured size limit",
                )
            )
        findings.extend(self._content_findings(rendered))
        if findings:
            return self._blocked(findings)

        return SystemPromptValidationResult(
            action=GuardAction.ALLOW,
            validated_prompt=ValidatedSystemPrompt(
                template_id=prompt.template_id,
                content=rendered,
            ),
        )

    def require(self, prompt: SystemPromptTemplate) -> ValidatedSystemPrompt:
        """Return validated prompt content or raise before provider submission."""
        result = self.validate(prompt)
        if not result.is_valid or result.validated_prompt is None:
            raise SystemPromptValidationError(result=result)
        return result.validated_prompt

    def _structural_findings(
        self,
        prompt: SystemPromptTemplate,
    ) -> list[SystemPromptValidationFinding]:
        findings: list[SystemPromptValidationFinding] = []
        placeholders = set(_PLACEHOLDER_RE.findall(prompt.template))
        declared = {variable.name for variable in prompt.variables}
        without_placeholders = _PLACEHOLDER_RE.sub("", prompt.template)
        if "{{" in without_placeholders or "}}" in without_placeholders:
            findings.append(
                self._finding(
                    SystemPromptValidationCode.INVALID_TEMPLATE,
                    "System prompt contains an invalid placeholder",
                )
            )
        if self._policy.reject_undeclared_variables:
            for _name in sorted(placeholders.difference(declared)):
                findings.append(
                    self._finding(
                        SystemPromptValidationCode.UNDECLARED_VARIABLE,
                        "System prompt references an undeclared variable",
                    )
                )
        if self._policy.reject_unused_variables:
            for _name in sorted(declared.difference(placeholders)):
                findings.append(
                    self._finding(
                        SystemPromptValidationCode.UNUSED_VARIABLE,
                        "Declared system-prompt variable is unused",
                    )
                )
        for variable in prompt.variables:
            if variable.data_class in self._policy.forbidden_data_classes:
                findings.append(
                    self._finding(
                        SystemPromptValidationCode.FORBIDDEN_DATA_CLASS,
                        "Variable classification is forbidden in system prompts",
                    )
                )
        if len(prompt.template) > self._policy.max_prompt_chars:
            findings.append(
                self._finding(
                    SystemPromptValidationCode.PROMPT_TOO_LARGE,
                    "System-prompt template exceeds the configured size limit",
                )
            )
        return findings

    def _content_findings(self, content: str) -> list[SystemPromptValidationFinding]:
        findings: list[SystemPromptValidationFinding] = []
        context = GuardContext(stage=GuardStage.SYSTEM_PROMPT)
        if self._policy.reject_sensitive_data:
            seen_rule_ids: set[str] = set()
            for rule in self._sensitive_rules:
                decision = rule.evaluate(content, context)
                if decision.finding is None or rule.rule_id in seen_rule_ids:
                    continue
                seen_rule_ids.add(rule.rule_id)
                findings.append(
                    self._finding(
                        SystemPromptValidationCode.SENSITIVE_DATA_DETECTED,
                        "Sensitive data is not permitted in a system prompt",
                        detector_rule_id=rule.rule_id,
                    )
                )
        if self._policy.reject_authorization_logic and any(
            pattern.search(content) for pattern in _AUTHORIZATION_LOGIC_PATTERNS
        ):
            findings.append(
                self._finding(
                    SystemPromptValidationCode.AUTHORIZATION_LOGIC_DETECTED,
                    "Security-critical authorization logic must be enforced outside the model",
                )
            )
        return findings

    @staticmethod
    def _finding(
        code: SystemPromptValidationCode,
        message: str,
        *,
        detector_rule_id: str | None = None,
    ) -> SystemPromptValidationFinding:
        return SystemPromptValidationFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=message,
            detector_rule_id=detector_rule_id,
        )

    @staticmethod
    def _blocked(
        findings: list[SystemPromptValidationFinding],
    ) -> SystemPromptValidationResult:
        return SystemPromptValidationResult(action=GuardAction.BLOCK, findings=tuple(findings))


class SystemPromptLeakageDetector:
    """Compare generated output with private prompt references using bounded work."""

    def __init__(self, policy: SystemPromptLeakagePolicy | None = None) -> None:
        self._policy = (policy or SystemPromptLeakagePolicy()).model_copy(deep=True)
        self._normalizer = TextNormalizer()
        self._echo_rule = SystemPromptVerbatimEchoRule()

    @property
    def policy(self) -> SystemPromptLeakagePolicy:
        """Return a defensive copy of the active leakage policy."""
        return self._policy.model_copy(deep=True)

    def detect(
        self,
        output: str,
        references: tuple[SystemPromptReference, ...] | list[SystemPromptReference],
    ) -> SystemPromptLeakageResult:
        """Block structured, partial, or encoded reproduction of a prompt."""
        findings: list[SystemPromptLeakageFinding] = []
        if len(output) > self._policy.max_output_chars:
            return SystemPromptLeakageResult(
                action=GuardAction.BLOCK,
                findings=(
                    self._finding(
                        SystemPromptLeakageCode.OUTPUT_TOO_LARGE,
                        "Generated output exceeds the configured scan limit",
                    ),
                ),
            )
        bounded_output = output
        if self._policy.detect_structured_echo:
            echo = self._echo_rule.evaluate(
                bounded_output,
                GuardContext(stage=GuardStage.LLM_RESPONSE),
            )
            if echo.action == GuardAction.BLOCK:
                findings.append(
                    self._finding(
                        SystemPromptLeakageCode.STRUCTURED_ECHO,
                        "Generated output announces or structures a system-prompt disclosure",
                    )
                )

        output_candidates: list[tuple[str, bool]] = [(self._normalize(bounded_output), False)]
        if self._policy.detect_encoded_output:
            for decoded in self._normalizer.extract_base64_payloads(bounded_output)[:16]:
                output_candidates.append((self._normalize(decoded), True))

        for reference in references:
            if len(reference.content) > self._policy.max_prompt_chars:
                findings.append(
                    self._finding(
                        SystemPromptLeakageCode.REFERENCE_TOO_LARGE,
                        "System-prompt reference exceeds the configured scan limit",
                        prompt_id=reference.prompt_id,
                    )
                )
                continue
            fragments = self._fragments(reference.content)
            matched_code: SystemPromptLeakageCode | None = None
            for candidate, is_decoded in output_candidates:
                if any(fragment in candidate for fragment in fragments):
                    matched_code = (
                        SystemPromptLeakageCode.ENCODED_FRAGMENT
                        if is_decoded
                        else SystemPromptLeakageCode.VERBATIM_FRAGMENT
                    )
                    break
            if matched_code is not None:
                findings.append(
                    self._finding(
                        matched_code,
                        "Generated output reproduces a protected system-prompt fragment",
                        prompt_id=reference.prompt_id,
                    )
                )

        if findings:
            return SystemPromptLeakageResult(
                action=GuardAction.BLOCK,
                findings=tuple(findings),
            )
        return SystemPromptLeakageResult(action=GuardAction.ALLOW)

    def require_safe(
        self,
        output: str,
        references: tuple[SystemPromptReference, ...] | list[SystemPromptReference],
    ) -> None:
        """Raise before delivery when generated output leaks prompt material."""
        result = self.detect(output, references)
        if result.is_blocked:
            raise SystemPromptLeakageError(result=result)

    def _fragments(self, prompt: str) -> tuple[str, ...]:
        normalized = self._normalize(prompt)
        fragments: set[str] = {
            part
            for part in _SENTENCE_BOUNDARY_RE.split(normalized)
            if len(part) >= self._policy.min_fragment_chars
        }
        if len(normalized) >= self._policy.min_fragment_chars:
            fragments.add(normalized)
        words = normalized.split()
        window = self._policy.fragment_words
        step = max(1, window // 2)
        for start in range(0, max(0, len(words) - window + 1), step):
            fragment = " ".join(words[start : start + window])
            if len(fragment) >= self._policy.min_fragment_chars:
                fragments.add(fragment)
            if len(fragments) >= self._policy.max_fragments_per_prompt:
                break
        return tuple(sorted(fragments, key=len, reverse=True))

    def _normalize(self, value: str) -> str:
        normalized = self._normalizer.normalize(value).normalized
        return _WHITESPACE_RE.sub(" ", normalized).strip().casefold()

    @staticmethod
    def _finding(
        code: SystemPromptLeakageCode,
        message: str,
        *,
        prompt_id: str | None = None,
    ) -> SystemPromptLeakageFinding:
        return SystemPromptLeakageFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=message,
            prompt_id=prompt_id,
        )
