"""Advanced prompt injection detection rules.

Covers multilingual, payload-splitting, adversarial-suffix, and multimodal attack vectors.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry
from trustrail.rules.prompt_injection.direct import (
    DirectInjectionRule,
    JailbreakRule,
    SystemOverrideRule,
)


@registry.register
class MultilingualInjectionRule(BaseRule):
    """Detects multilingual prompt injection attempts (PI-012).

    Identifies injection patterns in non-English languages that attempt to bypass
    English-only detection patterns.
    """

    rule_id = "PI-012"
    rule_name = "Multilingual Injection Detection"
    category = RuleCategory.PROMPT_INJECTION
    phase = RulePhase.DETECT
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Detects prompt injection attempts in multiple languages"
    owasp = ("LLM01",)

    # Common injection phrases in various languages
    MULTILINGUAL_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        # Spanish
        re.compile(r"ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+anteriores", re.IGNORECASE),
        re.compile(r"olvida\s+todo\s+lo\s+anterior", re.IGNORECASE),
        # French
        re.compile(
            r"ignore[zr]?\s+(?:toutes?\s+)?les\s+instructions\s+pr[ée]c[ée]dentes",
            re.IGNORECASE,
        ),
        re.compile(r"oublie[zr]?\s+tout", re.IGNORECASE),
        # German
        re.compile(r"ignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?anweisungen", re.IGNORECASE),
        re.compile(r"vergiss\s+alles", re.IGNORECASE),
        # Italian
        re.compile(r"ignora\s+(?:tutte?\s+)?le\s+istruzioni\s+precedenti", re.IGNORECASE),
        re.compile(r"dimentica\s+tutto", re.IGNORECASE),
        # Portuguese
        re.compile(r"ignore\s+(?:todas?\s+)?as\s+instru[çc][õo]es\s+anteriores", re.IGNORECASE),
        re.compile(r"esque[çc]a\s+tudo", re.IGNORECASE),
        # Chinese (Simplified) - romanized
        re.compile(r"[忽无][略视]\s*[之所有]*\s*[先之前]前\s*的?\s*指令", re.UNICODE),
        # Japanese - romanized common patterns
        re.compile(r"[前先][のに]\s*指示\s*を\s*[無忘][視れ]", re.UNICODE),
        # Russian (Cyrillic)
        re.compile(r"игнорируй\s+(?:все\s+)?(?:предыдущие\s+)?инструкции", re.IGNORECASE),
        re.compile(r"забудь\s+все", re.IGNORECASE),
        # Arabic (common injection patterns)
        re.compile(r"تجاهل\s+(?:كل\s+)?(?:ال)?تعليمات\s+السابقة", re.UNICODE),
        # Korean
        re.compile(r"[이전모든]\s*지시\s*사항\s*[을를]\s*무시", re.UNICODE),
    ]

    def __init__(self, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect multilingual injection patterns."""
        for pattern in self.MULTILINGUAL_PATTERNS:
            if pattern.search(value):
                return self._block(
                    "Multilingual prompt injection detected",
                    confidence=0.9,
                    pattern=pattern.pattern,
                )

        return self._allow()


@registry.register
class PayloadSplittingRule(BaseRule):
    """Detects payload-splitting injection attempts (PI-013).

    Identifies attempts to split malicious payloads across multiple inputs,
    context boundaries, or encoding layers to bypass single-input detection.
    """

    rule_id = "PI-013"
    rule_name = "Payload Splitting Detection"
    category = RuleCategory.PROMPT_INJECTION
    phase = RulePhase.DETECT
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Detects payload-splitting and fragmentation attacks"
    owasp = ("LLM01",)

    # Patterns indicating payload continuation or assembly
    SPLIT_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        # Explicit continuation markers
        re.compile(
            r"(?:continue|append|concat(?:enate)?|combine|merge|join)\s+"
            r"(?:\w+\s+)?(?:with|to|the|previous|above)",
            re.IGNORECASE,
        ),
        re.compile(r"part\s+\d+\s+of\s+\d+", re.IGNORECASE),
        re.compile(r"fragment\s+\d+", re.IGNORECASE),
        # Encoding/decoding instructions
        re.compile(
            r"(?:decode|decipher|decrypt|reassemble|reconstruct)\s+"
            r"(?:the\s+)?(?:\w+\s+)?(?:above|previous|following)",
            re.IGNORECASE,
        ),
        # Multi-step assembly
        re.compile(r"step\s+\d+:\s*(?:take|use|combine|add)", re.IGNORECASE),
        re.compile(r"(?:first|then|next|finally),?\s+(?:take|combine|merge)", re.IGNORECASE),
        # Base64/hex indicators with suspicious context
        re.compile(r"(?:base64|hex|encoded)\s+(?:instruction|command|payload)", re.IGNORECASE),
    ]

    def __init__(self, enabled: bool = True, sensitivity: float = 0.7) -> None:
        super().__init__(enabled=enabled)
        self.sensitivity = sensitivity

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect payload-splitting patterns."""
        matches = []
        for pattern in self.SPLIT_PATTERNS:
            if pattern.search(value):
                matches.append(pattern.pattern)

        if matches:
            # Check for suspicious encoded content
            has_encoded = any(marker in value.lower() for marker in ["base64", "0x", "\\x", "&#"])

            confidence = 0.95 if has_encoded else 0.8

            return self._block(
                f"Payload-splitting attack detected: {len(matches)} indicators",
                confidence=confidence,
                patterns=matches,
                has_encoded_content=has_encoded,
            )

        return self._allow()


@registry.register
class AdversarialSuffixRule(BaseRule):
    """Detects adversarial suffix injection attempts (PI-014).

    Identifies suffixes designed to manipulate model behavior through
    gradient-based optimization or learned attack patterns.
    """

    rule_id = "PI-014"
    rule_name = "Adversarial Suffix Detection"
    category = RuleCategory.PROMPT_INJECTION
    phase = RulePhase.DETECT
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Detects adversarial suffix and optimization-based attacks"
    owasp = ("LLM01",)

    # Patterns indicating adversarial suffixes
    ADVERSARIAL_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        # Gibberish/optimized tokens (common in GCG attacks)
        re.compile(r"(?:[a-z]{1,3}\s+){10,}", re.IGNORECASE),
        re.compile(r"(?:\S+\s+){5,}(?:!!+|\.{3,}|\?{3,})", re.IGNORECASE),
        # Suspicious repetition patterns
        re.compile(r"(\b\w{1,4}\b\s*){15,}", re.IGNORECASE),
        re.compile(
            r"(sure|okay|yes|absolutely|certainly)(\s+\1){5,}",
            re.IGNORECASE,
        ),
        # Ending manipulation
        re.compile(r"(?:!{5,}|\?{5,}|\.{5,})", re.IGNORECASE),
        re.compile(
            r"(?:now|sure|yes|okay)\s*[!.]{3,}\s*(?:now\s+)?(?:ignore|disregard|forget)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:yes|okay|sure)[!.]{3,}\s+(?:now\s+)?(?:ignore|disregard|forget)",
            re.IGNORECASE,
        ),
        # Known GCG-style patterns
        re.compile(r"describing\.\+\s*(?:]}}\s*)?similarly\s+NOW\s+write", re.IGNORECASE),
        re.compile(r"[{}\[\]]+\s*(?:describing|similarly|write)", re.IGNORECASE),
    ]

    def __init__(self, enabled: bool = True, token_entropy_threshold: float = 2.5) -> None:
        super().__init__(enabled=enabled)
        self.token_entropy_threshold = token_entropy_threshold

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect adversarial suffix patterns."""
        for pattern in self.ADVERSARIAL_PATTERNS:
            match = pattern.search(value)
            if match:
                # Calculate basic token diversity (low diversity = suspicious)
                words = value.split()
                if len(words) > 10:
                    unique_ratio = len(set(words[-20:])) / min(20, len(words))
                    confidence = 0.95 if unique_ratio < 0.3 else 0.8
                else:
                    confidence = 0.8

                return self._block(
                    "Adversarial suffix pattern detected",
                    confidence=confidence,
                    pattern=pattern.pattern,
                    matched_text=match.group()[:100],  # First 100 chars of match
                )

        return self._allow()


@registry.register
class MultimodalInjectionRule(BaseRule):
    """Detects multimodal prompt injection attempts (PI-015).

    Identifies injection patterns that exploit image, audio, or other
    non-text modalities to bypass text-only defenses.
    """

    rule_id: ClassVar[str] = "PI-015"
    rule_name: ClassVar[str] = "Multimodal Injection Detection"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects multimodal prompt injection via images, audio, etc."
    owasp: ClassVar[list[str]] = ["LLM01"]

    DEFAULT_EXTRACTED_TEXT_KEYS: ClassVar[dict[str, str]] = {
        "image_ocr_text": "image",
        "image_alt_text": "image",
        "audio_transcript": "audio",
        "video_transcript": "video",
        "attachment_text": "file",
    }
    ALLOWED_MODALITIES: ClassVar[frozenset[str]] = frozenset(
        {"image", "audio", "video", "file", "unknown"}
    )

    # Patterns indicating multimodal injection attempts
    MULTIMODAL_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        # References to embedded instructions
        re.compile(
            r"(?:the\s+)?image\s+(?:contains|shows|says|tells|instructs)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:in\s+the\s+)?(?:picture|photo|image)\s*[,:]\s*"
            r"(?:ignore|disregard|do|execute)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:the\s+)?(?:audio|sound|voice)\s+(?:says|instructs|commands)",
            re.IGNORECASE,
        ),
        # OCR/vision-based injection
        re.compile(
            r"read\s+(?:the\s+)?(?:text|words|instructions)\s+(?:in|from)\s+"
            r"(?:the\s+)?(?:image|picture|photo)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:the\s+)?(?:image|picture)\s+has\s+(?:text|instructions|commands)",
            re.IGNORECASE,
        ),
        # Steganography references
        re.compile(
            r"hidden\s+(?:in|within)\s+(?:the\s+)?(?:image|audio|file|data)",
            re.IGNORECASE,
        ),
        re.compile(r"steganograph(?:y|ic)", re.IGNORECASE),
        re.compile(
            r"(?:decode|extract|read)\s+(?:the\s+)?(?:hidden|embedded)\s+"
            r"(?:message|instruction)",
            re.IGNORECASE,
        ),
        # Cross-modal attacks
        re.compile(
            r"(?:the\s+)?(?:image|audio)\s+(?:overrides|replaces|modifies)\s+"
            r"(?:the\s+)?(?:text|instruction)",
            re.IGNORECASE,
        ),
    ]

    def __init__(
        self,
        enabled: bool = True,
        *,
        scan_extracted_content: bool = True,
        max_extracted_chars: int = 10_000,
        extracted_text_keys: dict[str, str] | None = None,
    ) -> None:
        super().__init__(enabled=enabled)
        if max_extracted_chars < 1:
            raise ValueError("max_extracted_chars must be greater than zero")
        self.scan_extracted_content = scan_extracted_content
        self.max_extracted_chars = max_extracted_chars
        self.extracted_text_keys = dict(extracted_text_keys or self.DEFAULT_EXTRACTED_TEXT_KEYS)
        self._content_scanners: tuple[BaseRule, ...] = (
            DirectInjectionRule(),
            JailbreakRule(),
            SystemOverrideRule(),
        )

    def _normalize_modality(self, value: object) -> str:
        if isinstance(value, str) and value.lower() in self.ALLOWED_MODALITIES:
            return value.lower()
        return "unknown"

    def _iter_extracted_content(self, context: GuardContext) -> Iterator[tuple[str, str, str]]:
        """Yield source key, modality, and extracted text from supported metadata."""
        metadata = context.metadata
        for key, modality in self.extracted_text_keys.items():
            extracted_text = metadata.get(key)
            if isinstance(extracted_text, str) and extracted_text:
                yield key, self._normalize_modality(modality), extracted_text

        multimodal_inputs = metadata.get("multimodal_inputs")
        if not isinstance(multimodal_inputs, list):
            return

        for index, item in enumerate(multimodal_inputs):
            if not isinstance(item, Mapping):
                continue
            extracted_text = item.get("extracted_text")
            if not isinstance(extracted_text, str) or not extracted_text:
                continue
            source_key = f"multimodal_inputs[{index}].extracted_text"
            yield source_key, self._normalize_modality(item.get("modality")), extracted_text

    def _scan_extracted_content(
        self,
        source_key: str,
        modality: str,
        extracted_text: str,
        context: GuardContext,
    ) -> GuardDecision | None:
        scanned_text = extracted_text[: self.max_extracted_chars]

        for scanner in self._content_scanners:
            decision = scanner.evaluate(scanned_text, context)
            if decision.action == GuardAction.BLOCK:
                return self._block(
                    f"Prompt injection detected in extracted {modality} content",
                    confidence=0.98,
                    modality=modality,
                    source_key=source_key,
                    detector_rule_id=scanner.rule_id,
                    content_length=len(extracted_text),
                    scanned_characters=len(scanned_text),
                    truncated=len(extracted_text) > len(scanned_text),
                )

        for pattern in self.MULTIMODAL_PATTERNS:
            if pattern.search(scanned_text):
                return self._block(
                    f"Multimodal injection indicator detected in extracted {modality} content",
                    confidence=0.95,
                    modality=modality,
                    source_key=source_key,
                    detector_rule_id=self.rule_id,
                    content_length=len(extracted_text),
                    scanned_characters=len(scanned_text),
                    truncated=len(extracted_text) > len(scanned_text),
                )

        return None

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect multimodal injection patterns."""
        # Check for multimodal context
        has_image = context.metadata.get("has_image", False)
        has_audio = context.metadata.get("has_audio", False)
        has_file = context.metadata.get("has_file", False)

        matches = []
        for pattern in self.MULTIMODAL_PATTERNS:
            if pattern.search(value):
                matches.append(pattern.pattern)

        if matches:
            # Higher confidence if multimodal content is present
            if has_image or has_audio or has_file:
                confidence = 0.95
                modalities = []
                if has_image:
                    modalities.append("image")
                if has_audio:
                    modalities.append("audio")
                if has_file:
                    modalities.append("file")

                return self._block(
                    f"Multimodal injection detected with {', '.join(modalities)} present",
                    confidence=confidence,
                    patterns=matches,
                    modalities=modalities,
                )
            else:
                # Suspicious but no multimodal content
                return self._block(
                    "Potential multimodal injection pattern without multimodal content",
                    confidence=0.7,
                    patterns=matches,
                )

        if self.scan_extracted_content:
            for source_key, modality, extracted_text in self._iter_extracted_content(context):
                decision = self._scan_extracted_content(
                    source_key,
                    modality,
                    extracted_text,
                    context,
                )
                if decision is not None:
                    return decision

        return self._allow()
