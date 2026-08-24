"""Prompt injection policy."""

from __future__ import annotations

from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.prompt_injection import (
    AdversarialSuffixRule,
    DataExfiltrationRule,
    DirectInjectionRule,
    EncodingObfuscationRule,
    IndirectInjectionRule,
    JailbreakRule,
    MetadataPoisoningRule,
    ModelExtractionProbeRule,
    MultilingualInjectionRule,
    MultimodalInjectionRule,
    PayloadSplittingRule,
    SystemOverrideRule,
    SystemPromptExtractionRule,
    SystemPromptVerbatimEchoRule,
    TokenSmugglingRule,
    ToolManipulationRule,
    ToolResponseInjectionRule,
)


class PromptInjectionPolicy(BasePolicy):
    """Policy grouping all prompt injection detection rules."""

    def __init__(
        self,
        enabled: bool = True,
        include_indirect: bool = True,
        include_jailbreak: bool = True,
        include_exfiltration: bool = True,
        include_tool_manipulation: bool = True,
        include_metadata_poisoning: bool = True,
        include_extraction_probes: bool = True,
        include_prompt_echo: bool = True,
        include_encoding_obfuscation: bool = True,
        include_token_smuggling: bool = True,
        include_multimodal: bool = True,
        include_multilingual: bool = True,
        include_payload_splitting: bool = True,
        include_adversarial_suffix: bool = True,
        include_tool_response: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.include_indirect = include_indirect
        self.include_jailbreak = include_jailbreak
        self.include_exfiltration = include_exfiltration
        self.include_tool_manipulation = include_tool_manipulation
        self.include_metadata_poisoning = include_metadata_poisoning
        self.include_extraction_probes = include_extraction_probes
        self.include_prompt_echo = include_prompt_echo
        self.include_encoding_obfuscation = include_encoding_obfuscation
        self.include_token_smuggling = include_token_smuggling
        self.include_multimodal = include_multimodal
        self.include_multilingual = include_multilingual
        self.include_payload_splitting = include_payload_splitting
        self.include_adversarial_suffix = include_adversarial_suffix
        self.include_tool_response = include_tool_response

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = [
            DirectInjectionRule(),
            SystemOverrideRule(),
        ]
        if self.include_jailbreak:
            rules.append(JailbreakRule())
        if self.include_indirect:
            rules.append(IndirectInjectionRule())
        if self.include_exfiltration:
            rules.append(DataExfiltrationRule())
        if self.include_tool_manipulation:
            rules.append(ToolManipulationRule())
        if self.include_metadata_poisoning:
            rules.append(MetadataPoisoningRule())
        if self.include_extraction_probes:
            rules.extend([ModelExtractionProbeRule(), SystemPromptExtractionRule()])
        if self.include_prompt_echo:
            rules.append(SystemPromptVerbatimEchoRule())
        if self.include_encoding_obfuscation:
            rules.append(EncodingObfuscationRule())
        if self.include_token_smuggling:
            rules.append(TokenSmugglingRule())
        if self.include_multimodal:
            rules.append(MultimodalInjectionRule())
        if self.include_multilingual:
            rules.append(MultilingualInjectionRule())
        if self.include_payload_splitting:
            rules.append(PayloadSplittingRule())
        if self.include_adversarial_suffix:
            rules.append(AdversarialSuffixRule())
        if self.include_tool_response:
            rules.append(ToolResponseInjectionRule())
        return rules + self._rules
