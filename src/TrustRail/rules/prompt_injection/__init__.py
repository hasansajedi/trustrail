"""Prompt injection detection rules."""

from aiRail.rules.prompt_injection.advanced import (
    AdversarialSuffixRule,
    MultilingualInjectionRule,
    MultimodalInjectionRule,
    PayloadSplittingRule,
)
from aiRail.rules.prompt_injection.direct import (
    DirectInjectionRule,
    JailbreakRule,
    MetadataPoisoningRule,
    SystemOverrideRule,
    TokenSmugglingRule,
)
from aiRail.rules.prompt_injection.extraction_rules import (
    ModelExtractionProbeRule,
    SystemPromptExtractionRule,
    SystemPromptVerbatimEchoRule,
)
from aiRail.rules.prompt_injection.indirect import (
    DataExfiltrationRule,
    EncodingObfuscationRule,
    IndirectInjectionRule,
    ToolManipulationRule,
)
from aiRail.rules.prompt_injection.unicode_controls import InvisibleUnicodeRule

__all__ = [
    "AdversarialSuffixRule",
    "DataExfiltrationRule",
    "DirectInjectionRule",
    "EncodingObfuscationRule",
    "IndirectInjectionRule",
    "InvisibleUnicodeRule",
    "JailbreakRule",
    "MetadataPoisoningRule",
    "ModelExtractionProbeRule",
    "MultilingualInjectionRule",
    "MultimodalInjectionRule",
    "PayloadSplittingRule",
    "SystemOverrideRule",
    "SystemPromptExtractionRule",
    "SystemPromptVerbatimEchoRule",
    "TokenSmugglingRule",
    "ToolManipulationRule",
]
