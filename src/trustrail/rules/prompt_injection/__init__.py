"""Prompt injection detection rules."""

from trustrail.rules.prompt_injection.advanced import (
    AdversarialSuffixRule,
    MultilingualInjectionRule,
    MultimodalInjectionRule,
    PayloadSplittingRule,
)
from trustrail.rules.prompt_injection.boundary import CrossBoundaryInjectionRule
from trustrail.rules.prompt_injection.direct import (
    DirectInjectionRule,
    JailbreakRule,
    MetadataPoisoningRule,
    SystemOverrideRule,
    TokenSmugglingRule,
)
from trustrail.rules.prompt_injection.extraction_rules import (
    ModelExtractionProbeRule,
    SystemPromptExtractionRule,
    SystemPromptVerbatimEchoRule,
)
from trustrail.rules.prompt_injection.indirect import (
    DataExfiltrationRule,
    EncodingObfuscationRule,
    IndirectInjectionRule,
    ToolManipulationRule,
    ToolResponseInjectionRule,
)
from trustrail.rules.prompt_injection.unicode_controls import InvisibleUnicodeRule

__all__ = [
    "AdversarialSuffixRule",
    "CrossBoundaryInjectionRule",
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
    "ToolResponseInjectionRule",
]
