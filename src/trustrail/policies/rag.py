"""RAG security policy."""

from __future__ import annotations

from trustrail.models.enums import TrustLevel
from trustrail.policies.base import BasePolicy
from trustrail.rules.base import BaseRule
from trustrail.rules.rag import (
    MissingProvenanceRule,
    RAGContextLabelRule,
    RagContextTamperingRule,
    SourceTrustRule,
    UntrustedInstructionRule,
)


class RAGPolicy(BasePolicy):
    """Policy for RAG pipeline security."""

    def __init__(
        self,
        enabled: bool = True,
        require_provenance: bool = True,
        detect_instructions: bool = True,
        required_trust: TrustLevel = TrustLevel.SEMI_TRUSTED,
        detect_tampering: bool = True,
        require_context_labels: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.require_provenance = require_provenance
        self.detect_instructions = detect_instructions
        self.required_trust = required_trust
        self.detect_tampering = detect_tampering
        self.require_context_labels = require_context_labels

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = []
        if self.require_provenance:
            rules.append(MissingProvenanceRule())
        if self.detect_instructions:
            rules.append(UntrustedInstructionRule())
        if self.detect_tampering:
            rules.append(RagContextTamperingRule())
        if self.require_context_labels:
            rules.append(RAGContextLabelRule())
        rules.append(SourceTrustRule(required_trust=self.required_trust))
        return rules + self._rules
