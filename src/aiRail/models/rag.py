"""Structured models for provenance-labeled RAG context."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from trustrail.models.core import Document, GuardContext
from trustrail.models.enums import GuardStage, TrustLevel

RAG_CONTEXT_KIND: Literal["trustrail.rag_context.v1"] = "trustrail.rag_context.v1"
RAG_CONTEXT_CHANNEL: Literal["retrieved_data"] = "retrieved_data"


def _integrity_digest(
    *,
    document_id: str,
    content: str,
    source: str | None,
    source_url: str | None,
    trust_level: TrustLevel,
) -> str:
    """Return a deterministic digest covering content and its security labels."""
    canonical = json.dumps(
        {
            "content": content,
            "document_id": document_id,
            "source": source,
            "source_url": source_url,
            "trust_level": trust_level.value,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class ProvenanceLabel(BaseModel):
    """Immutable source, trust, and integrity labels for retrieved content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: str = Field(min_length=1)
    source: str | None = None
    source_url: str | None = None
    trust_level: TrustLevel
    integrity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def has_source(self) -> bool:
        """Return whether at least one source identifier is present."""
        return any(value and value.strip() for value in (self.source, self.source_url))


class RAGContextSegment(BaseModel):
    """Retrieved text kept inside a dedicated data field with its labels."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provenance: ProvenanceLabel
    content: str

    @model_validator(mode="after")
    def validate_integrity(self) -> RAGContextSegment:
        """Reject content or label mutation after the envelope was assembled."""
        expected = _integrity_digest(
            document_id=self.provenance.document_id,
            content=self.content,
            source=self.provenance.source,
            source_url=self.provenance.source_url,
            trust_level=self.provenance.trust_level,
        )
        if self.provenance.integrity_sha256 != expected:
            raise ValueError("RAG context segment integrity check failed")
        return self


class RAGContextEnvelope(BaseModel):
    """Structurally separated retrieved data with immutable provenance labels.

    Use :meth:`from_documents` instead of concatenating retrieved text. The JSON
    representation keeps attacker-controlled content inside a data field and
    retains source and trust information through prompt assembly.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["trustrail.rag_context.v1"] = RAG_CONTEXT_KIND
    channel: Literal["retrieved_data"] = RAG_CONTEXT_CHANNEL
    segments: tuple[RAGContextSegment, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_document_ids(self) -> RAGContextEnvelope:
        """Reject ambiguous provenance caused by repeated document IDs."""
        document_ids = [segment.provenance.document_id for segment in self.segments]
        if len(document_ids) != len(set(document_ids)):
            raise ValueError("RAG context document IDs must be unique")
        return self

    @classmethod
    def from_documents(
        cls,
        documents: list[Document],
        *,
        require_provenance: bool = True,
    ) -> RAGContextEnvelope:
        """Build an envelope while preserving application-assigned labels."""
        if not documents:
            raise ValueError("At least one RAG document is required")

        segments: list[RAGContextSegment] = []
        for index, document in enumerate(documents):
            has_source = any(
                value and value.strip() for value in (document.source, document.source_url)
            )
            if require_provenance and not has_source:
                raise ValueError(f"RAG document at index {index} lacks source provenance")
            label = ProvenanceLabel(
                document_id=document.id,
                source=document.source,
                source_url=document.source_url,
                trust_level=document.trust_level,
                integrity_sha256=_integrity_digest(
                    document_id=document.id,
                    content=document.content,
                    source=document.source,
                    source_url=document.source_url,
                    trust_level=document.trust_level,
                ),
            )
            segments.append(RAGContextSegment(provenance=label, content=document.content))
        return cls(segments=tuple(segments))

    def render(self) -> str:
        """Render a machine-readable prompt value without delimiter injection."""
        return self.model_dump_json()

    def guard_context(self) -> GuardContext:
        """Create privacy-safe evaluation metadata for the assembled context."""
        trust_counts = Counter(segment.provenance.trust_level.value for segment in self.segments)
        trust_order = {
            TrustLevel.UNTRUSTED: 0,
            TrustLevel.SEMI_TRUSTED: 1,
            TrustLevel.TRUSTED: 2,
        }
        minimum_trust = min(
            (segment.provenance.trust_level for segment in self.segments),
            key=trust_order.__getitem__,
        )
        metadata: dict[str, Any] = {
            "rag_context_envelope": {
                "channel": self.channel,
                "document_count": len(self.segments),
                "kind": self.kind,
                "trust_counts": dict(trust_counts),
            }
        }
        return GuardContext(
            stage=GuardStage.RAG_CONTEXT,
            trust_level=minimum_trust,
            metadata=metadata,
        )
