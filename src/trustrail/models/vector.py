"""Typed security models for vector and embedding workflows."""

from __future__ import annotations

import hashlib
import json
import math
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.core import Document
from trustrail.models.enums import GuardAction, Severity, TrustLevel
from trustrail.normalization import TextNormalizer

_normalizer = TextNormalizer()


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _normalized_content_digest(content: str) -> str:
    normalized = _normalizer.normalize(content).normalized.casefold()
    return hashlib.sha256(normalized.encode()).hexdigest()


def _vector_digest(vector: tuple[float, ...]) -> str:
    return _digest(list(vector))


class VectorVerificationCode(StrEnum):
    """Stable machine-readable vector workflow rejection reasons."""

    INDEX_NOT_ALLOWED = "index_not_allowed"
    EMBEDDING_MODEL_NOT_ALLOWED = "embedding_model_not_allowed"
    HIT_LIMIT_EXCEEDED = "hit_limit_exceeded"
    CATALOG_LIMIT_EXCEEDED = "catalog_limit_exceeded"
    CATALOG_DUPLICATE = "catalog_duplicate"
    UNKNOWN_INDEX_ENTRY = "unknown_index_entry"
    BROKEN_LINEAGE = "broken_lineage"
    TENANT_MISMATCH = "tenant_mismatch"
    USER_NOT_AUTHORIZED = "user_not_authorized"
    SCOPE_MISSING = "scope_missing"
    DOCUMENT_NOT_AUTHORIZED = "document_not_authorized"
    RESOURCE_NOT_AUTHORIZED = "resource_not_authorized"
    CONTENT_INTEGRITY_MISMATCH = "content_integrity_mismatch"
    INVALID_EMBEDDING_VECTOR = "invalid_embedding_vector"
    VECTOR_DIMENSION_MISMATCH = "vector_dimension_mismatch"
    INVALID_SIMILARITY_SCORE = "invalid_similarity_score"
    SIMILARITY_MISMATCH = "similarity_mismatch"
    RANK_MANIPULATION = "rank_manipulation"
    DUPLICATE_CONTENT = "duplicate_content"


class VectorPrincipal(BaseModel):
    """Authenticated identity supplied by trusted application code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    scopes: frozenset[str] = Field(default_factory=frozenset)


class VectorAccessPolicy(BaseModel):
    """Authoritative access policy carried with a vectorized resource."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=256)
    owner_id: str = Field(min_length=1, max_length=256)
    allowed_user_ids: frozenset[str] = Field(default_factory=frozenset)
    required_scopes: frozenset[str] = Field(default_factory=frozenset)
    allow_tenant_users: bool = False

    def authorizes(self, principal: VectorPrincipal) -> bool:
        """Return whether identity and scopes satisfy this exact policy."""
        if principal.tenant_id != self.tenant_id:
            return False
        user_allowed = (
            self.allow_tenant_users
            or principal.user_id == self.owner_id
            or principal.user_id in self.allowed_user_ids
        )
        return user_allowed and self.required_scopes.issubset(principal.scopes)


class VectorChunk(BaseModel):
    """Content chunk with immutable source, access, trust, and integrity labels."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chunk_id: str = Field(min_length=1, max_length=256)
    document_id: str = Field(min_length=1, max_length=256)
    resource_id: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    source: str = Field(min_length=1, max_length=2_048)
    source_url: str | None = Field(default=None, max_length=2_048)
    trust_level: TrustLevel
    access: VectorAccessPolicy
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_content(
        cls,
        *,
        chunk_id: str,
        document_id: str,
        resource_id: str,
        content: str,
        source: str,
        trust_level: TrustLevel,
        access: VectorAccessPolicy,
        source_url: str | None = None,
    ) -> VectorChunk:
        """Create a chunk with integrity-bound security metadata."""
        content_sha256 = _content_digest(content)
        normalized_sha256 = _normalized_content_digest(content)
        lineage = cls._lineage(
            chunk_id=chunk_id,
            document_id=document_id,
            resource_id=resource_id,
            source=source,
            source_url=source_url,
            trust_level=trust_level,
            access=access,
            content_sha256=content_sha256,
            normalized_content_sha256=normalized_sha256,
        )
        return cls(
            chunk_id=chunk_id,
            document_id=document_id,
            resource_id=resource_id,
            content=content,
            source=source,
            source_url=source_url,
            trust_level=trust_level,
            access=access,
            content_sha256=content_sha256,
            normalized_content_sha256=normalized_sha256,
            lineage_sha256=lineage,
        )

    @model_validator(mode="after")
    def validate_integrity(self) -> VectorChunk:
        if not self.has_valid_integrity:
            raise ValueError("vector chunk integrity check failed")
        return self

    @property
    def has_valid_integrity(self) -> bool:
        """Check content digests and the security-metadata lineage link."""
        return (
            self.content_sha256 == _content_digest(self.content)
            and self.normalized_content_sha256 == _normalized_content_digest(self.content)
            and self.lineage_sha256
            == self._lineage(
                chunk_id=self.chunk_id,
                document_id=self.document_id,
                resource_id=self.resource_id,
                source=self.source,
                source_url=self.source_url,
                trust_level=self.trust_level,
                access=self.access,
                content_sha256=self.content_sha256,
                normalized_content_sha256=self.normalized_content_sha256,
            )
        )

    @staticmethod
    def _lineage(
        *,
        chunk_id: str,
        document_id: str,
        resource_id: str,
        source: str,
        source_url: str | None,
        trust_level: TrustLevel,
        access: VectorAccessPolicy,
        content_sha256: str,
        normalized_content_sha256: str,
    ) -> str:
        return _digest(
            {
                "access": access.model_dump(mode="json"),
                "chunk_id": chunk_id,
                "content_sha256": content_sha256,
                "document_id": document_id,
                "normalized_content_sha256": normalized_content_sha256,
                "resource_id": resource_id,
                "source": source,
                "source_url": source_url,
                "trust_level": trust_level.value,
            }
        )


class VectorEmbedding(BaseModel):
    """Embedding bytes linked to the exact chunk and embedding model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chunk: VectorChunk
    embedding_model_id: str = Field(min_length=1, max_length=256)
    vector: tuple[float, ...] = Field(
        min_length=1,
        max_length=65_536,
        exclude=True,
        repr=False,
    )
    vector_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("vector")
    @classmethod
    def validate_vector(cls, vector: tuple[float, ...]) -> tuple[float, ...]:
        if not all(math.isfinite(value) for value in vector):
            raise ValueError("embedding vector values must be finite")
        if not any(value != 0.0 for value in vector):
            raise ValueError("embedding vector must have a non-zero norm")
        return vector

    @classmethod
    def from_chunk(
        cls,
        chunk: VectorChunk,
        *,
        embedding_model_id: str,
        vector: tuple[float, ...],
    ) -> VectorEmbedding:
        """Create embedding evidence linked to the validated chunk."""
        vector_sha256 = _vector_digest(vector)
        lineage_sha256 = _digest(
            {
                "chunk_lineage_sha256": chunk.lineage_sha256,
                "embedding_model_id": embedding_model_id,
                "vector_sha256": vector_sha256,
            }
        )
        return cls(
            chunk=chunk,
            embedding_model_id=embedding_model_id,
            vector=vector,
            vector_sha256=vector_sha256,
            lineage_sha256=lineage_sha256,
        )

    @model_validator(mode="after")
    def validate_integrity(self) -> VectorEmbedding:
        if not self.has_valid_integrity:
            raise ValueError("vector embedding lineage check failed")
        return self

    @property
    def has_valid_integrity(self) -> bool:
        """Check vector bytes and their link to the validated chunk."""
        expected = _digest(
            {
                "chunk_lineage_sha256": self.chunk.lineage_sha256,
                "embedding_model_id": self.embedding_model_id,
                "vector_sha256": self.vector_sha256,
            }
        )
        return (
            self.chunk.has_valid_integrity
            and all(math.isfinite(value) for value in self.vector)
            and any(value != 0.0 for value in self.vector)
            and self.vector_sha256 == _vector_digest(self.vector)
            and self.lineage_sha256 == expected
        )


class VectorIndexEntry(BaseModel):
    """Authoritative indexed embedding and its complete provenance chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str = Field(min_length=1, max_length=256)
    index_id: str = Field(min_length=1, max_length=256)
    namespace: str = Field(min_length=1, max_length=256)
    embedding: VectorEmbedding
    lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_embedding(
        cls,
        embedding: VectorEmbedding,
        *,
        entry_id: str,
        index_id: str,
        namespace: str,
    ) -> VectorIndexEntry:
        """Create an index entry linked to its embedding evidence."""
        lineage_sha256 = _digest(
            {
                "embedding_lineage_sha256": embedding.lineage_sha256,
                "entry_id": entry_id,
                "index_id": index_id,
                "namespace": namespace,
            }
        )
        return cls(
            entry_id=entry_id,
            index_id=index_id,
            namespace=namespace,
            embedding=embedding,
            lineage_sha256=lineage_sha256,
        )

    @model_validator(mode="after")
    def validate_integrity(self) -> VectorIndexEntry:
        if not self.has_valid_integrity:
            raise ValueError("vector index lineage check failed")
        return self

    @property
    def has_valid_integrity(self) -> bool:
        """Check the complete chunk-to-embedding-to-index lineage."""
        expected = _digest(
            {
                "embedding_lineage_sha256": self.embedding.lineage_sha256,
                "entry_id": self.entry_id,
                "index_id": self.index_id,
                "namespace": self.namespace,
            }
        )
        return self.embedding.has_valid_integrity and self.lineage_sha256 == expected


class VectorRetrievalRequest(BaseModel):
    """Authenticated retrieval intent and query embedding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=256)
    principal: VectorPrincipal
    index_id: str = Field(min_length=1, max_length=256)
    embedding_model_id: str = Field(min_length=1, max_length=256)
    authorized_document_ids: frozenset[str] = Field(min_length=1)
    authorized_resource_ids: frozenset[str] = Field(min_length=1)
    query_vector: tuple[float, ...] = Field(
        min_length=1,
        max_length=65_536,
        exclude=True,
        repr=False,
    )
    top_k: int = Field(default=5, ge=1, le=1_000)

    @field_validator("query_vector")
    @classmethod
    def validate_query_vector(cls, vector: tuple[float, ...]) -> tuple[float, ...]:
        if not all(math.isfinite(value) for value in vector):
            raise ValueError("query embedding values must be finite")
        if not any(value != 0.0 for value in vector):
            raise ValueError("query embedding must have a non-zero norm")
        return vector


class VectorRetrievalHit(BaseModel):
    """Untrusted vector-store result to verify against the trusted catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str = Field(min_length=1, max_length=256)
    content: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    similarity_score: float
    rank: int = Field(ge=1, le=10_000)


class VectorRetrievalPolicy(BaseModel):
    """Fail-closed limits and allowlists for vector retrieval verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_index_ids: frozenset[str] = Field(min_length=1)
    allowed_embedding_model_ids: frozenset[str] = Field(min_length=1)
    max_hits: int = Field(default=20, ge=1, le=1_000)
    max_catalog_entries: int = Field(default=1_000, ge=1, le=100_000)
    max_embedding_dimensions: int = Field(default=8_192, ge=1, le=65_536)
    similarity_tolerance: float = Field(default=1e-5, gt=0.0, le=0.1)
    max_identical_content_hits: int = Field(default=1, ge=1, le=100)
    require_sequential_ranks: bool = True


class VectorVerificationFinding(BaseModel):
    """Content-free explanation of a blocked retrieval result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: VectorVerificationCode
    severity: Severity
    message: str
    rank: int | None = None


class AuthorizedVectorHit(BaseModel):
    """Retrieved content with metadata copied only from the trusted catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    chunk_id: str
    document_id: str
    resource_id: str
    content: str = Field(exclude=True, repr=False)
    source: str
    source_url: str | None = None
    trust_level: TrustLevel
    similarity_score: float
    rank: int

    def to_document(self) -> Document:
        """Convert to a uniquely labeled document for guarded context assembly."""
        return Document(
            id=self.chunk_id,
            content=self.content,
            source=self.source,
            source_url=self.source_url,
            trust_level=self.trust_level,
            metadata={
                "vector_entry_id": self.entry_id,
                "root_document_id": self.document_id,
                "resource_id": self.resource_id,
                "similarity_rank": self.rank,
            },
        )


class VectorVerificationResult(BaseModel):
    """Allow or block decision for a complete vector retrieval operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    findings: tuple[VectorVerificationFinding, ...] = ()
    authorized_hits: tuple[AuthorizedVectorHit, ...] = Field(
        default=(),
        exclude=True,
        repr=False,
    )

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW
