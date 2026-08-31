"""Verify source, writer, tenant, version, and content before indexing data."""

from trustrail import (
    DataAssetKind,
    DataIngestionRecord,
    DataPoisoningPolicy,
    DataPoisoningVerifier,
    DataProvenance,
    DataSourcePolicy,
    Document,
    Guard,
    IngestionAuthorization,
    TrustLevel,
)

source_policy = DataSourcePolicy(
    source_id="knowledge-export",
    source_uri="https://content.example.test/export",
    allowed_kinds=frozenset({DataAssetKind.RAG_DOCUMENT}),
    trust_level=TrustLevel.SEMI_TRUSTED,
    authorized_writers=frozenset({"ingestion-service"}),
    allowed_tenants=frozenset({"tenant-a"}),
    allowed_purposes=frozenset({"rag_document"}),
    allowed_versions=frozenset({"snapshot-8f71c2"}),
)
verifier = DataPoisoningVerifier(DataPoisoningPolicy(sources=(source_policy,)))

record = DataIngestionRecord.from_content(
    item_id="refund-policy",
    kind=DataAssetKind.RAG_DOCUMENT,
    content="The approved refund period is thirty days.",
    provenance=DataProvenance(
        source_id=source_policy.source_id,
        source_uri=source_policy.source_uri,
        version="snapshot-8f71c2",
        trust_level=TrustLevel.SEMI_TRUSTED,
    ),
    authorization=IngestionAuthorization(
        writer_id="ingestion-service",
        tenant_id="tenant-a",
        purpose="rag_document",
    ),
)

accepted = verifier.require(record)
assert isinstance(accepted.content, str)

# Only verified data is converted into an indexable application document.
document = Document(
    id=accepted.item_id,
    content=accepted.content,
    source=accepted.provenance.source_id,
    source_url=accepted.provenance.source_uri,
    trust_level=accepted.provenance.trust_level,
)
envelope = Guard.silent().build_rag_context([document])
print(envelope.render())
