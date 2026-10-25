"""Integration coverage for connector admission through protected RAG assembly."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    ArtifactDigest,
    ConnectorArtifactIdentity,
    ConnectorConfiguration,
    ConnectorDocument,
    ConnectorEffectiveState,
    ConnectorNetworkDestination,
    ConnectorParserIdentity,
    ConnectorSandboxControl,
    ConnectorSchedule,
    ConnectorSyncRequest,
    DataAssetKind,
    DataIngestionRecord,
    DataPoisoningPolicy,
    DataPoisoningVerifier,
    DataProvenance,
    DataSourcePolicy,
    Document,
    Guard,
    IngestionAuthorization,
    IngestionConnectorGuard,
    IngestionConnectorKind,
    IngestionConnectorSigner,
    TrustLevel,
)

NOW = datetime(2026, 10, 25, 14, tzinfo=UTC)
SOURCE = "https://knowledge.example.test/export"


def test_admitted_connector_output_flows_through_poisoning_and_rag_guards() -> None:
    publisher = IngestionConnectorSigner.generate(authority_id="knowledge-publisher")
    assessor = IngestionConnectorSigner.generate(authority_id="security-assessor")
    controller = IngestionConnectorSigner.generate(authority_id="ingestion-controller")
    parser = ConnectorParserIdentity(
        parser_id="html-reader",
        version="4.0.0",
        implementation_digest="b" * 64,
        configuration_digest="c" * 64,
    )
    configuration = ConnectorConfiguration(
        artifact=ConnectorArtifactIdentity(
            artifact_id="knowledge-crawler",
            publisher="knowledge-team",
            source_uri="https://packages.example.test/knowledge-crawler.whl",
            revision="4.0.0",
            artifact_digest=ArtifactDigest.from_bytes(b"reviewed crawler"),
            dependency_lock_digest="a" * 64,
        ),
        parser=parser,
        allowed_source_uris=frozenset({SOURCE}),
        credential_references=frozenset({"vault:knowledge-read"}),
        schedule=ConnectorSchedule(schedule_id="knowledge-hourly", interval_seconds=3_600),
        network_destinations=(
            ConnectorNetworkDestination(scheme="https", host="knowledge.example.test"),
        ),
        expected_content_types=frozenset({"text/html"}),
        granted_scopes=frozenset({"knowledge:read"}),
        sandbox_controls=frozenset(ConnectorSandboxControl),
    )
    manifest = publisher.sign_manifest(
        manifest_id="knowledge-v4",
        connector_id="knowledge-production",
        kind=IngestionConnectorKind.CRAWLER,
        configuration=configuration,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=3),
    )
    evidence = assessor.sign_evidence(
        evidence_id="knowledge-review-v4",
        connector_id=manifest.connector_id,
        manifest_digest=manifest.manifest_digest,
        configuration=configuration,
        issued_at=NOW,
    )
    connector_guard = IngestionConnectorGuard(
        manifest_keys=(publisher.trusted_key,),
        evidence_keys=(assessor.trusted_key,),
        control_signer=controller,
    )
    admission = connector_guard.admit(manifest, evidence, now=NOW).admission
    assert admission is not None
    state = ConnectorEffectiveState(
        observation_id="runtime-observation-v4",
        connector_id=manifest.connector_id,
        manifest_digest=manifest.manifest_digest,
        evidence_digest=evidence.evidence_digest,
        configuration=configuration,
        observed_at=NOW,
    )
    request = ConnectorSyncRequest(
        sync_id="knowledge-sync-42",
        connector_id=manifest.connector_id,
        manifest_digest=manifest.manifest_digest,
        source_uris=frozenset({SOURCE}),
        scheduled_for=NOW,
        effective_state=state,
    )
    authorization = connector_guard.authorize_sync(
        manifest, admission, request, now=NOW
    ).authorization
    assert authorization is not None
    content = "The incident response number is 555-0100."
    verified = connector_guard.verify_document(
        manifest,
        authorization,
        ConnectorDocument.from_content(
            document_id="knowledge-document-42",
            content=content,
            source_uri=SOURCE,
            content_type="text/html",
            parser_candidates=(parser,),
        ),
        now=NOW,
    ).document
    assert verified is not None and verified.provenance is not None
    assert isinstance(verified.content, str)
    assert connector_guard.verify_downstream(manifest, verified, now=NOW).is_allowed

    poisoning = DataPoisoningVerifier(
        DataPoisoningPolicy(
            sources=(
                DataSourcePolicy(
                    source_id=manifest.connector_id,
                    source_uri=SOURCE,
                    allowed_kinds=frozenset({DataAssetKind.RAG_DOCUMENT}),
                    trust_level=TrustLevel.SEMI_TRUSTED,
                    authorized_writers=frozenset({"ingestion-controller"}),
                    allowed_tenants=frozenset({"tenant-a"}),
                    allowed_purposes=frozenset({"rag-index"}),
                    allowed_versions=frozenset({manifest.manifest_digest}),
                ),
            )
        )
    )
    poisoning_result = poisoning.verify(
        DataIngestionRecord.from_content(
            item_id=verified.document_id,
            kind=DataAssetKind.RAG_DOCUMENT,
            content=verified.content,
            provenance=DataProvenance(
                source_id=manifest.connector_id,
                source_uri=verified.source_uri,
                version=manifest.manifest_digest,
                trust_level=TrustLevel.SEMI_TRUSTED,
            ),
            authorization=IngestionAuthorization(
                writer_id="ingestion-controller",
                tenant_id="tenant-a",
                purpose="rag-index",
            ),
        )
    )
    assert poisoning_result.is_allowed

    envelope = Guard.silent().build_rag_context(
        [
            Document(
                id=verified.document_id,
                content=verified.content,
                source=manifest.connector_id,
                source_url=verified.source_uri,
                trust_level=TrustLevel.SEMI_TRUSTED,
                metadata={
                    "connector_provenance_digest": verified.provenance.provenance_digest,
                },
            )
        ]
    )

    assert envelope.segments[0].content == content
    assert envelope.segments[0].provenance.source == manifest.connector_id
