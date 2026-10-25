"""Admit an ingestion connector and verify every document before indexing."""

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
    ConnectorSyncReport,
    ConnectorSyncRequest,
    ConnectorSyncStatus,
    IngestionConnectorGuard,
    IngestionConnectorKind,
    IngestionConnectorSigner,
)

now = datetime.now(tz=UTC)
source_uri = "https://knowledge.example.com/export"

# Keep these roles independent in production and load their keys from protected
# key-management systems. Generated keys make this example self-contained.
publisher = IngestionConnectorSigner.generate(authority_id="connector-publisher")
assessor = IngestionConnectorSigner.generate(authority_id="security-assessor")
controller = IngestionConnectorSigner.generate(authority_id="ingestion-control-plane")

parser = ConnectorParserIdentity(
    parser_id="markdown-parser",
    version="3.2.0",
    implementation_digest="b" * 64,
    configuration_digest="c" * 64,
)
configuration = ConnectorConfiguration(
    artifact=ConnectorArtifactIdentity(
        artifact_id="knowledge-loader",
        publisher="knowledge-team",
        source_uri="https://packages.example.com/knowledge-loader.whl",
        revision="2.4.1",
        artifact_digest=ArtifactDigest.from_bytes(b"reviewed connector artifact"),
        dependency_lock_digest="a" * 64,
    ),
    parser=parser,
    allowed_source_uris=frozenset({source_uri}),
    credential_references=frozenset({"vault:knowledge-read"}),
    schedule=ConnectorSchedule(schedule_id="knowledge-hourly", interval_seconds=3_600),
    network_destinations=(
        ConnectorNetworkDestination(scheme="https", host="knowledge.example.com"),
    ),
    expected_content_types=frozenset({"text/markdown"}),
    granted_scopes=frozenset({"knowledge:read"}),
    sandbox_controls=frozenset(ConnectorSandboxControl),
)

# The publisher signs the complete intended state. An independent assessor signs
# evidence for artifact integrity, dependencies, sandboxing, least privilege,
# and source ownership for that exact state.
manifest = publisher.sign_manifest(
    manifest_id="knowledge-loader-2.4.1",
    connector_id="knowledge-production",
    kind=IngestionConnectorKind.DOCUMENT_LOADER,
    configuration=configuration,
    issued_at=now,
    expires_at=now + timedelta(hours=4),
)
evidence = assessor.sign_evidence(
    evidence_id="knowledge-loader-review-42",
    connector_id=manifest.connector_id,
    manifest_digest=manifest.manifest_digest,
    configuration=configuration,
    issued_at=now,
    expires_at=now + timedelta(hours=1),
)
guard = IngestionConnectorGuard(
    manifest_keys=(publisher.trusted_key,),
    evidence_keys=(assessor.trusted_key,),
    control_signer=controller,
)
admission = guard.admit(manifest, evidence, now=now).admission
assert admission is not None

# Observe the real deployed artifact, parser, credentials, transforms, schedule,
# network destinations, scopes, and sandbox immediately before every sync.
state = ConnectorEffectiveState(
    observation_id="runtime-observation-42",
    connector_id=manifest.connector_id,
    manifest_digest=manifest.manifest_digest,
    evidence_digest=evidence.evidence_digest,
    configuration=configuration,
    observed_at=now,
)
request = ConnectorSyncRequest(
    sync_id="knowledge-sync-42",
    connector_id=manifest.connector_id,
    manifest_digest=manifest.manifest_digest,
    source_uris=frozenset({source_uri}),
    scheduled_for=now,
    effective_state=state,
)
authorization = guard.authorize_sync(manifest, admission, request, now=now).authorization
assert authorization is not None

verified = guard.verify_document(
    manifest,
    authorization,
    ConnectorDocument.from_content(
        document_id="document-42",
        content="# Incident response\nCall the on-duty team.",
        source_uri=source_uri,
        content_type="text/markdown",
        parser_candidates=(parser,),
    ),
    now=now,
).document
assert verified is not None and verified.provenance is not None

# Register every chunk/index/embedding/cache derivative so a connector incident
# can quarantine the complete transitive lineage.
chunk_reference = guard.register_downstream_artifact(
    "chunk-42", (verified.provenance.document_reference,)
)
guard.register_downstream_artifact("embedding-42", (chunk_reference,))

# Reverify signed provenance immediately before indexing or RAG use.
assert guard.verify_downstream(manifest, verified, now=now).is_allowed
completion = guard.complete_sync(
    manifest,
    authorization,
    ConnectorSyncReport(
        authorization_id=authorization.authorization_id,
        sync_id=authorization.sync_id,
        manifest_digest=authorization.manifest_digest,
        state_digest=authorization.state_digest,
        status=ConnectorSyncStatus.COMPLETE,
        expected_documents=1,
        processed_documents=1,
        failure_count=0,
        completed_at=now,
    ),
    now=now,
)
assert completion.is_allowed

incident = guard.quarantine_connector(manifest.connector_id)
print(incident.action.value, len(incident.affected_artifact_references))
