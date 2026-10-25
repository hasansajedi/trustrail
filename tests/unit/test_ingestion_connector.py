"""Unit tests for ingestion connector admission and continuous verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    AdmittedIngestionConnector,
    ArtifactDigest,
    AuthorizedConnectorSync,
    ConnectorAdmissionControl,
    ConnectorAdmissionEvidence,
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
    ConnectorTrustedKey,
    GuardAction,
    IngestionConnectorCode,
    IngestionConnectorDecision,
    IngestionConnectorGuard,
    IngestionConnectorKind,
    IngestionConnectorManifest,
    IngestionConnectorSigner,
    IngestionConnectorStatus,
    MemoryConnectorLineageStore,
    connector_reference,
)

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)
SOURCE = "https://docs.example.test/export"


@dataclass(frozen=True)
class ConnectorSetup:
    publisher: IngestionConnectorSigner
    assessor: IngestionConnectorSigner
    controller: IngestionConnectorSigner
    guard: IngestionConnectorGuard
    configuration: ConnectorConfiguration
    manifest: IngestionConnectorManifest
    evidence: ConnectorAdmissionEvidence
    admission: AdmittedIngestionConnector


def _configuration() -> ConnectorConfiguration:
    return ConnectorConfiguration(
        artifact=ConnectorArtifactIdentity(
            artifact_id="docs-loader",
            publisher="example-security",
            source_uri="https://packages.example.test/docs-loader.whl",
            revision="2.4.1",
            artifact_digest=ArtifactDigest.from_bytes(b"connector wheel"),
            dependency_lock_digest="a" * 64,
        ),
        parser=ConnectorParserIdentity(
            parser_id="markdown-parser",
            version="3.2.0",
            implementation_digest="b" * 64,
            configuration_digest="c" * 64,
        ),
        allowed_source_uris=frozenset({SOURCE}),
        credential_references=frozenset({"vault:docs-reader"}),
        schedule=ConnectorSchedule(schedule_id="docs-hourly", interval_seconds=3_600),
        network_destinations=(
            ConnectorNetworkDestination(scheme="https", host="docs.example.test"),
        ),
        expected_content_types=frozenset({"text/markdown"}),
        granted_scopes=frozenset({"documents:read"}),
        sandbox_controls=frozenset(ConnectorSandboxControl),
    )


def _setup(*, max_documents: int = 4, max_bytes: int = 1_024) -> ConnectorSetup:
    publisher = IngestionConnectorSigner.generate(authority_id="connector-publisher")
    assessor = IngestionConnectorSigner.generate(authority_id="security-assessor")
    controller = IngestionConnectorSigner.generate(authority_id="ingestion-control-plane")
    configuration = _configuration()
    manifest = publisher.sign_manifest(
        manifest_id="manifest-2026-10-25",
        connector_id="production-docs",
        kind=IngestionConnectorKind.DOCUMENT_LOADER,
        configuration=configuration,
        max_documents_per_sync=max_documents,
        max_document_bytes=max_bytes,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=4),
    )
    evidence = assessor.sign_evidence(
        evidence_id="assessment-2026-10-25",
        connector_id=manifest.connector_id,
        manifest_digest=manifest.manifest_digest,
        configuration=configuration,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    guard = IngestionConnectorGuard(
        manifest_keys=(publisher.trusted_key,),
        evidence_keys=(assessor.trusted_key,),
        control_signer=controller,
    )
    result = guard.admit(manifest, evidence, now=NOW)
    assert result.admission is not None
    return ConnectorSetup(
        publisher,
        assessor,
        controller,
        guard,
        configuration,
        manifest,
        evidence,
        result.admission,
    )


def _authorization(
    setup: ConnectorSetup, *, request: ConnectorSyncRequest | None = None
) -> AuthorizedConnectorSync:
    manifest = setup.manifest
    evidence = setup.evidence
    state = ConnectorEffectiveState(
        observation_id="observation-1",
        connector_id="production-docs",
        manifest_digest=manifest.manifest_digest,
        evidence_digest=evidence.evidence_digest,
        configuration=setup.configuration,
        observed_at=NOW,
    )
    sync_request = request or ConnectorSyncRequest(
        sync_id="sync-1",
        connector_id="production-docs",
        manifest_digest=manifest.manifest_digest,
        source_uris=frozenset({SOURCE}),
        scheduled_for=NOW,
        effective_state=state,
    )
    decision = setup.guard.authorize_sync(manifest, setup.admission, sync_request, now=NOW)
    assert decision.authorization is not None
    return decision.authorization


def _document(**overrides: object) -> ConnectorDocument:
    values: dict[str, object] = {
        "document_id": "document-1",
        "content": "# Verified docs",
        "source_uri": SOURCE,
        "content_type": "text/markdown",
        "parser_candidates": (_configuration().parser,),
    }
    values.update(overrides)
    return ConnectorDocument.from_content(**values)  # type: ignore[arg-type]


def _codes(decision: IngestionConnectorDecision) -> set[IngestionConnectorCode]:
    return {finding.code for finding in decision.findings}


def test_complete_connector_lifecycle_and_content_free_serialization() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    verified = setup.guard.verify_document(setup.manifest, authorization, _document(), now=NOW)

    assert verified.action == GuardAction.ALLOW
    assert verified.document is not None
    assert verified.document.provenance is not None
    assert "Verified docs" not in verified.model_dump_json()
    assert setup.guard.verify_downstream(setup.manifest, verified.document, now=NOW).is_allowed

    completion = setup.guard.complete_sync(
        setup.manifest,
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
            completed_at=NOW,
        ),
        now=NOW,
    )
    assert completion.is_allowed


def test_unsigned_or_tampered_manifest_and_missing_evidence_fail_closed() -> None:
    setup = _setup()
    unsigned = setup.manifest.model_copy(update={"signature": None})
    missing = setup.guard.admit(unsigned, None, now=NOW)
    tampered = setup.manifest.model_copy(update={"max_document_bytes": 999})
    altered = setup.guard.admit(tampered, setup.evidence, now=NOW)

    assert missing.is_quarantined
    assert _codes(missing) == {
        IngestionConnectorCode.MANIFEST_UNSIGNED,
        IngestionConnectorCode.EVIDENCE_REQUIRED,
    }
    assert IngestionConnectorCode.MANIFEST_SIGNATURE_INVALID in _codes(altered)


def test_admission_requires_complete_controls_and_source_ownership() -> None:
    setup = _setup()
    incomplete = setup.assessor.sign_evidence(
        evidence_id="incomplete",
        connector_id="production-docs",
        manifest_digest=setup.manifest.manifest_digest,
        configuration=setup.configuration,
        controls=frozenset({ConnectorAdmissionControl.ARTIFACT_INTEGRITY}),
        owned_source_uris=frozenset({"https://other.example.test/export"}),
        issued_at=NOW,
    )

    decision = setup.guard.admit(setup.manifest, incomplete, now=NOW)

    assert decision.is_quarantined
    assert IngestionConnectorCode.ADMISSION_CONTROL_MISSING in _codes(decision)
    assert IngestionConnectorCode.SOURCE_OWNERSHIP_UNVERIFIED in _codes(decision)


def test_revoked_assessor_key_is_rejected() -> None:
    setup = _setup()
    key = setup.assessor.trusted_key
    revoked = ConnectorTrustedKey(
        authority_id=key.authority_id,
        public_key=key.public_key,
        revoked=True,
    )
    guard = IngestionConnectorGuard(
        manifest_keys=(setup.publisher.trusted_key,),
        evidence_keys=(revoked,),
        control_signer=setup.controller,
    )

    decision = guard.admit(setup.manifest, setup.evidence, now=NOW)

    assert IngestionConnectorCode.EVIDENCE_KEY_INACTIVE in _codes(decision)


def test_effective_configuration_drift_is_quarantined_before_sync() -> None:
    setup = _setup()
    drifted = setup.configuration.model_copy(
        update={"credential_references": frozenset({"vault:unexpected-admin"})}
    )
    state = ConnectorEffectiveState(
        observation_id="drifted",
        connector_id="production-docs",
        manifest_digest=setup.manifest.manifest_digest,
        evidence_digest=setup.evidence.evidence_digest,
        configuration=drifted,
        observed_at=NOW,
    )
    request = ConnectorSyncRequest(
        sync_id="sync-drifted",
        connector_id="production-docs",
        manifest_digest=setup.manifest.manifest_digest,
        source_uris=frozenset({SOURCE}),
        scheduled_for=NOW,
        effective_state=state,
    )

    decision = setup.guard.authorize_sync(setup.manifest, setup.admission, request, now=NOW)

    assert IngestionConnectorCode.EFFECTIVE_STATE_DRIFT in _codes(decision)
    assert decision.authorization is None


@pytest.mark.parametrize(
    ("override", "code"),
    [
        (
            {"source_uri": "https://evil.example.test/export"},
            IngestionConnectorCode.SOURCE_NOT_ALLOWED,
        ),
        ({"content_type": "application/pdf"}, IngestionConnectorCode.CONTENT_TYPE_UNEXPECTED),
        ({"parser_candidates": ()}, IngestionConnectorCode.PARSER_AMBIGUOUS),
        ({"content": "x" * 1_025}, IngestionConnectorCode.DOCUMENT_TOO_LARGE),
    ],
)
def test_document_boundary_rejects_source_type_parser_and_size_bypasses(
    override: dict[str, object], code: IngestionConnectorCode
) -> None:
    setup = _setup()
    authorization = _authorization(setup)

    decision = setup.guard.verify_document(
        setup.manifest, authorization, _document(**override), now=NOW
    )

    assert decision.is_quarantined
    assert code in _codes(decision)


def test_document_digest_tampering_and_parser_substitution_fail_closed() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    wrong_parser = setup.configuration.parser.model_copy(update={"version": "9.9.9"})
    document = _document(parser_candidates=(wrong_parser,)).model_copy(
        update={"content": "modified after hashing"}
    )

    decision = setup.guard.verify_document(setup.manifest, authorization, document, now=NOW)

    assert IngestionConnectorCode.PARSER_MISMATCH in _codes(decision)
    assert IngestionConnectorCode.CONTENT_INTEGRITY_MISMATCH in _codes(decision)


def test_partial_sync_transitively_quarantines_document_and_derived_artifacts() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    verified = setup.guard.verify_document(
        setup.manifest, authorization, _document(), now=NOW
    ).document
    assert verified is not None and verified.provenance is not None
    chunk = setup.guard.register_downstream_artifact(
        "chunk-1", (verified.provenance.document_reference,)
    )
    embedding = setup.guard.register_downstream_artifact("embedding-1", (chunk,))

    decision = setup.guard.complete_sync(
        setup.manifest,
        authorization,
        ConnectorSyncReport(
            authorization_id=authorization.authorization_id,
            sync_id=authorization.sync_id,
            manifest_digest=authorization.manifest_digest,
            state_digest=authorization.state_digest,
            status=ConnectorSyncStatus.PARTIAL,
            expected_documents=2,
            processed_documents=1,
            failure_count=1,
            completed_at=NOW,
        ),
        now=NOW,
    )

    assert IngestionConnectorCode.PARTIAL_SYNC in _codes(decision)
    assert set(decision.affected_artifact_references) == {
        verified.provenance.document_reference,
        chunk,
        embedding,
    }
    downstream = setup.guard.verify_downstream(setup.manifest, verified, now=NOW)
    assert IngestionConnectorCode.ARTIFACT_QUARANTINED in _codes(downstream)


def test_missing_and_tampered_provenance_are_rejected_downstream() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    plain = _document()
    missing = setup.guard.verify_downstream(setup.manifest, plain, now=NOW)
    verified = setup.guard.verify_document(setup.manifest, authorization, plain, now=NOW).document
    assert verified is not None and verified.provenance is not None
    bad_provenance = verified.provenance.model_copy(update={"source_uri": SOURCE + "/changed"})
    tampered = setup.guard.verify_downstream(
        setup.manifest,
        verified.model_copy(update={"provenance": bad_provenance}),
        now=NOW,
    )

    assert IngestionConnectorCode.PROVENANCE_MISSING in _codes(missing)
    assert IngestionConnectorCode.PROVENANCE_INVALID in _codes(tampered)


def test_connector_compromise_traces_registered_descendants() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    verified = setup.guard.verify_document(
        setup.manifest, authorization, _document(), now=NOW
    ).document
    assert verified is not None and verified.provenance is not None
    derived = setup.guard.register_downstream_artifact(
        "vector-entry", (verified.provenance.document_reference,)
    )

    incident = setup.guard.quarantine_connector("production-docs")

    assert incident.action == GuardAction.QUARANTINE
    assert derived in incident.affected_artifact_references


def test_signed_compromised_manifest_quarantines_all_existing_lineage() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    verified = setup.guard.verify_document(
        setup.manifest, authorization, _document(), now=NOW
    ).document
    assert verified is not None and verified.provenance is not None
    derived = setup.guard.register_downstream_artifact(
        "derived-after-compromise", (verified.provenance.document_reference,)
    )
    compromised = setup.publisher.sign_manifest(
        manifest_id="compromised-manifest",
        connector_id="production-docs",
        kind=IngestionConnectorKind.DOCUMENT_LOADER,
        configuration=setup.configuration,
        status=IngestionConnectorStatus.COMPROMISED,
        issued_at=NOW,
    )

    decision = setup.guard.admit(compromised, None, now=NOW)

    assert IngestionConnectorCode.CONNECTOR_COMPROMISED in _codes(decision)
    assert set(decision.affected_artifact_references) == {
        verified.provenance.document_reference,
        derived,
    }


def test_lineage_capacity_exhaustion_fails_closed() -> None:
    setup = _setup()
    guard = IngestionConnectorGuard(
        manifest_keys=(setup.publisher.trusted_key,),
        evidence_keys=(setup.assessor.trusted_key,),
        control_signer=setup.controller,
        lineage_store=MemoryConnectorLineageStore(max_artifacts=1),
    )
    admission = guard.admit(setup.manifest, setup.evidence, now=NOW).admission
    assert admission is not None
    state = ConnectorEffectiveState(
        observation_id="capacity-state",
        connector_id="production-docs",
        manifest_digest=setup.manifest.manifest_digest,
        evidence_digest=setup.evidence.evidence_digest,
        configuration=setup.configuration,
        observed_at=NOW,
    )
    request = ConnectorSyncRequest(
        sync_id="capacity-sync",
        connector_id="production-docs",
        manifest_digest=setup.manifest.manifest_digest,
        source_uris=frozenset({SOURCE}),
        scheduled_for=NOW,
        effective_state=state,
    )
    authorization = guard.authorize_sync(setup.manifest, admission, request, now=NOW).authorization
    assert authorization is not None
    assert guard.verify_document(setup.manifest, authorization, _document(), now=NOW).is_allowed

    decision = guard.verify_document(
        setup.manifest,
        authorization,
        _document(document_id="document-2"),
        now=NOW,
    )

    assert IngestionConnectorCode.LINEAGE_UNAVAILABLE in _codes(decision)


def test_document_identity_cannot_be_rebound_to_different_content() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    assert setup.guard.verify_document(
        setup.manifest, authorization, _document(), now=NOW
    ).is_allowed

    rebound = setup.guard.verify_document(
        setup.manifest,
        authorization,
        _document(content="different bytes under the same document ID"),
        now=NOW,
    )

    assert IngestionConnectorCode.LINEAGE_UNAVAILABLE in _codes(rebound)


def test_completion_consumes_authorization_and_replay_is_rejected() -> None:
    setup = _setup()
    authorization = _authorization(setup)
    report = ConnectorSyncReport(
        authorization_id=authorization.authorization_id,
        sync_id=authorization.sync_id,
        manifest_digest=authorization.manifest_digest,
        state_digest=authorization.state_digest,
        status=ConnectorSyncStatus.COMPLETE,
        expected_documents=0,
        processed_documents=0,
        failure_count=0,
        completed_at=NOW,
    )
    assert setup.guard.complete_sync(setup.manifest, authorization, report, now=NOW).is_allowed

    replay = setup.guard.complete_sync(setup.manifest, authorization, report, now=NOW)

    assert IngestionConnectorCode.AUTHORIZATION_REPLAYED in _codes(replay)


@pytest.mark.parametrize(
    "uri",
    [
        "https://user:password@docs.example.test/export",
        "https://docs.example.test/export#fragment",
        "docs.example.test/no-scheme",
    ],
)
def test_source_uris_cannot_embed_credentials_fragments_or_omit_scheme(uri: str) -> None:
    with pytest.raises(ValidationError, match="source URI"):
        ConnectorConfiguration.model_validate(
            {
                **_configuration().model_dump(),
                "allowed_source_uris": [uri],
            }
        )


def test_reference_helpers_do_not_expose_raw_connector_identity() -> None:
    reference = connector_reference("secret-internal-connector")

    assert reference.startswith("sha256:")
    assert "secret" not in reference
    assert connector_reference("same", domain="connector") != connector_reference(
        "same", domain="document"
    )
