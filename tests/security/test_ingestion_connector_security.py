"""Bypass corpus for ingestion connector admission and provenance controls."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    ArtifactDigest,
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
    IngestionConnectorGuard,
    IngestionConnectorKind,
    IngestionConnectorManifest,
    IngestionConnectorSigner,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "ingestion_connectors.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 10, 25, 16, tzinfo=UTC)
SOURCE = "https://security.example.test/export"


def _configuration() -> ConnectorConfiguration:
    return ConnectorConfiguration(
        artifact=ConnectorArtifactIdentity(
            artifact_id="security-loader",
            publisher="security-team",
            source_uri="https://packages.example.test/security-loader.whl",
            revision="1.0.0",
            artifact_digest=ArtifactDigest.from_bytes(b"reviewed loader"),
            dependency_lock_digest="a" * 64,
        ),
        parser=ConnectorParserIdentity(
            parser_id="secure-parser",
            version="1.0.0",
            implementation_digest="b" * 64,
            configuration_digest="c" * 64,
        ),
        allowed_source_uris=frozenset({SOURCE}),
        credential_references=frozenset({"vault:security-reader"}),
        schedule=ConnectorSchedule(schedule_id="security-hourly", interval_seconds=3_600),
        network_destinations=(
            ConnectorNetworkDestination(scheme="https", host="security.example.test"),
        ),
        expected_content_types=frozenset({"text/plain"}),
        granted_scopes=frozenset({"documents:read"}),
        sandbox_controls=frozenset(ConnectorSandboxControl),
    )


def _components() -> tuple[
    IngestionConnectorSigner,
    IngestionConnectorSigner,
    IngestionConnectorGuard,
    ConnectorConfiguration,
    IngestionConnectorManifest,
    ConnectorAdmissionEvidence,
]:
    publisher = IngestionConnectorSigner.generate(authority_id="security-publisher")
    assessor = IngestionConnectorSigner.generate(authority_id="security-assessor")
    controller = IngestionConnectorSigner.generate(authority_id="security-controller")
    configuration = _configuration()
    manifest = publisher.sign_manifest(
        manifest_id="security-manifest",
        connector_id="security-connector",
        kind=IngestionConnectorKind.DOCUMENT_LOADER,
        configuration=configuration,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=3),
    )
    evidence = assessor.sign_evidence(
        evidence_id="security-evidence",
        connector_id=manifest.connector_id,
        manifest_digest=manifest.manifest_digest,
        configuration=configuration,
        issued_at=NOW,
    )
    guard = IngestionConnectorGuard(
        manifest_keys=(publisher.trusted_key,),
        evidence_keys=(assessor.trusted_key,),
        control_signer=controller,
    )
    return publisher, assessor, guard, configuration, manifest, evidence


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_ingestion_connector_bypass_corpus_fails_closed(case: dict[str, str]) -> None:
    publisher, assessor, guard, configuration, manifest, evidence = _components()
    mutation = case["mutation"]

    if mutation == "manifest_artifact":
        changed_artifact = configuration.artifact.model_copy(
            update={"dependency_lock_digest": "f" * 64}
        )
        changed = configuration.model_copy(update={"artifact": changed_artifact})
        decision = guard.admit(
            manifest.model_copy(update={"configuration": changed}), evidence, now=NOW
        )
    elif mutation in {"source_ownership", "sandbox_evidence"}:
        controls = frozenset(ConnectorAdmissionControl)
        sources = configuration.allowed_source_uris
        if mutation == "source_ownership":
            sources = frozenset({"https://unrelated.example.test/export"})
        else:
            controls -= {ConnectorAdmissionControl.SANDBOX}
        bad_evidence = assessor.sign_evidence(
            evidence_id="mutated-evidence",
            connector_id=manifest.connector_id,
            manifest_digest=manifest.manifest_digest,
            configuration=configuration,
            controls=controls,
            owned_source_uris=sources,
            issued_at=NOW,
        )
        decision = guard.admit(manifest, bad_evidence, now=NOW)
    else:
        admission = guard.admit(manifest, evidence, now=NOW).admission
        assert admission is not None
        effective = configuration
        if mutation == "dependency_lock":
            artifact = configuration.artifact.model_copy(
                update={"dependency_lock_digest": "d" * 64}
            )
            effective = configuration.model_copy(update={"artifact": artifact})
        elif mutation == "credential_scope":
            effective = configuration.model_copy(
                update={"granted_scopes": frozenset({"documents:admin"})}
            )
        state = ConnectorEffectiveState(
            observation_id="security-observation",
            connector_id=manifest.connector_id,
            manifest_digest=manifest.manifest_digest,
            evidence_digest=evidence.evidence_digest,
            configuration=effective,
            observed_at=NOW,
        )
        source_uris = frozenset({SOURCE})
        if mutation == "sync_source":
            source_uris = frozenset({"https://lookalike.example.test/export"})
        request = ConnectorSyncRequest(
            sync_id="security-sync",
            connector_id=manifest.connector_id,
            manifest_digest=manifest.manifest_digest,
            source_uris=source_uris,
            scheduled_for=NOW,
            effective_state=state,
        )
        sync_decision = guard.authorize_sync(manifest, admission, request, now=NOW)
        if mutation in {"dependency_lock", "credential_scope", "sync_source"}:
            decision = sync_decision
        else:
            authorization = sync_decision.authorization
            assert authorization is not None
            document = ConnectorDocument.from_content(
                document_id="security-document",
                content="reviewed content",
                source_uri=SOURCE,
                content_type=(
                    "application/octet-stream" if mutation == "content_type" else "text/plain"
                ),
                parser_candidates=(
                    () if mutation == "parser_ambiguity" else (configuration.parser,)
                ),
            )
            if mutation == "document_digest":
                document = document.model_copy(update={"content": "changed content"})
            document_decision = guard.verify_document(manifest, authorization, document, now=NOW)
            if mutation in {"parser_ambiguity", "content_type", "document_digest"}:
                decision = document_decision
            elif mutation == "partial_sync":
                assert document_decision.document is not None
                decision = guard.complete_sync(
                    manifest,
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
            elif mutation == "missing_provenance":
                decision = guard.verify_downstream(manifest, document, now=NOW)
            else:
                verified = document_decision.document
                assert verified is not None and verified.provenance is not None
                tampered = verified.model_copy(
                    update={
                        "provenance": verified.provenance.model_copy(
                            update={"signature": "0" * 128}
                        )
                    }
                )
                decision = guard.verify_downstream(manifest, tampered, now=NOW)

    codes = {finding.code.value for finding in decision.findings}
    serialized = decision.model_dump_json()
    assert decision.is_quarantined
    assert case["expected_code"] in codes
    assert "reviewed content" not in serialized
    assert "vault:security-reader" not in serialized
    assert "documents:admin" not in serialized
    assert publisher.trusted_key.public_key.hex() not in serialized
