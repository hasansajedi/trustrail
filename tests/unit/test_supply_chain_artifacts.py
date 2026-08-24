"""Unit tests for typed AI artifact manifests and verification."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from trustrail import (
    ArtifactDigest,
    ArtifactKind,
    ArtifactManifest,
    ArtifactObservation,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactVerificationCode,
    ArtifactVerificationError,
    ArtifactVerificationPolicy,
    ArtifactVerifier,
    DigestAlgorithm,
    GuardAction,
    TrustLevel,
)

PAYLOAD = b"reviewed model artifact"


def _record(**updates: object) -> ArtifactRecord:
    record = ArtifactRecord.from_bytes(
        artifact_id="model.summarizer",
        kind=ArtifactKind.MODEL,
        supplier="approved-ai",
        source_uri="https://models.example/summarizer",
        revision="8f1c2d3e4a5b6c7d8e9f",
        payload=PAYLOAD,
        trust_level=TrustLevel.TRUSTED,
        approved=True,
        license_id="Apache-2.0",
    )
    return record.model_copy(update=updates)


def _manifest(record: ArtifactRecord | None = None) -> ArtifactManifest:
    return ArtifactManifest(
        manifest_id="production-ai-bom",
        artifacts=(record or _record(),),
    )


def _observation(record: ArtifactRecord | None = None, **updates: object) -> ArtifactObservation:
    expected = record or _record()
    observation = ArtifactObservation(
        artifact_id=expected.artifact_id,
        kind=expected.kind,
        supplier=expected.supplier,
        source_uri=expected.source_uri,
        revision=expected.revision,
        digest=expected.digest,
    )
    return observation.model_copy(update=updates)


class TestArtifactModels:
    @pytest.mark.parametrize(
        "algorithm,length",
        [
            (DigestAlgorithm.SHA256, 64),
            (DigestAlgorithm.SHA384, 96),
            (DigestAlgorithm.SHA512, 128),
        ],
    )
    def test_calculates_supported_digests(self, algorithm: DigestAlgorithm, length: int):
        digest = ArtifactDigest.from_bytes(PAYLOAD, algorithm)

        assert digest.algorithm == algorithm
        assert len(digest.value) == length

    def test_rejects_malformed_digest(self):
        with pytest.raises(ValidationError, match="digest must be 64 hexadecimal"):
            ArtifactDigest(value="not-a-valid-digest")

    def test_normalizes_uppercase_digest(self):
        digest = ArtifactDigest(value="A" * 64)

        assert digest.value == "a" * 64

    def test_rejects_duplicate_artifact_ids(self):
        with pytest.raises(ValidationError, match="duplicate artifact IDs"):
            ArtifactManifest(
                manifest_id="duplicate",
                artifacts=(_record(), _record()),
            )

    def test_manifest_fingerprint_is_deterministic_and_tamper_evident(self):
        manifest = _manifest()
        changed = _manifest(_record(revision="different-revision"))

        assert manifest.matches_fingerprint(manifest.fingerprint_sha256)
        assert manifest.fingerprint_sha256 != changed.fingerprint_sha256


class TestArtifactVerifier:
    def test_verifies_approved_artifact_bytes(self):
        result = ArtifactVerifier(_manifest()).verify_bytes("model.summarizer", PAYLOAD)

        assert result.action == GuardAction.ALLOW
        assert result.is_verified
        assert not result.findings

    def test_blocks_tampered_bytes(self):
        result = ArtifactVerifier(_manifest()).verify_bytes(
            "model.summarizer", b"tampered model artifact"
        )

        assert result.is_blocked
        assert {finding.code for finding in result.findings} == {
            ArtifactVerificationCode.DIGEST_MISMATCH
        }

    def test_blocks_unknown_artifact(self):
        result = ArtifactVerifier(_manifest()).verify_bytes("model.lookalike", PAYLOAD)

        assert result.is_blocked
        assert result.findings[0].code == ArtifactVerificationCode.UNKNOWN_ARTIFACT

    @pytest.mark.parametrize(
        "field,value,code",
        [
            ("kind", ArtifactKind.ADAPTER, ArtifactVerificationCode.KIND_MISMATCH),
            ("supplier", "lookalike-ai", ArtifactVerificationCode.SUPPLIER_MISMATCH),
            (
                "source_uri",
                "https://attacker.example/summarizer",
                ArtifactVerificationCode.SOURCE_MISMATCH,
            ),
            ("revision", "different-revision", ArtifactVerificationCode.REVISION_MISMATCH),
            ("digest", None, ArtifactVerificationCode.DIGEST_MISSING),
        ],
    )
    def test_blocks_changed_observed_metadata(
        self,
        field: str,
        value: object,
        code: ArtifactVerificationCode,
    ):
        result = ArtifactVerifier(_manifest()).verify(_observation(**{field: value}))

        assert result.is_blocked
        assert code in {finding.code for finding in result.findings}

    @pytest.mark.parametrize(
        "record,code",
        [
            (_record(approved=False), ArtifactVerificationCode.UNAPPROVED_ARTIFACT),
            (
                _record(trust_level=TrustLevel.UNTRUSTED),
                ArtifactVerificationCode.INSUFFICIENT_TRUST,
            ),
            (_record(status=ArtifactStatus.REVOKED), ArtifactVerificationCode.REVOKED_ARTIFACT),
            (_record(revision="refs/heads/main"), ArtifactVerificationCode.UNPINNED_REVISION),
            (_record(digest=None), ArtifactVerificationCode.DIGEST_MISSING),
        ],
    )
    def test_blocks_untrusted_manifest_records(
        self,
        record: ArtifactRecord,
        code: ArtifactVerificationCode,
    ):
        result = ArtifactVerifier(_manifest(record)).verify(_observation(record))

        assert result.is_blocked
        assert code in {finding.code for finding in result.findings}

    def test_can_warn_for_reviewed_deprecated_artifact(self):
        record = _record(status=ArtifactStatus.DEPRECATED)
        policy = ArtifactVerificationPolicy(reject_deprecated=False)

        result = ArtifactVerifier(_manifest(record), policy=policy).verify(_observation(record))

        assert result.action == GuardAction.WARN
        assert result.findings[0].code == ArtifactVerificationCode.DEPRECATED_ARTIFACT

    def test_enforces_supplier_and_license_policy(self):
        policy = ArtifactVerificationPolicy(
            allowed_suppliers=frozenset({"different-supplier"}),
            require_license=True,
        )
        record = _record(license_id=None)

        result = ArtifactVerifier(_manifest(record), policy=policy).verify(_observation(record))

        assert result.is_blocked
        assert {finding.code for finding in result.findings} >= {
            ArtifactVerificationCode.LICENSE_MISSING,
            ArtifactVerificationCode.SUPPLIER_NOT_ALLOWED,
        }

    def test_blocks_tampered_manifest_with_coordinated_artifact_change(self):
        trusted_manifest = _manifest()
        tampered_payload = b"coordinated malicious replacement"
        tampered_record = ArtifactRecord.from_bytes(
            artifact_id="model.summarizer",
            kind=ArtifactKind.MODEL,
            supplier="approved-ai",
            source_uri="https://models.example/summarizer",
            revision="8f1c2d3e4a5b6c7d8e9f",
            payload=tampered_payload,
            trust_level=TrustLevel.TRUSTED,
            approved=True,
            license_id="Apache-2.0",
        )
        tampered_manifest = _manifest(tampered_record)
        verifier = ArtifactVerifier(
            tampered_manifest,
            expected_manifest_sha256=trusted_manifest.fingerprint_sha256,
        )

        result = verifier.verify_bytes("model.summarizer", tampered_payload)

        assert result.is_blocked
        assert ArtifactVerificationCode.MANIFEST_INTEGRITY_MISMATCH in {
            finding.code for finding in result.findings
        }

    def test_require_raises_content_free_exception(self):
        secret_source = "https://private.example/path?credential=do-not-log"
        observation = _observation(source_uri=secret_source)

        with pytest.raises(ArtifactVerificationError) as exc_info:
            ArtifactVerifier(_manifest()).require(observation)

        assert secret_source not in str(exc_info.value)
        assert secret_source not in exc_info.value.result.model_dump_json()
