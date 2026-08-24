"""Runtime verification for AI supply-chain artifacts."""

from __future__ import annotations

import re

from trustrail.exceptions import ArtifactVerificationError
from trustrail.models.enums import GuardAction, Severity, TrustLevel
from trustrail.models.supply_chain import (
    ArtifactDigest,
    ArtifactManifest,
    ArtifactObservation,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactVerificationCode,
    ArtifactVerificationFinding,
    ArtifactVerificationPolicy,
    ArtifactVerificationResult,
    DigestAlgorithm,
)

_TRUST_ORDER = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 1,
    TrustLevel.TRUSTED: 2,
}
_MUTABLE_REVISIONS = frozenset(
    {"dev", "development", "head", "latest", "main", "master", "stable", "current"}
)
_MUTABLE_REVISION_RE = re.compile(
    r"(?:^|[/@:._-])(?:dev|development|head|latest|main|master|stable|current)"
    r"(?:$|[/@:._-])",
    re.IGNORECASE,
)


def _is_mutable_revision(revision: str) -> bool:
    normalized = revision.strip().casefold()
    return (
        normalized in _MUTABLE_REVISIONS
        or bool(_MUTABLE_REVISION_RE.search(normalized))
        or any(character in normalized for character in ("*", "^", "~", ">", "<"))
    )


class ArtifactVerifier:
    """Verify observed AI components against an approved, immutable inventory."""

    def __init__(
        self,
        manifest: ArtifactManifest,
        *,
        policy: ArtifactVerificationPolicy | None = None,
        expected_manifest_sha256: str | None = None,
    ) -> None:
        self._manifest = manifest
        self._policy = policy or ArtifactVerificationPolicy()
        self._records = {record.artifact_id: record for record in manifest.artifacts}
        self._manifest_integrity_valid = (
            expected_manifest_sha256 is None
            or manifest.matches_fingerprint(expected_manifest_sha256)
        )

    @property
    def manifest(self) -> ArtifactManifest:
        return self._manifest

    def verify(self, observed: ArtifactObservation) -> ArtifactVerificationResult:
        """Compare observed provenance and integrity metadata with the manifest."""
        expected = self._records.get(observed.artifact_id)
        if expected is None:
            return self._result(
                observed.artifact_id,
                [
                    self._finding(
                        ArtifactVerificationCode.UNKNOWN_ARTIFACT,
                        Severity.CRITICAL,
                        "Artifact is not present in the approved manifest",
                    )
                ],
            )

        findings = self._record_findings(expected)
        if not self._manifest_integrity_valid:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.MANIFEST_INTEGRITY_MISMATCH,
                    Severity.CRITICAL,
                    "Artifact manifest fingerprint does not match the trusted value",
                )
            )
        if observed.kind != expected.kind:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.KIND_MISMATCH,
                    Severity.CRITICAL,
                    "Observed artifact kind differs from the approved manifest",
                )
            )
        if observed.supplier != expected.supplier:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.SUPPLIER_MISMATCH,
                    Severity.CRITICAL,
                    "Observed artifact supplier differs from the approved manifest",
                )
            )
        if observed.source_uri != expected.source_uri:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.SOURCE_MISMATCH,
                    Severity.CRITICAL,
                    "Observed artifact source differs from the approved manifest",
                )
            )
        if observed.revision != expected.revision:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.REVISION_MISMATCH,
                    Severity.CRITICAL,
                    "Observed artifact revision differs from the approved manifest",
                )
            )
        findings.extend(self._digest_findings(expected, observed.digest))
        return self._result(observed.artifact_id, findings)

    def verify_bytes(self, artifact_id: str, payload: bytes) -> ArtifactVerificationResult:
        """Hash artifact bytes and verify them against the approved manifest record."""
        expected = self._records.get(artifact_id)
        if expected is None:
            return self._result(
                artifact_id,
                [
                    self._finding(
                        ArtifactVerificationCode.UNKNOWN_ARTIFACT,
                        Severity.CRITICAL,
                        "Artifact is not present in the approved manifest",
                    )
                ],
            )
        algorithm = expected.digest.algorithm if expected.digest else DigestAlgorithm.SHA256
        observed = ArtifactObservation(
            artifact_id=expected.artifact_id,
            kind=expected.kind,
            supplier=expected.supplier,
            source_uri=expected.source_uri,
            revision=expected.revision,
            digest=ArtifactDigest.from_bytes(payload, algorithm),
        )
        return self.verify(observed)

    def require(self, observed: ArtifactObservation) -> ArtifactVerificationResult:
        """Return a verified result or raise before the artifact can be used."""
        result = self.verify(observed)
        if result.is_blocked:
            raise ArtifactVerificationError(result=result)
        return result

    def require_bytes(self, artifact_id: str, payload: bytes) -> ArtifactVerificationResult:
        """Return a verified byte result or raise before loading the artifact."""
        result = self.verify_bytes(artifact_id, payload)
        if result.is_blocked:
            raise ArtifactVerificationError(result=result)
        return result

    def _record_findings(self, expected: ArtifactRecord) -> list[ArtifactVerificationFinding]:
        findings: list[ArtifactVerificationFinding] = []
        if expected.status == ArtifactStatus.REVOKED:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.REVOKED_ARTIFACT,
                    Severity.CRITICAL,
                    "Artifact has been revoked by supply-chain policy",
                )
            )
        elif expected.status == ArtifactStatus.DEPRECATED:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.DEPRECATED_ARTIFACT,
                    Severity.HIGH if self._policy.reject_deprecated else Severity.MEDIUM,
                    "Artifact is marked as deprecated",
                )
            )
        if self._policy.require_approval and not expected.approved:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.UNAPPROVED_ARTIFACT,
                    Severity.HIGH,
                    "Artifact has not passed the required review and approval",
                )
            )
        if _TRUST_ORDER[expected.trust_level] < _TRUST_ORDER[self._policy.minimum_trust]:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.INSUFFICIENT_TRUST,
                    Severity.HIGH,
                    "Artifact trust level is below the configured minimum",
                )
            )
        if self._policy.allowed_suppliers is not None and (
            expected.supplier not in self._policy.allowed_suppliers
        ):
            findings.append(
                self._finding(
                    ArtifactVerificationCode.SUPPLIER_NOT_ALLOWED,
                    Severity.HIGH,
                    "Artifact supplier is not in the configured allowlist",
                )
            )
        if self._policy.require_pinned_revision and _is_mutable_revision(expected.revision):
            findings.append(
                self._finding(
                    ArtifactVerificationCode.UNPINNED_REVISION,
                    Severity.HIGH,
                    "Artifact revision is a mutable reference rather than an immutable pin",
                )
            )
        if self._policy.require_license and not expected.license_id:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.LICENSE_MISSING,
                    Severity.HIGH,
                    "Artifact lacks required license inventory metadata",
                )
            )
        if expected.kind in self._policy.digest_required_for and expected.digest is None:
            findings.append(
                self._finding(
                    ArtifactVerificationCode.DIGEST_MISSING,
                    Severity.CRITICAL,
                    "Approved artifact record lacks a required cryptographic digest",
                )
            )
        return findings

    def _digest_findings(
        self,
        expected: ArtifactRecord,
        observed: ArtifactDigest | None,
    ) -> list[ArtifactVerificationFinding]:
        if expected.digest is None:
            return []
        if observed is None:
            return [
                self._finding(
                    ArtifactVerificationCode.DIGEST_MISSING,
                    Severity.CRITICAL,
                    "Observed artifact lacks required integrity evidence",
                )
            ]
        if not expected.digest.matches(observed):
            return [
                self._finding(
                    ArtifactVerificationCode.DIGEST_MISMATCH,
                    Severity.CRITICAL,
                    "Observed artifact digest differs from the approved manifest",
                )
            ]
        return []

    def _result(
        self,
        artifact_id: str,
        findings: list[ArtifactVerificationFinding],
    ) -> ArtifactVerificationResult:
        blocking = any(
            finding.severity in (Severity.HIGH, Severity.CRITICAL) for finding in findings
        )
        return ArtifactVerificationResult(
            artifact_id=artifact_id,
            manifest_id=self._manifest.manifest_id,
            action=(
                GuardAction.BLOCK
                if blocking
                else (GuardAction.WARN if findings else GuardAction.ALLOW)
            ),
            findings=tuple(findings),
        )

    @staticmethod
    def _finding(
        code: ArtifactVerificationCode,
        severity: Severity,
        message: str,
    ) -> ArtifactVerificationFinding:
        return ArtifactVerificationFinding(code=code, severity=severity, message=message)
