"""Fail-closed verification for data and model poisoning boundaries."""

from __future__ import annotations

import re
from collections.abc import Iterable
from itertools import pairwise
from typing import Protocol

from trustrail.exceptions import DataPoisoningError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.poisoning import (
    DataIngestionRecord,
    DataPoisoningPolicy,
    DataPoisoningResult,
    DataSourcePolicy,
    PoisoningCode,
    PoisoningFinding,
)
from trustrail.models.supply_chain import ArtifactDigest
from trustrail.normalization.normalizer import TextNormalizer

_MUTABLE_VERSION_RE = re.compile(
    r"(?:^|[/@:._-])(?:dev|development|head|latest|main|master|stable|current)"
    r"(?:$|[/@:._-])",
    re.IGNORECASE,
)
_VERSION_RANGE_RE = re.compile(r"[*^~<>]")
_SAFE_DETECTOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_POISONING_PATTERNS = (
    re.compile(
        r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?"
        r"(?:previous|prior|above|system)\s+(?:instructions?|rules?|context)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:new|updated|replacement)\s+(?:system\s+)?"
        r"(?:prompt|instruction|directive|objective|task)\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:<|\[|###\s*)(?:system|assistant|instruction)(?:>|\]|\s*:)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:backdoor|sleeper)\s+(?:trigger|instruction|behavior)|"
        r"trigger\s+(?:phrase|token)\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"when\s+(?:the\s+)?(?:model|assistant|ai|llm)\s+"
        r"(?:sees?|reads?|receives?)\b.{0,120}\bthen\b",
        re.IGNORECASE,
    ),
)


class PoisoningDetector(Protocol):
    """Privacy-safe hook for an application-specific anomaly detector.

    Detectors receive the full record but return only a severity. A non-None
    value becomes a generic, content-free finding associated with detector_id.
    """

    detector_id: str

    def detect(self, record: DataIngestionRecord) -> Severity | None:
        """Return a severity when the record is anomalous, otherwise None."""
        ...


class DataPoisoningVerifier:
    """Verify provenance, authorization, integrity, lineage, and anomaly signals."""

    def __init__(
        self,
        policy: DataPoisoningPolicy,
        *,
        detectors: Iterable[PoisoningDetector] = (),
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._sources = {source.source_id: source for source in self._policy.sources}
        self._detectors = tuple(detectors)
        self._normalizer = TextNormalizer()

    @property
    def policy(self) -> DataPoisoningPolicy:
        """Return the immutable policy used for verification."""
        return self._policy.model_copy(deep=True)

    def verify(self, record: DataIngestionRecord) -> DataPoisoningResult:
        """Evaluate one asset without copying its content into the result."""
        findings: list[PoisoningFinding] = []
        source_policy = self._sources.get(record.provenance.source_id)
        if source_policy is None:
            findings.append(
                self._finding(
                    PoisoningCode.UNKNOWN_SOURCE,
                    Severity.CRITICAL,
                    "Source is not present in the trusted ingestion policy",
                    "policy",
                )
            )
        else:
            findings.extend(self._source_findings(record, source_policy))

        findings.extend(self._integrity_findings(record))
        findings.extend(self._lineage_findings(record))
        findings.extend(self._anomaly_findings(record))
        findings.extend(self._pattern_findings(record))
        findings.extend(self._custom_detector_findings(record))

        blocking = any(
            finding.severity in (Severity.HIGH, Severity.CRITICAL) for finding in findings
        )
        return DataPoisoningResult(
            item_id=record.item_id,
            source_id=record.provenance.source_id,
            action=(
                GuardAction.QUARANTINE
                if blocking
                else (GuardAction.WARN if findings else GuardAction.ALLOW)
            ),
            findings=tuple(findings),
        )

    def require(self, record: DataIngestionRecord) -> DataIngestionRecord:
        """Return an accepted record or raise before indexing, storing, or loading it."""
        result = self.verify(record)
        if result.is_quarantined:
            raise DataPoisoningError(result=result)
        return record

    def _source_findings(
        self,
        record: DataIngestionRecord,
        source: DataSourcePolicy,
    ) -> list[PoisoningFinding]:
        findings: list[PoisoningFinding] = []
        if record.provenance.source_uri != source.source_uri:
            findings.append(
                self._finding(
                    PoisoningCode.UNKNOWN_SOURCE,
                    Severity.CRITICAL,
                    "Source location differs from trusted ingestion policy",
                    "policy",
                )
            )
        if record.kind not in source.allowed_kinds:
            findings.append(
                self._finding(
                    PoisoningCode.KIND_NOT_ALLOWED,
                    Severity.HIGH,
                    "Asset kind is not allowed for this source",
                    "policy",
                )
            )
        if record.provenance.trust_level != source.trust_level:
            findings.append(
                self._finding(
                    PoisoningCode.TRUST_MISMATCH,
                    Severity.HIGH,
                    "Observed trust label differs from trusted ingestion policy",
                    "policy",
                )
            )
        if source.allowed_versions is not None and (
            record.provenance.version not in source.allowed_versions
        ):
            findings.append(
                self._finding(
                    PoisoningCode.VERSION_NOT_ALLOWED,
                    Severity.HIGH,
                    "Asset version is not approved for this source",
                    "policy",
                )
            )
        if source.require_pinned_version and _is_mutable_version(record.provenance.version):
            findings.append(
                self._finding(
                    PoisoningCode.UNPINNED_VERSION,
                    Severity.HIGH,
                    "Asset version is a mutable reference rather than an immutable pin",
                    "policy",
                )
            )
        findings.extend(self._authorization_findings(record, source))
        return findings

    def _authorization_findings(
        self,
        record: DataIngestionRecord,
        source: DataSourcePolicy,
    ) -> list[PoisoningFinding]:
        if not self._policy.require_authorization:
            return []
        authorization = record.authorization
        if authorization is None:
            return [
                self._finding(
                    PoisoningCode.AUTHORIZATION_MISSING,
                    Severity.HIGH,
                    "Asset lacks required writer authorization evidence",
                    "authorization",
                )
            ]

        findings: list[PoisoningFinding] = []
        if authorization.writer_id not in source.authorized_writers:
            findings.append(
                self._finding(
                    PoisoningCode.WRITER_NOT_AUTHORIZED,
                    Severity.CRITICAL,
                    "Writer is not authorized for this ingestion source",
                    "authorization",
                )
            )
        if source.allowed_tenants is not None and (
            authorization.tenant_id not in source.allowed_tenants
        ):
            findings.append(
                self._finding(
                    PoisoningCode.TENANT_NOT_AUTHORIZED,
                    Severity.CRITICAL,
                    "Tenant is not authorized for this ingestion source",
                    "authorization",
                )
            )
        if source.allowed_purposes is not None and (
            authorization.purpose not in source.allowed_purposes
        ):
            findings.append(
                self._finding(
                    PoisoningCode.PURPOSE_NOT_AUTHORIZED,
                    Severity.HIGH,
                    "Ingestion purpose is not authorized for this source",
                    "authorization",
                )
            )
        return findings

    def _integrity_findings(self, record: DataIngestionRecord) -> list[PoisoningFinding]:
        payload = record.content.encode() if isinstance(record.content, str) else record.content
        actual = ArtifactDigest.from_bytes(payload, record.observed_digest.algorithm)
        findings: list[PoisoningFinding] = []
        if not record.observed_digest.matches(actual):
            findings.append(
                self._finding(
                    PoisoningCode.CONTENT_INTEGRITY_MISMATCH,
                    Severity.CRITICAL,
                    "Asset content does not match its observed integrity digest",
                    "integrity",
                )
            )

        expected = self._policy.expected_digests.get(record.item_id)
        if expected is None:
            if record.kind in self._policy.require_expected_digest_for:
                findings.append(
                    self._finding(
                        PoisoningCode.EXPECTED_DIGEST_MISSING,
                        Severity.CRITICAL,
                        "Trusted policy lacks a required expected digest for this asset",
                        "integrity",
                    )
                )
        elif not expected.matches(actual):
            findings.append(
                self._finding(
                    PoisoningCode.EXPECTED_DIGEST_MISMATCH,
                    Severity.CRITICAL,
                    "Asset content differs from the trusted expected digest",
                    "integrity",
                )
            )
        return findings

    def _lineage_findings(self, record: DataIngestionRecord) -> list[PoisoningFinding]:
        transformations = record.provenance.transformations
        broken = any(
            not previous.output_digest.matches(current.input_digest)
            for previous, current in pairwise(transformations)
        )
        if transformations and not transformations[-1].output_digest.matches(
            record.observed_digest
        ):
            broken = True
        if not broken:
            return []
        return [
            self._finding(
                PoisoningCode.BROKEN_TRANSFORMATION_LINEAGE,
                Severity.CRITICAL,
                "Asset transformation lineage contains an integrity gap",
                "lineage",
            )
        ]

    def _anomaly_findings(self, record: DataIngestionRecord) -> list[PoisoningFinding]:
        if record.anomaly_score is None or record.anomaly_score < self._policy.anomaly_threshold:
            return []
        return [
            self._finding(
                PoisoningCode.ANOMALY_THRESHOLD_EXCEEDED,
                Severity.HIGH,
                "Asset exceeded the configured anomaly threshold",
                "anomaly_score",
            )
        ]

    def _pattern_findings(self, record: DataIngestionRecord) -> list[PoisoningFinding]:
        if isinstance(record.content, str) and len(record.content) > self._policy.max_scan_chars:
            return [
                self._finding(
                    PoisoningCode.CONTENT_SCAN_LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Text asset exceeds the configured poisoning scan limit",
                    "instruction_patterns",
                )
            ]
        if isinstance(record.content, str) and self._contains_poisoning_pattern(record.content):
            return [
                self._finding(
                    PoisoningCode.SUSPICIOUS_INSTRUCTION,
                    Severity.HIGH,
                    "Asset contains a suspicious model-directed instruction",
                    "instruction_patterns",
                )
            ]
        if not self._policy.scan_metadata:
            return []

        metadata_values, limits_exceeded = self._metadata_strings(record.metadata)
        if limits_exceeded or any(
            self._contains_poisoning_pattern(value) for value in metadata_values
        ):
            return [
                self._finding(
                    PoisoningCode.SUSPICIOUS_METADATA,
                    Severity.HIGH,
                    "Asset metadata is anomalous or contains a suspicious instruction",
                    "metadata_patterns",
                )
            ]
        return []

    def _custom_detector_findings(self, record: DataIngestionRecord) -> list[PoisoningFinding]:
        findings: list[PoisoningFinding] = []
        for detector in self._detectors:
            try:
                severity = detector.detect(record)
            except Exception:
                severity = Severity.CRITICAL
            if severity is not None:
                detector_id = (
                    detector.detector_id
                    if _SAFE_DETECTOR_ID_RE.fullmatch(detector.detector_id)
                    else "custom_detector"
                )
                findings.append(
                    self._finding(
                        PoisoningCode.CUSTOM_DETECTOR,
                        severity,
                        "Application-specific detector reported an anomalous asset",
                        detector_id,
                    )
                )
        return findings

    def _contains_poisoning_pattern(self, value: str) -> bool:
        bounded = value[: self._policy.max_scan_chars]
        normalized = self._normalizer.normalize(bounded)
        variants = [normalized.normalized]
        variants.extend(self._normalizer.extract_base64_payloads(normalized.normalized))
        return any(
            pattern.search(variant) for variant in variants for pattern in _POISONING_PATTERNS
        )

    def _metadata_strings(self, metadata: dict[str, object]) -> tuple[list[str], bool]:
        strings: list[str] = []
        stack: list[tuple[object, int]] = [(metadata, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > self._policy.max_metadata_nodes or depth > self._policy.max_metadata_depth:
                return strings, True
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, dict):
                stack.extend((key, depth + 1) for key in value)
                stack.extend((nested, depth + 1) for nested in value.values())
            elif isinstance(value, (list, tuple)):
                stack.extend((nested, depth + 1) for nested in value)
        return strings, False

    @staticmethod
    def _finding(
        code: PoisoningCode,
        severity: Severity,
        message: str,
        detector_id: str,
    ) -> PoisoningFinding:
        return PoisoningFinding(
            code=code,
            severity=severity,
            message=message,
            detector_id=detector_id,
        )


def _is_mutable_version(version: str) -> bool:
    normalized = version.strip().casefold()
    return bool(_MUTABLE_VERSION_RE.search(normalized) or _VERSION_RANGE_RE.search(normalized))
