"""Fail-closed runtime enforcement for signed tool capability manifests."""

from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import JsonValue

from trustrail.exceptions import ToolManifestError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.tool_manifest import (
    AuthorizedToolExecution,
    ToolCapabilityEffect,
    ToolCapabilityManifest,
    ToolDataClassification,
    ToolEgressDestination,
    ToolEnforcementControl,
    ToolExecutionOutput,
    ToolExecutionRequest,
    ToolExecutorIdentity,
    ToolFilesystemCapability,
    ToolManifestBinding,
    ToolManifestBindingPhase,
    ToolManifestCode,
    ToolManifestDecision,
    ToolManifestFinding,
    ToolManifestPolicy,
    ToolManifestTrustedKey,
    ToolResourceLimits,
    ToolRuntimeEvidence,
    VerifiedToolOutput,
    canonical_tool_manifest_json,
    tool_manifest_digest,
    tool_manifest_reference,
    utcnow,
)

_CLASSIFICATION_RANK = {
    ToolDataClassification.PUBLIC: 0,
    ToolDataClassification.INTERNAL: 1,
    ToolDataClassification.CONFIDENTIAL: 2,
    ToolDataClassification.RESTRICTED: 3,
}


class ToolManifestSigner:
    """Issue Ed25519-signed manifests or control-plane bindings."""

    def __init__(self, private_key: Ed25519PrivateKey, *, authority_id: str) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = ToolManifestTrustedKey(
            authority_id=authority_id,
            public_key=public_key,
        )

    @classmethod
    def generate(cls, *, authority_id: str) -> ToolManifestSigner:
        return cls(Ed25519PrivateKey.generate(), authority_id=authority_id)

    @property
    def trusted_key(self) -> ToolManifestTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def sign_manifest(
        self,
        *,
        manifest_id: str,
        tool_id: str,
        version: str,
        executor: ToolExecutorIdentity,
        effects: frozenset[ToolCapabilityEffect],
        filesystem: ToolFilesystemCapability,
        resources: ToolResourceLimits,
        input_schema: dict[str, JsonValue],
        output_schema: dict[str, JsonValue],
        input_classifications: frozenset[ToolDataClassification],
        max_output_classification: ToolDataClassification,
        scopes: frozenset[str] = frozenset(),
        egress: frozenset[ToolEgressDestination] = frozenset(),
        credential_references: frozenset[str] = frozenset(),
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ToolCapabilityManifest:
        """Sign one canonical manifest for an exact executor identity."""
        current_time = issued_at or utcnow()
        unsigned = ToolCapabilityManifest(
            manifest_id=manifest_id,
            tool_id=tool_id,
            version=version,
            executor=executor,
            effects=effects,
            scopes=scopes,
            filesystem=filesystem,
            egress=egress,
            credential_references=credential_references,
            resources=resources,
            input_schema=input_schema,
            output_schema=output_schema,
            input_classifications=input_classifications,
            max_output_classification=max_output_classification,
            authority_id=self._trusted_key.authority_id,
            key_id=self._trusted_key.key_id,
            issued_at=current_time,
            expires_at=expires_at or current_time + timedelta(days=1),
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )

    def sign_binding(
        self,
        *,
        binding_id: str,
        phase: ToolManifestBindingPhase,
        manifest_digest: str,
        executor_identity_digest: str,
        discovery_digest: str | None = None,
        approved_by: str | None = None,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ToolManifestBinding:
        """Sign discovery or approval state in an isolated control plane."""
        current_time = issued_at or utcnow()
        unsigned = ToolManifestBinding(
            binding_id=binding_id,
            phase=phase,
            manifest_digest=manifest_digest,
            executor_identity_digest=executor_identity_digest,
            discovery_digest=discovery_digest,
            approved_by=approved_by,
            authority_id=self._trusted_key.authority_id,
            key_id=self._trusted_key.key_id,
            issued_at=current_time,
            expires_at=expires_at or current_time + timedelta(hours=1),
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class ToolRuntimeEvidenceSigner:
    """Issue signed evidence from a trusted runtime enforcement service."""

    def __init__(self, private_key: Ed25519PrivateKey, *, authority_id: str) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = ToolManifestTrustedKey(
            authority_id=authority_id,
            public_key=public_key,
        )

    @classmethod
    def generate(cls, *, authority_id: str) -> ToolRuntimeEvidenceSigner:
        return cls(Ed25519PrivateKey.generate(), authority_id=authority_id)

    @property
    def trusted_key(self) -> ToolManifestTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def sign(
        self,
        *,
        evidence_id: str,
        manifest_digest: str,
        executor: ToolExecutorIdentity,
        filesystem: ToolFilesystemCapability,
        egress: frozenset[ToolEgressDestination],
        credential_references: frozenset[str],
        resources: ToolResourceLimits,
        controls: frozenset[ToolEnforcementControl] | None = None,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ToolRuntimeEvidence:
        """Sign one short-lived snapshot of actively enforced limits."""
        current_time = issued_at or utcnow()
        unsigned = ToolRuntimeEvidence(
            evidence_id=evidence_id,
            manifest_digest=manifest_digest,
            executor=executor,
            filesystem=filesystem,
            egress=egress,
            credential_references=credential_references,
            resources=resources,
            controls=(controls if controls is not None else frozenset(ToolEnforcementControl)),
            authority_id=self._trusted_key.authority_id,
            key_id=self._trusted_key.key_id,
            issued_at=current_time,
            expires_at=expires_at or current_time + timedelta(minutes=1),
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class ToolCapabilityEnforcer:
    """Bind tool discovery, approval, dispatch, and output to one manifest.

    This class never executes a tool. Applications must place ``authorize``
    immediately before dispatch and release output only after ``verify_output``.
    """

    def __init__(
        self,
        *,
        manifest_keys: tuple[ToolManifestTrustedKey, ...],
        evidence_keys: tuple[ToolManifestTrustedKey, ...],
        control_signer: ToolManifestSigner,
        policy: ToolManifestPolicy | None = None,
    ) -> None:
        self._manifest_keys = {key.key_id: key.model_copy(deep=True) for key in manifest_keys}
        self._evidence_keys = {key.key_id: key.model_copy(deep=True) for key in evidence_keys}
        self._control_signer = control_signer
        self._control_key = control_signer.trusted_key
        self._policy = (policy or ToolManifestPolicy()).model_copy(deep=True)
        self._active: dict[str, str] = {}
        self._lock = threading.Lock()

    @property
    def policy(self) -> ToolManifestPolicy:
        return self._policy.model_copy(deep=True)

    def discover(
        self,
        manifest: ToolCapabilityManifest,
        executor: ToolExecutorIdentity,
        *,
        now: datetime | None = None,
    ) -> ToolManifestDecision:
        """Verify and bind discovery to the live measured executor."""
        current_time = now or utcnow()
        findings = self._manifest_findings(manifest, current_time)
        if manifest.executor != executor:
            findings.append(self._finding(ToolManifestCode.EXECUTOR_MISMATCH, manifest))
        if findings:
            return self._blocked(findings)
        binding = self._control_signer.sign_binding(
            binding_id=str(uuid.uuid4()),
            phase=ToolManifestBindingPhase.DISCOVERY,
            manifest_digest=manifest.manifest_digest,
            executor_identity_digest=executor.digest,
            issued_at=current_time,
            expires_at=current_time + timedelta(seconds=self._policy.binding_ttl_seconds),
        )
        return ToolManifestDecision(action=GuardAction.ALLOW, binding=binding)

    def require_discovery(
        self,
        manifest: ToolCapabilityManifest,
        executor: ToolExecutorIdentity,
        *,
        now: datetime | None = None,
    ) -> ToolManifestBinding:
        result = self.discover(manifest, executor, now=now)
        if not result.is_allowed or result.binding is None:
            raise ToolManifestError(result)
        return result.binding

    def approve(
        self,
        manifest: ToolCapabilityManifest,
        discovery: ToolManifestBinding,
        *,
        approved_by: str,
        now: datetime | None = None,
    ) -> ToolManifestDecision:
        """Bind explicit approval to the exact verified discovery."""
        current_time = now or utcnow()
        findings = self._manifest_findings(manifest, current_time)
        findings.extend(
            self._binding_findings(
                discovery,
                manifest,
                ToolManifestBindingPhase.DISCOVERY,
                current_time,
            )
        )
        if findings:
            return self._blocked(findings)
        binding = self._control_signer.sign_binding(
            binding_id=str(uuid.uuid4()),
            phase=ToolManifestBindingPhase.APPROVAL,
            manifest_digest=manifest.manifest_digest,
            executor_identity_digest=manifest.executor.digest,
            discovery_digest=discovery.binding_digest,
            approved_by=approved_by,
            issued_at=current_time,
            expires_at=min(
                discovery.expires_at,
                current_time + timedelta(seconds=self._policy.binding_ttl_seconds),
            ),
        )
        return ToolManifestDecision(action=GuardAction.ALLOW, binding=binding)

    def require_approval(
        self,
        manifest: ToolCapabilityManifest,
        discovery: ToolManifestBinding,
        *,
        approved_by: str,
        now: datetime | None = None,
    ) -> ToolManifestBinding:
        result = self.approve(manifest, discovery, approved_by=approved_by, now=now)
        if not result.is_allowed or result.binding is None:
            raise ToolManifestError(result)
        return result.binding

    def authorize(
        self,
        manifest: ToolCapabilityManifest,
        approval: ToolManifestBinding,
        request: ToolExecutionRequest,
        evidence: ToolRuntimeEvidence | None,
        *,
        now: datetime | None = None,
    ) -> ToolManifestDecision:
        """Fail closed unless the exact requested capabilities are actively enforced."""
        current_time = now or utcnow()
        findings = self._manifest_findings(manifest, current_time)
        findings.extend(
            self._binding_findings(
                approval,
                manifest,
                ToolManifestBindingPhase.APPROVAL,
                current_time,
            )
        )
        findings.extend(self._request_findings(request, manifest))
        if evidence is None:
            findings.append(self._finding(ToolManifestCode.EVIDENCE_REQUIRED, manifest))
        else:
            findings.extend(self._evidence_findings(evidence, manifest, request, current_time))
        findings = self._deduplicate(findings)
        if findings or evidence is None:
            return self._blocked(findings)

        authorization = AuthorizedToolExecution(
            authorization_id=str(uuid.uuid4()),
            execution_id=request.execution_id,
            manifest_digest=manifest.manifest_digest,
            approval_digest=approval.binding_digest,
            request_digest=request.request_digest,
            evidence_digest=evidence.evidence_digest,
            output_schema_digest=tool_manifest_digest(manifest.output_schema),
            max_output_classification=manifest.max_output_classification,
            output_limit_bytes=request.resources.output_bytes,
            issued_at=current_time,
            expires_at=min(
                manifest.expires_at,
                approval.expires_at,
                evidence.expires_at,
                current_time + timedelta(seconds=self._policy.authorization_ttl_seconds),
            ),
        )
        with self._lock:
            self._active[authorization.authorization_id] = authorization.authorization_digest
        return ToolManifestDecision(action=GuardAction.ALLOW, authorization=authorization)

    def require_authorization(
        self,
        manifest: ToolCapabilityManifest,
        approval: ToolManifestBinding,
        request: ToolExecutionRequest,
        evidence: ToolRuntimeEvidence | None,
        *,
        now: datetime | None = None,
    ) -> AuthorizedToolExecution:
        result = self.authorize(manifest, approval, request, evidence, now=now)
        if not result.is_allowed or result.authorization is None:
            raise ToolManifestError(result)
        return result.authorization

    def verify_output(
        self,
        manifest: ToolCapabilityManifest,
        authorization: AuthorizedToolExecution,
        output: ToolExecutionOutput,
        *,
        now: datetime | None = None,
    ) -> ToolManifestDecision:
        """Consume an execution lease and validate output before releasing it."""
        current_time = now or utcnow()
        findings: list[ToolManifestFinding] = []
        if (
            authorization.manifest_digest != manifest.manifest_digest
            or authorization.output_schema_digest != tool_manifest_digest(manifest.output_schema)
            or output.authorization_id != authorization.authorization_id
            or output.execution_id != authorization.execution_id
            or output.manifest_digest != authorization.manifest_digest
        ):
            findings.append(self._finding(ToolManifestCode.AUTHORIZATION_INVALID, manifest))
        if current_time > authorization.expires_at:
            findings.append(self._finding(ToolManifestCode.AUTHORIZATION_EXPIRED, manifest))
        with self._lock:
            active_digest = self._active.pop(authorization.authorization_id, None)
        if active_digest is None:
            findings.append(self._finding(ToolManifestCode.AUTHORIZATION_REPLAYED, manifest))
        elif active_digest != authorization.authorization_digest:
            findings.append(self._finding(ToolManifestCode.AUTHORIZATION_INVALID, manifest))
        if not self._matches_schema(output.value, manifest.output_schema):
            findings.append(self._finding(ToolManifestCode.OUTPUT_CONTRACT_INVALID, manifest))
        if (
            _CLASSIFICATION_RANK[output.classification]
            > _CLASSIFICATION_RANK[authorization.max_output_classification]
        ):
            findings.append(self._finding(ToolManifestCode.OUTPUT_CLASSIFICATION_DENIED, manifest))
        if (
            len(canonical_tool_manifest_json(output.value).encode())
            > authorization.output_limit_bytes
        ):
            findings.append(self._finding(ToolManifestCode.OUTPUT_LIMIT_EXCEEDED, manifest))
        findings = self._deduplicate(findings)
        if findings:
            return ToolManifestDecision(action=GuardAction.QUARANTINE, findings=tuple(findings))
        verified = VerifiedToolOutput(
            authorization_id=authorization.authorization_id,
            execution_id=authorization.execution_id,
            value=output.value,
            classification=output.classification,
            verified_at=current_time,
        )
        return ToolManifestDecision(action=GuardAction.ALLOW, output=verified)

    def require_output(
        self,
        manifest: ToolCapabilityManifest,
        authorization: AuthorizedToolExecution,
        output: ToolExecutionOutput,
        *,
        now: datetime | None = None,
    ) -> VerifiedToolOutput:
        result = self.verify_output(manifest, authorization, output, now=now)
        if not result.is_allowed or result.output is None:
            raise ToolManifestError(result)
        return result.output

    def _manifest_findings(
        self, manifest: ToolCapabilityManifest, now: datetime
    ) -> list[ToolManifestFinding]:
        if manifest.signature is None:
            return [self._finding(ToolManifestCode.MANIFEST_UNSIGNED, manifest)]
        key = self._manifest_keys.get(manifest.key_id)
        if key is None or key.authority_id != manifest.authority_id:
            return [self._finding(ToolManifestCode.MANIFEST_KEY_UNKNOWN, manifest)]
        if not self._key_active(key, now):
            return [self._finding(ToolManifestCode.MANIFEST_KEY_INACTIVE, manifest)]
        if not self._signature_valid(key, manifest.signing_bytes, manifest.signature):
            return [self._finding(ToolManifestCode.MANIFEST_SIGNATURE_INVALID, manifest)]
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        if manifest.issued_at > now + skew:
            return [self._finding(ToolManifestCode.MANIFEST_NOT_YET_VALID, manifest)]
        if manifest.expires_at < now - skew:
            return [self._finding(ToolManifestCode.MANIFEST_EXPIRED, manifest)]
        if now - manifest.issued_at > timedelta(seconds=self._policy.max_manifest_age_seconds):
            return [self._finding(ToolManifestCode.MANIFEST_EXPIRED, manifest)]
        return []

    def _binding_findings(
        self,
        binding: ToolManifestBinding,
        manifest: ToolCapabilityManifest,
        phase: ToolManifestBindingPhase,
        now: datetime,
    ) -> list[ToolManifestFinding]:
        code = (
            ToolManifestCode.DISCOVERY_INVALID
            if phase == ToolManifestBindingPhase.DISCOVERY
            else ToolManifestCode.APPROVAL_INVALID
        )
        invalid = (
            binding.phase != phase
            or binding.signature is None
            or binding.key_id != self._control_key.key_id
            or binding.authority_id != self._control_key.authority_id
            or not self._key_active(self._control_key, now)
            or not self._signature_valid(
                self._control_key,
                binding.signing_bytes,
                binding.signature or "",
            )
            or binding.issued_at > now + timedelta(seconds=self._policy.clock_skew_seconds)
            or binding.expires_at < now
        )
        findings = [self._finding(code, manifest)] if invalid else []
        if (
            binding.manifest_digest != manifest.manifest_digest
            or binding.executor_identity_digest != manifest.executor.digest
        ):
            findings.append(self._finding(ToolManifestCode.MANIFEST_SUBSTITUTION, manifest))
        return findings

    def _request_findings(
        self, request: ToolExecutionRequest, manifest: ToolCapabilityManifest
    ) -> list[ToolManifestFinding]:
        findings: list[ToolManifestFinding] = []
        if (
            request.tool_id != manifest.tool_id
            or request.version != manifest.version
            or request.manifest_digest != manifest.manifest_digest
            or request.executor != manifest.executor
        ):
            findings.append(self._finding(ToolManifestCode.REQUEST_INTEGRITY_INVALID, manifest))
        if not request.effects.issubset(manifest.effects) or not request.scopes.issubset(
            manifest.scopes
        ):
            findings.append(self._finding(ToolManifestCode.CAPABILITY_UNDECLARED, manifest))
        if not self._filesystem_within(request.filesystem, manifest.filesystem):
            findings.append(self._finding(ToolManifestCode.FILESYSTEM_WIDENED, manifest))
        if not request.egress.issubset(manifest.egress):
            findings.append(self._finding(ToolManifestCode.EGRESS_WIDENED, manifest))
        if not request.credential_references.issubset(manifest.credential_references):
            findings.append(self._finding(ToolManifestCode.CREDENTIAL_WIDENED, manifest))
        if not self._resources_within(request.resources, manifest.resources):
            findings.append(self._finding(ToolManifestCode.RESOURCE_LIMIT_WIDENED, manifest))
        if request.input_classification not in manifest.input_classifications:
            findings.append(self._finding(ToolManifestCode.DATA_CLASSIFICATION_DENIED, manifest))
        if not self._matches_schema(request.input_value, manifest.input_schema):
            findings.append(self._finding(ToolManifestCode.INPUT_CONTRACT_INVALID, manifest))
        return findings

    def _evidence_findings(
        self,
        evidence: ToolRuntimeEvidence,
        manifest: ToolCapabilityManifest,
        request: ToolExecutionRequest,
        now: datetime,
    ) -> list[ToolManifestFinding]:
        key = self._evidence_keys.get(evidence.key_id)
        if key is None or key.authority_id != evidence.authority_id:
            return [self._finding(ToolManifestCode.EVIDENCE_KEY_UNKNOWN, manifest)]
        if not self._key_active(key, now):
            return [self._finding(ToolManifestCode.EVIDENCE_KEY_INACTIVE, manifest)]
        if evidence.signature is None or not self._signature_valid(
            key, evidence.signing_bytes, evidence.signature
        ):
            return [self._finding(ToolManifestCode.EVIDENCE_SIGNATURE_INVALID, manifest)]
        findings: list[ToolManifestFinding] = []
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        if (
            evidence.issued_at > now + skew
            or evidence.expires_at < now
            or now - evidence.issued_at > timedelta(seconds=self._policy.max_evidence_age_seconds)
        ):
            findings.append(self._finding(ToolManifestCode.EVIDENCE_STALE, manifest))
        if (
            evidence.manifest_digest != manifest.manifest_digest
            or evidence.executor != manifest.executor
        ):
            findings.append(self._finding(ToolManifestCode.EVIDENCE_MISMATCH, manifest))
        missing = self._policy.required_controls - evidence.controls
        if missing:
            findings.append(self._finding(ToolManifestCode.ENFORCEMENT_CONTROL_MISSING, manifest))
        if not self._filesystem_within(evidence.filesystem, manifest.filesystem) or not (
            self._filesystem_within(request.filesystem, evidence.filesystem)
        ):
            findings.append(self._finding(ToolManifestCode.FILESYSTEM_WIDENED, manifest))
        if not evidence.egress.issubset(manifest.egress) or not request.egress.issubset(
            evidence.egress
        ):
            findings.append(self._finding(ToolManifestCode.EGRESS_WIDENED, manifest))
        if not evidence.credential_references.issubset(
            manifest.credential_references
        ) or not request.credential_references.issubset(evidence.credential_references):
            findings.append(self._finding(ToolManifestCode.CREDENTIAL_WIDENED, manifest))
        if not self._resources_within(
            evidence.resources, manifest.resources
        ) or not self._resources_within(request.resources, evidence.resources):
            findings.append(self._finding(ToolManifestCode.RESOURCE_LIMIT_WIDENED, manifest))
        return findings

    @staticmethod
    def _key_active(key: ToolManifestTrustedKey, now: datetime) -> bool:
        return (
            not key.revoked
            and not (key.active_from and now < key.active_from)
            and not (key.expires_at and now >= key.expires_at)
        )

    @staticmethod
    def _signature_valid(key: ToolManifestTrustedKey, payload: bytes, signature: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(signature), payload
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    @classmethod
    def _filesystem_within(
        cls,
        child: ToolFilesystemCapability,
        parent: ToolFilesystemCapability,
    ) -> bool:
        return cls._roots_within(child.read_roots, parent.read_roots) and cls._roots_within(
            child.write_roots, parent.write_roots
        )

    @staticmethod
    def _roots_within(children: tuple[str, ...], parents: tuple[str, ...]) -> bool:
        return all(
            any(PurePosixPath(child).is_relative_to(PurePosixPath(parent)) for parent in parents)
            for child in children
        )

    @staticmethod
    def _resources_within(child: ToolResourceLimits, parent: ToolResourceLimits) -> bool:
        return all(
            getattr(child, field) <= getattr(parent, field)
            for field in (
                "cpu_millis",
                "memory_bytes",
                "duration_ms",
                "output_bytes",
                "network_bytes",
            )
        )

    @classmethod
    def _matches_schema(cls, value: JsonValue, schema: dict[str, JsonValue]) -> bool:
        schema_type = schema["type"]
        type_matches = {
            "null": value is None,
            "boolean": isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "string": isinstance(value, str),
            "array": isinstance(value, list),
            "object": isinstance(value, dict),
        }
        if not type_matches[str(schema_type)]:
            return False
        if "const" in schema and canonical_tool_manifest_json(
            value
        ) != canonical_tool_manifest_json(schema["const"]):
            return False
        enum = schema.get("enum")
        if isinstance(enum, list) and canonical_tool_manifest_json(value) not in {
            canonical_tool_manifest_json(item) for item in enum
        }:
            return False
        if isinstance(value, str):
            minimum = schema.get("minLength")
            if isinstance(minimum, int) and len(value) < minimum:
                return False
            maximum = schema.get("maxLength")
            if isinstance(maximum, int) and len(value) > maximum:
                return False
            pattern = schema.get("pattern")
            if isinstance(pattern, str) and re.search(pattern, value) is None:
                return False
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if isinstance(minimum, (int, float)) and value < minimum:
                return False
            if isinstance(maximum, (int, float)) and value > maximum:
                return False
        if isinstance(value, list):
            minimum = schema.get("minItems")
            if isinstance(minimum, int) and len(value) < minimum:
                return False
            maximum = schema.get("maxItems")
            if isinstance(maximum, int) and len(value) > maximum:
                return False
            items = schema.get("items")
            if not isinstance(items, dict) or any(
                not cls._matches_schema(item, items) for item in value
            ):
                return False
        if isinstance(value, dict):
            properties = schema.get("properties")
            required = schema.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list):
                return False
            if not set(required).issubset(value) or not set(value).issubset(properties):
                return False
            if any(
                not isinstance(child_schema, dict)
                or not cls._matches_schema(value[name], child_schema)
                for name, child_schema in properties.items()
                if name in value
            ):
                return False
        return True

    @staticmethod
    def _finding(
        code: ToolManifestCode,
        manifest: ToolCapabilityManifest,
    ) -> ToolManifestFinding:
        messages = {
            ToolManifestCode.MANIFEST_UNSIGNED: "Tool manifest is unsigned",
            ToolManifestCode.MANIFEST_KEY_UNKNOWN: "Tool manifest authority is not trusted",
            ToolManifestCode.MANIFEST_KEY_INACTIVE: "Tool manifest key is inactive",
            ToolManifestCode.MANIFEST_SIGNATURE_INVALID: "Tool manifest signature is invalid",
            ToolManifestCode.MANIFEST_NOT_YET_VALID: "Tool manifest is not yet valid",
            ToolManifestCode.MANIFEST_EXPIRED: "Tool manifest is stale or expired",
            ToolManifestCode.EXECUTOR_MISMATCH: "Live executor identity differs from the manifest",
            ToolManifestCode.DISCOVERY_INVALID: "Manifest discovery binding is invalid",
            ToolManifestCode.APPROVAL_INVALID: "Manifest approval binding is invalid",
            ToolManifestCode.MANIFEST_SUBSTITUTION: "Manifest or executor was substituted",
            ToolManifestCode.REQUEST_INTEGRITY_INVALID: (
                "Execution request is not bound to the manifest"
            ),
            ToolManifestCode.CAPABILITY_UNDECLARED: (
                "Execution requests undeclared effects or scopes"
            ),
            ToolManifestCode.FILESYSTEM_WIDENED: (
                "Filesystem capability exceeds an enforced boundary"
            ),
            ToolManifestCode.EGRESS_WIDENED: "Egress capability exceeds an enforced boundary",
            ToolManifestCode.CREDENTIAL_WIDENED: (
                "Credential capability exceeds an enforced boundary"
            ),
            ToolManifestCode.RESOURCE_LIMIT_WIDENED: "Resource limits exceed an enforced boundary",
            ToolManifestCode.DATA_CLASSIFICATION_DENIED: (
                "Input data classification is not declared"
            ),
            ToolManifestCode.INPUT_CONTRACT_INVALID: "Tool input violates its declared contract",
            ToolManifestCode.EVIDENCE_REQUIRED: "Runtime enforcement evidence is required",
            ToolManifestCode.EVIDENCE_KEY_UNKNOWN: "Runtime evidence authority is not trusted",
            ToolManifestCode.EVIDENCE_KEY_INACTIVE: "Runtime evidence key is inactive",
            ToolManifestCode.EVIDENCE_SIGNATURE_INVALID: "Runtime evidence signature is invalid",
            ToolManifestCode.EVIDENCE_STALE: "Runtime enforcement evidence is stale or expired",
            ToolManifestCode.EVIDENCE_MISMATCH: (
                "Runtime evidence is bound to another executor or manifest"
            ),
            ToolManifestCode.ENFORCEMENT_CONTROL_MISSING: (
                "A required runtime control is not active"
            ),
            ToolManifestCode.AUTHORIZATION_INVALID: "Execution authorization binding is invalid",
            ToolManifestCode.AUTHORIZATION_EXPIRED: "Execution authorization has expired",
            ToolManifestCode.AUTHORIZATION_REPLAYED: (
                "Execution authorization is absent or already consumed"
            ),
            ToolManifestCode.OUTPUT_CONTRACT_INVALID: "Tool output violates its declared contract",
            ToolManifestCode.OUTPUT_CLASSIFICATION_DENIED: (
                "Tool output exceeds its classification boundary"
            ),
            ToolManifestCode.OUTPUT_LIMIT_EXCEEDED: "Tool output exceeds its byte limit",
        }
        return ToolManifestFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=messages[code],
            tool_reference=tool_manifest_reference(manifest.tool_id),
        )

    @staticmethod
    def _deduplicate(findings: list[ToolManifestFinding]) -> list[ToolManifestFinding]:
        seen: set[ToolManifestCode] = set()
        result: list[ToolManifestFinding] = []
        for finding in findings:
            if finding.code not in seen:
                seen.add(finding.code)
                result.append(finding)
        return result

    @staticmethod
    def _blocked(findings: list[ToolManifestFinding]) -> ToolManifestDecision:
        return ToolManifestDecision(action=GuardAction.BLOCK, findings=tuple(findings))
