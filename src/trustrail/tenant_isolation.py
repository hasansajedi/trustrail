"""Fail-closed multi-tenant isolation for AI state, caches, and batching."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import threading
from collections import deque
from datetime import datetime
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail.exceptions import TenantIsolationError
from trustrail.models.data_labels import canonical_data_label_json
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.tenant_isolation import (
    AuthorizedTenantBatch,
    AuthorizedTenantStateAccess,
    DeploymentAttestationEvidence,
    DeploymentAttestationTrustedKey,
    DeploymentIsolationAttestation,
    IsolationLevel,
    TenantBatchRequest,
    TenantContextTrustedKey,
    TenantIsolationAuditEvent,
    TenantIsolationCode,
    TenantIsolationDecision,
    TenantIsolationFinding,
    TenantIsolationPolicy,
    TenantSecurityContext,
    TenantStateAccessRequest,
    TenantStateBinding,
    TenantStateKey,
    TenantStateKind,
    TenantStateOperation,
    tenant_isolation_digest,
    tenant_isolation_reference,
    utcnow,
)

_ISOLATION_RANK = {
    IsolationLevel.LOGICAL: 0,
    IsolationLevel.PROCESS: 1,
    IsolationLevel.HARDWARE: 2,
}


class TenantIsolationAuditSink(Protocol):
    """Persist content-free tenant-isolation decisions."""

    def emit(self, event: TenantIsolationAuditEvent) -> None: ...


class TenantKeyClaimStore(Protocol):
    """Atomically claim a storage key for one ownership digest."""

    def claim(self, storage_key: str, owner_digest: str) -> bool: ...


class MemoryTenantIsolationAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[TenantIsolationAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: TenantIsolationAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[TenantIsolationAuditEvent]:
        with self._lock:
            return list(self._events)


class MemoryTenantKeyClaimStore:
    """Process-local atomic key registry for tests and single-worker deployments."""

    def __init__(self) -> None:
        self._owners: dict[str, str] = {}
        self._lock = threading.Lock()

    def claim(self, storage_key: str, owner_digest: str) -> bool:
        with self._lock:
            existing = self._owners.get(storage_key)
            if existing is not None and existing != owner_digest:
                return False
            self._owners[storage_key] = owner_digest
            return True


class TenantContextSigner:
    """Issue tenant contexts after external identity and membership checks."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        issuer_id: str,
        allowed_tenant_ids: frozenset[str],
    ) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = TenantContextTrustedKey(
            issuer_id=issuer_id,
            public_key=public_key,
            allowed_tenant_ids=allowed_tenant_ids,
        )

    @classmethod
    def generate(
        cls,
        *,
        issuer_id: str,
        allowed_tenant_ids: frozenset[str],
    ) -> TenantContextSigner:
        """Create a signer backed by a new Ed25519 key pair."""
        return cls(
            Ed25519PrivateKey.generate(),
            issuer_id=issuer_id,
            allowed_tenant_ids=allowed_tenant_ids,
        )

    @property
    def trusted_key(self) -> TenantContextTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def issue(
        self,
        *,
        context_id: str,
        tenant_id: str,
        principal_id: str,
        session_id: str,
        allowed_state_kinds: frozenset[TenantStateKind],
        issued_at: datetime,
        expires_at: datetime,
        nonce: str,
    ) -> TenantSecurityContext:
        """Issue an immutable context for an authenticated tenant membership."""
        if tenant_id not in self._trusted_key.allowed_tenant_ids:
            raise ValueError("context issuer is not authorized for the tenant")
        unsigned = TenantSecurityContext(
            context_id=context_id,
            issuer_id=self._trusted_key.issuer_id,
            key_id=self._trusted_key.key_id,
            tenant_id=tenant_id,
            principal_id=principal_id,
            session_id=session_id,
            allowed_state_kinds=allowed_state_kinds,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class TenantContextVerifier:
    """Verify tenant-context issuer, authority, signature, and freshness."""

    def __init__(self, trusted_keys: tuple[TenantContextTrustedKey, ...]) -> None:
        if len({key.key_id for key in trusted_keys}) != len(trusted_keys):
            raise ValueError("trusted tenant-context key IDs must be unique")
        self._keys = {key.key_id: key.model_copy(deep=True) for key in trusted_keys}

    def findings(
        self,
        context: TenantSecurityContext,
        *,
        now: datetime,
    ) -> list[TenantIsolationFinding]:
        if context.signature is None:
            return [_finding(TenantIsolationCode.CONTEXT_UNSIGNED, "Tenant context is unsigned")]
        key = self._keys.get(context.key_id)
        if key is None or key.revoked:
            return [
                _finding(
                    TenantIsolationCode.CONTEXT_KEY_UNKNOWN,
                    "Tenant context issuer key is unavailable",
                )
            ]
        if key.issuer_id != context.issuer_id or context.tenant_id not in key.allowed_tenant_ids:
            return [
                _finding(
                    TenantIsolationCode.CONTEXT_ISSUER_MISMATCH,
                    "Context issuer is not authorized for the tenant",
                )
            ]
        if key.active_from is not None and now < key.active_from:
            return [
                _finding(
                    TenantIsolationCode.CONTEXT_KEY_UNKNOWN,
                    "Tenant context issuer key is not active",
                )
            ]
        if key.expires_at is not None and now >= key.expires_at:
            return [
                _finding(
                    TenantIsolationCode.CONTEXT_KEY_UNKNOWN,
                    "Tenant context issuer key has expired",
                )
            ]
        if now < context.issued_at or now >= context.expires_at:
            return [
                _finding(
                    TenantIsolationCode.CONTEXT_EXPIRED,
                    "Tenant context is outside its usable lifetime",
                    Severity.HIGH,
                )
            ]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(context.signature), context.signing_bytes
            )
        except (InvalidSignature, ValueError):
            return [
                _finding(
                    TenantIsolationCode.CONTEXT_SIGNATURE_INVALID,
                    "Tenant context signature is invalid",
                )
            ]
        return []


class TenantStateKeyBuilder:
    """Build tenant- and state-domain-separated opaque keys and bindings."""

    def __init__(self, secret: bytes, *, namespace: str) -> None:
        if len(secret) < 32:
            raise ValueError("tenant state key secret must contain at least 32 bytes")
        if not namespace or len(namespace) > 256:
            raise ValueError("namespace must be between 1 and 256 characters")
        self._secret = bytes(secret)
        self._namespace = namespace
        self._namespace_ref = self._reference("namespace", namespace)

    def tenant_reference(self, tenant_id: str) -> str:
        """Return the deployment-specific opaque reference for a tenant."""
        return self._reference("tenant", tenant_id)

    def build(
        self,
        context: TenantSecurityContext,
        *,
        state_kind: TenantStateKind,
        artifact_id: str,
        partition_id: str = "default",
    ) -> TenantStateKey:
        """Build a key that cannot collide across tenant or state domains."""
        tenant_ref = self.tenant_reference(context.tenant_id)
        partition_ref = self._reference("partition", partition_id)
        artifact_ref = self._reference("artifact", artifact_id)
        payload = {
            "format_version": 1,
            "namespace_ref": self._namespace_ref,
            "tenant_ref": tenant_ref,
            "state_kind": state_kind,
            "partition_ref": partition_ref,
            "artifact_ref": artifact_ref,
        }
        key_digest = self._mac("storage-key", canonical_data_label_json(payload))
        storage_key = f"trustrail:v1:{state_kind.value}:{key_digest}"
        return TenantStateKey(
            storage_key=storage_key,
            namespace_ref=self._namespace_ref,
            tenant_ref=tenant_ref,
            state_kind=state_kind,
            partition_ref=partition_ref,
            artifact_ref=artifact_ref,
            context_digest=context.context_digest,
        )

    def bind(
        self,
        state_key: TenantStateKey,
        *,
        created_at: datetime,
        expires_at: datetime,
    ) -> TenantStateBinding:
        """Create integrity-protected ownership metadata to store with a value."""
        unsigned = TenantStateBinding(
            storage_key=state_key.storage_key,
            owner_digest=state_key.owner_digest,
            tenant_ref=state_key.tenant_ref,
            state_kind=state_key.state_kind,
            artifact_ref=state_key.artifact_ref,
            context_digest=state_key.context_digest,
            created_at=created_at,
            expires_at=expires_at,
            integrity_tag="0" * 64,
        )
        tag = self._mac("state-binding", canonical_data_label_json(unsigned.signing_payload))
        return unsigned.model_copy(update={"integrity_tag": tag}, deep=True)

    def verify_binding(self, binding: TenantStateBinding) -> bool:
        """Verify state ownership metadata without trusting stored fields."""
        expected = self._mac("state-binding", canonical_data_label_json(binding.signing_payload))
        return hmac.compare_digest(expected, binding.integrity_tag)

    def _reference(self, domain: str, value: str) -> str:
        return f"hmac-sha256:{self._mac(domain, value)}"

    def _mac(self, domain: str, value: str) -> str:
        message = f"trustrail-tenant-isolation-v1\0{domain}\0{value}".encode()
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()


class DeploymentAttestationSigner:
    """Issue external deployment-isolation claims for library validation."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        issuer_id: str,
        allowed_deployment_ids: frozenset[str],
    ) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = DeploymentAttestationTrustedKey(
            issuer_id=issuer_id,
            public_key=public_key,
            allowed_deployment_refs=frozenset(
                tenant_isolation_reference(item) for item in allowed_deployment_ids
            ),
        )

    @classmethod
    def generate(
        cls,
        *,
        issuer_id: str,
        allowed_deployment_ids: frozenset[str],
    ) -> DeploymentAttestationSigner:
        """Create an attestation signer backed by a new Ed25519 key pair."""
        return cls(
            Ed25519PrivateKey.generate(),
            issuer_id=issuer_id,
            allowed_deployment_ids=allowed_deployment_ids,
        )

    @property
    def trusted_key(self) -> DeploymentAttestationTrustedKey:
        return self._trusted_key.model_copy(deep=True)

    def issue(
        self,
        *,
        attestation_id: str,
        deployment_id: str,
        isolation_level: IsolationLevel,
        covered_state_kinds: frozenset[TenantStateKind],
        measurement_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        dedicated_tenant_ref: str | None = None,
    ) -> DeploymentIsolationAttestation:
        """Sign claims produced by an independently trusted deployment authority."""
        deployment_ref = tenant_isolation_reference(deployment_id)
        if deployment_ref not in self._trusted_key.allowed_deployment_refs:
            raise ValueError("attestor is not authorized for the deployment")
        unsigned = DeploymentIsolationAttestation(
            attestation_id=attestation_id,
            issuer_id=self._trusted_key.issuer_id,
            key_id=self._trusted_key.key_id,
            deployment_ref=deployment_ref,
            isolation_level=isolation_level,
            covered_state_kinds=covered_state_kinds,
            dedicated_tenant_ref=dedicated_tenant_ref,
            measurement_digest=measurement_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class DeploymentAttestationVerifier:
    """Validate attestation signatures and claims, not deployed infrastructure."""

    def __init__(self, trusted_keys: tuple[DeploymentAttestationTrustedKey, ...]) -> None:
        if len({key.key_id for key in trusted_keys}) != len(trusted_keys):
            raise ValueError("trusted attestation key IDs must be unique")
        self._keys = {key.key_id: key.model_copy(deep=True) for key in trusted_keys}

    def findings(
        self,
        attestation: DeploymentIsolationAttestation,
        *,
        deployment_id: str,
        state_kind: TenantStateKind,
        required_level: IsolationLevel,
        required_tenant_ref: str | None,
        now: datetime,
    ) -> list[TenantIsolationFinding]:
        if attestation.signature is None:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_UNSIGNED,
                    "Deployment isolation attestation is unsigned",
                )
            ]
        key = self._keys.get(attestation.key_id)
        if key is None or key.revoked:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_KEY_UNKNOWN,
                    "Deployment attestation key is unavailable",
                )
            ]
        if (
            key.issuer_id != attestation.issuer_id
            or attestation.deployment_ref not in key.allowed_deployment_refs
        ):
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_ISSUER_MISMATCH,
                    "Attestor is not authorized for the claimed deployment",
                )
            ]
        if key.active_from is not None and now < key.active_from:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_KEY_UNKNOWN,
                    "Deployment attestation key is not active",
                )
            ]
        if key.expires_at is not None and now >= key.expires_at:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_KEY_UNKNOWN,
                    "Deployment attestation key has expired",
                )
            ]
        if now < attestation.issued_at or now >= attestation.expires_at:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_EXPIRED,
                    "Deployment isolation attestation is outside its usable lifetime",
                    Severity.HIGH,
                )
            ]
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                bytes.fromhex(attestation.signature), attestation.signing_bytes
            )
        except (InvalidSignature, ValueError):
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_SIGNATURE_INVALID,
                    "Deployment isolation attestation signature is invalid",
                )
            ]
        if (
            attestation.deployment_ref != tenant_isolation_reference(deployment_id)
            or state_kind not in attestation.covered_state_kinds
            or (
                required_tenant_ref is not None
                and attestation.dedicated_tenant_ref != required_tenant_ref
            )
        ):
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_SCOPE_MISMATCH,
                    "Deployment attestation does not cover the requested tenant state",
                )
            ]
        if _ISOLATION_RANK[attestation.isolation_level] < _ISOLATION_RANK[required_level]:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_LEVEL_INSUFFICIENT,
                    "Claimed deployment isolation is weaker than policy requires",
                    Severity.HIGH,
                )
            ]
        return []


class TenantIsolationGuard:
    """Mediate every tenant-owned AI state operation and inference batch."""

    def __init__(
        self,
        policy: TenantIsolationPolicy,
        key_builder: TenantStateKeyBuilder,
        trusted_context_keys: tuple[TenantContextTrustedKey, ...],
        *,
        trusted_attestation_keys: tuple[DeploymentAttestationTrustedKey, ...] = (),
        key_claim_store: TenantKeyClaimStore | None = None,
        audit_sink: TenantIsolationAuditSink | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._key_builder = key_builder
        self._context_verifier = TenantContextVerifier(trusted_context_keys)
        self._attestation_verifier = DeploymentAttestationVerifier(trusted_attestation_keys)
        self._claim_store = key_claim_store or MemoryTenantKeyClaimStore()
        self._audit_sink = audit_sink

    def authorize_state(
        self,
        request: TenantStateAccessRequest,
        *,
        now: datetime | None = None,
    ) -> TenantIsolationDecision:
        """Authorize one exact tenant state operation before storage or cache use."""
        current_time = now or utcnow()
        findings: list[TenantIsolationFinding] = []
        context = request.context
        expected_key: TenantStateKey | None = None
        evidence: DeploymentAttestationEvidence | None = None

        if context is None:
            findings.append(
                _finding(
                    TenantIsolationCode.CONTEXT_MISSING,
                    "Tenant-owned state requires a trusted tenant context",
                )
            )
        else:
            findings.extend(self._context_verifier.findings(context, now=current_time))
            if request.state_kind not in context.allowed_state_kinds:
                findings.append(
                    _finding(
                        TenantIsolationCode.STATE_KIND_DENIED,
                        "Tenant context does not authorize this state category",
                        Severity.HIGH,
                    )
                )
            rule = self._policy.rule_for(request.state_kind)
            if request.operation not in rule.allowed_operations:
                findings.append(
                    _finding(
                        TenantIsolationCode.OPERATION_DENIED,
                        "Isolation policy does not authorize this state operation",
                        Severity.HIGH,
                    )
                )
            expected_key = self._key_builder.build(
                context,
                state_kind=request.state_kind,
                artifact_id=request.artifact_id,
                partition_id=request.partition_id,
            )
            if request.state_key is None or not _same_state_key(request.state_key, expected_key):
                findings.append(
                    _finding(
                        TenantIsolationCode.STATE_KEY_INVALID,
                        "State key is not bound to the authenticated tenant and artifact",
                    )
                )
            findings.extend(
                self._attestation_findings(
                    rule.required_isolation_level,
                    rule.require_dedicated_tenant,
                    request.state_kind,
                    context,
                    request.deployment_id,
                    request.attestation,
                    current_time,
                )
            )
            evidence = _attestation_evidence(request.attestation, findings)

            if request.operation == TenantStateOperation.WRITE:
                findings.extend(
                    self._write_findings(request, rule.maximum_ttl_seconds, current_time)
                )
            else:
                findings.extend(
                    self._observed_binding_findings(request, expected_key, current_time)
                )

        permit: AuthorizedTenantStateAccess | None = None
        if context is not None and expected_key is not None and not findings:
            binding = None
            if request.operation == TenantStateOperation.WRITE:
                assert request.requested_expires_at is not None
                if not self._claim_store.claim(expected_key.storage_key, expected_key.owner_digest):
                    findings.append(
                        _finding(
                            TenantIsolationCode.STATE_KEY_COLLISION,
                            "State key is already claimed by different ownership metadata",
                        )
                    )
                else:
                    binding = self._key_builder.bind(
                        expected_key,
                        created_at=current_time,
                        expires_at=request.requested_expires_at,
                    )
            if not findings:
                permit = AuthorizedTenantStateAccess(
                    permit_id=tenant_isolation_digest(
                        {
                            "request_id": request.request_id,
                            "context": context.context_digest,
                            "key": expected_key.storage_key,
                            "operation": request.operation,
                        }
                    ),
                    context_digest=context.context_digest,
                    tenant_ref=expected_key.tenant_ref,
                    state_kind=request.state_kind,
                    operation=request.operation,
                    storage_key=expected_key.storage_key,
                    binding=binding,
                )

        return self._state_decision(request, permit, findings, evidence, current_time)

    def require_state(
        self,
        request: TenantStateAccessRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizedTenantStateAccess:
        """Return an exact state permit or raise before tenant state is touched."""
        result = self.authorize_state(request, now=now)
        if not result.is_allowed or result.access_permit is None:
            raise TenantIsolationError(result)
        return result.access_permit

    def authorize_batch(
        self,
        request: TenantBatchRequest,
        *,
        now: datetime | None = None,
    ) -> TenantIsolationDecision:
        """Reject mixed-tenant inference batches before enqueue or provider calls."""
        current_time = now or utcnow()
        findings: list[TenantIsolationFinding] = []
        for context in request.contexts:
            findings.extend(self._context_verifier.findings(context, now=current_time))
            if request.state_kind not in context.allowed_state_kinds:
                findings.append(
                    _finding(
                        TenantIsolationCode.STATE_KIND_DENIED,
                        "A batch context does not authorize the requested state category",
                        Severity.HIGH,
                    )
                )
        tenant_ids = {context.tenant_id for context in request.contexts}
        if len(tenant_ids) != 1:
            findings.append(
                _finding(
                    TenantIsolationCode.BATCH_CROSS_TENANT,
                    "Inference batch combines more than one tenant",
                )
            )

        first_context = request.contexts[0]
        rule = self._policy.rule_for(request.state_kind)
        findings.extend(
            self._attestation_findings(
                rule.required_isolation_level,
                rule.require_dedicated_tenant,
                request.state_kind,
                first_context,
                request.deployment_id,
                request.attestation,
                current_time,
            )
        )
        evidence = _attestation_evidence(request.attestation, findings)
        permit: AuthorizedTenantBatch | None = None
        if not findings:
            tenant_ref = self._key_builder.tenant_reference(first_context.tenant_id)
            context_digests = tuple(context.context_digest for context in request.contexts)
            permit = AuthorizedTenantBatch(
                permit_id=tenant_isolation_digest(
                    {
                        "request_id": request.request_id,
                        "tenant_ref": tenant_ref,
                        "state_kind": request.state_kind,
                        "contexts": context_digests,
                    }
                ),
                tenant_ref=tenant_ref,
                state_kind=request.state_kind,
                context_digests=context_digests,
            )

        action = GuardAction.ALLOW if permit is not None else GuardAction.BLOCK
        code = TenantIsolationCode.ALLOWED if permit is not None else findings[0].code
        audit = TenantIsolationAuditEvent(
            occurred_at=current_time,
            action=action,
            code=code,
            request_ref=tenant_isolation_reference(request.request_id),
            tenant_ref=(
                self._key_builder.tenant_reference(first_context.tenant_id)
                if len(tenant_ids) == 1
                else None
            ),
            state_kind=request.state_kind,
            operation="batch",
            attestation_ref=(
                tenant_isolation_reference(request.attestation.attestation_digest)
                if request.attestation is not None
                else None
            ),
        )
        self._publish(audit)
        return TenantIsolationDecision(
            action=action,
            findings=tuple(_deduplicate(findings)),
            batch_permit=permit,
            attestation_evidence=evidence,
            audit_event=audit,
        )

    def require_batch(
        self,
        request: TenantBatchRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizedTenantBatch:
        """Return a single-tenant batch permit or raise before enqueue."""
        result = self.authorize_batch(request, now=now)
        if not result.is_allowed or result.batch_permit is None:
            raise TenantIsolationError(result)
        return result.batch_permit

    def _write_findings(
        self,
        request: TenantStateAccessRequest,
        maximum_ttl_seconds: int,
        now: datetime,
    ) -> list[TenantIsolationFinding]:
        expires_at = request.requested_expires_at
        if (
            expires_at is None
            or expires_at <= now
            or (expires_at - now).total_seconds() > maximum_ttl_seconds
        ):
            return [
                _finding(
                    TenantIsolationCode.RETENTION_DENIED,
                    "State lifetime must be positive and bounded by isolation policy",
                    Severity.HIGH,
                )
            ]
        return []

    def _observed_binding_findings(
        self,
        request: TenantStateAccessRequest,
        expected_key: TenantStateKey,
        now: datetime,
    ) -> list[TenantIsolationFinding]:
        binding = request.observed_binding
        if binding is None:
            return [
                _finding(
                    TenantIsolationCode.STATE_BINDING_MISSING,
                    "Stored tenant ownership metadata is required",
                )
            ]
        findings: list[TenantIsolationFinding] = []
        if not self._key_builder.verify_binding(binding) or now >= binding.expires_at:
            findings.append(
                _finding(
                    TenantIsolationCode.STATE_BINDING_INVALID,
                    "Stored tenant ownership metadata is invalid or expired",
                )
            )
        if binding.tenant_ref != expected_key.tenant_ref:
            findings.append(_tenant_mismatch_finding(request.operation))
        if binding.state_kind != request.state_kind:
            findings.append(
                _finding(
                    TenantIsolationCode.STATE_KIND_MISMATCH,
                    "Stored value belongs to a different state category",
                )
            )
        if (
            binding.storage_key != expected_key.storage_key
            or binding.owner_digest != expected_key.owner_digest
            or binding.artifact_ref != expected_key.artifact_ref
        ):
            findings.append(
                _finding(
                    TenantIsolationCode.STATE_BINDING_INVALID,
                    "Stored ownership metadata does not match the requested state key",
                )
            )
        return findings

    def _attestation_findings(
        self,
        required_level: IsolationLevel,
        require_dedicated_tenant: bool,
        state_kind: TenantStateKind,
        context: TenantSecurityContext,
        deployment_id: str | None,
        attestation: DeploymentIsolationAttestation | None,
        now: datetime,
    ) -> list[TenantIsolationFinding]:
        if attestation is None:
            if required_level != IsolationLevel.LOGICAL:
                return [
                    _finding(
                        TenantIsolationCode.ATTESTATION_REQUIRED,
                        "Policy requires a deployment isolation attestation",
                        Severity.HIGH,
                    )
                ]
            return []
        if deployment_id is None:
            return [
                _finding(
                    TenantIsolationCode.ATTESTATION_SCOPE_MISMATCH,
                    "An attestation requires an exact deployment identifier",
                )
            ]
        tenant_ref = (
            self._key_builder.tenant_reference(context.tenant_id)
            if require_dedicated_tenant
            else None
        )
        return self._attestation_verifier.findings(
            attestation,
            deployment_id=deployment_id,
            state_kind=state_kind,
            required_level=required_level,
            required_tenant_ref=tenant_ref,
            now=now,
        )

    def _state_decision(
        self,
        request: TenantStateAccessRequest,
        permit: AuthorizedTenantStateAccess | None,
        findings: list[TenantIsolationFinding],
        evidence: DeploymentAttestationEvidence | None,
        now: datetime,
    ) -> TenantIsolationDecision:
        action = GuardAction.ALLOW if permit is not None else GuardAction.BLOCK
        code = TenantIsolationCode.ALLOWED if permit is not None else findings[0].code
        tenant_ref = permit.tenant_ref if permit is not None else None
        if tenant_ref is None and request.context is not None:
            tenant_ref = self._key_builder.tenant_reference(request.context.tenant_id)
        audit = TenantIsolationAuditEvent(
            occurred_at=now,
            action=action,
            code=code,
            request_ref=tenant_isolation_reference(request.request_id),
            tenant_ref=tenant_ref,
            state_kind=request.state_kind,
            operation=request.operation,
            state_key_ref=(
                tenant_isolation_reference(request.state_key.storage_key)
                if request.state_key is not None
                else None
            ),
            attestation_ref=(
                tenant_isolation_reference(request.attestation.attestation_digest)
                if request.attestation is not None
                else None
            ),
        )
        self._publish(audit)
        return TenantIsolationDecision(
            action=action,
            findings=tuple(_deduplicate(findings)),
            access_permit=permit,
            attestation_evidence=evidence,
            audit_event=audit,
        )

    def _publish(self, event: TenantIsolationAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


def _same_state_key(actual: TenantStateKey, expected: TenantStateKey) -> bool:
    return (
        actual.storage_key == expected.storage_key
        and actual.namespace_ref == expected.namespace_ref
        and actual.tenant_ref == expected.tenant_ref
        and actual.state_kind == expected.state_kind
        and actual.partition_ref == expected.partition_ref
        and actual.artifact_ref == expected.artifact_ref
    )


def _tenant_mismatch_finding(
    operation: TenantStateOperation,
) -> TenantIsolationFinding:
    if operation == TenantStateOperation.CACHE_HIT:
        code = TenantIsolationCode.CACHE_HIT_CROSS_TENANT
        message = "Cache hit belongs to a different tenant"
    elif operation == TenantStateOperation.ADAPTER_USE:
        code = TenantIsolationCode.ADAPTER_CROSS_TENANT
        message = "Adapter belongs to a different tenant"
    elif operation == TenantStateOperation.RESTORE:
        code = TenantIsolationCode.RESTORE_CROSS_TENANT
        message = "Restored state belongs to a different tenant"
    else:
        code = TenantIsolationCode.STATE_TENANT_MISMATCH
        message = "Stored state belongs to a different tenant"
    return _finding(code, message)


def _attestation_evidence(
    attestation: DeploymentIsolationAttestation | None,
    findings: list[TenantIsolationFinding],
) -> DeploymentAttestationEvidence | None:
    if attestation is None or any(
        finding.code.value.startswith("attestation_") for finding in findings
    ):
        return None
    return DeploymentAttestationEvidence(
        attestation_digest=attestation.attestation_digest,
        deployment_ref=attestation.deployment_ref,
        claimed_isolation_level=attestation.isolation_level,
    )


def _finding(
    code: TenantIsolationCode,
    message: str,
    severity: Severity = Severity.CRITICAL,
) -> TenantIsolationFinding:
    return TenantIsolationFinding(code=code, severity=severity, message=message)


def _deduplicate(
    findings: list[TenantIsolationFinding],
) -> list[TenantIsolationFinding]:
    unique: list[TenantIsolationFinding] = []
    seen: set[TenantIsolationCode] = set()
    for finding in findings:
        if finding.code not in seen:
            unique.append(finding)
            seen.add(finding.code)
    return unique
