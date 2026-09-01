"""Bypass corpus for OWASP ASI03 identity and privilege abuse."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    AgentIdentity,
    AgentIdentityKind,
    DelegatedAccessPolicy,
    DelegatedAccessRequest,
    DelegatedCapability,
    DelegatedIdentityAuthorizer,
    DelegationChain,
    StaticDelegatedCapabilityVerifier,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "identity_privilege_abuse.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


def _identity(identity_id: str, kind: AgentIdentityKind) -> AgentIdentity:
    return AgentIdentity(identity_id=identity_id, kind=kind, tenant_id="tenant-a")


def _chain(
    *,
    issued_at: datetime = NOW - timedelta(seconds=5),
    root_expiry: datetime = NOW + timedelta(minutes=10),
    leaf_expiry: datetime = NOW + timedelta(minutes=5),
) -> DelegationChain:
    user = _identity("user-a", AgentIdentityKind.HUMAN)
    agent = _identity("primary-agent", AgentIdentityKind.AGENT)
    sub_agent = _identity("worker-agent", AgentIdentityKind.SUB_AGENT)
    root = DelegatedCapability.create(
        capability_id="security-root",
        issuer=user,
        subject=agent,
        scopes=frozenset({"records:read", "records:delete"}),
        delegatable_scopes=frozenset({"records:read", "records:delete"}),
        audiences=frozenset({"tool:records.read", "tool:records.delete"}),
        purpose_id="case-review",
        issued_at=issued_at,
        not_before=issued_at,
        expires_at=root_expiry,
        max_delegation_depth=1,
    )
    leaf = DelegatedCapability.create(
        capability_id="security-leaf",
        issuer=agent,
        subject=sub_agent,
        scopes=frozenset({"records:read", "records:delete"}),
        audiences=frozenset({"tool:records.read", "tool:records.delete"}),
        purpose_id="case-review",
        issued_at=issued_at,
        not_before=issued_at,
        expires_at=leaf_expiry,
        delegation_depth=1,
        max_delegation_depth=1,
        parent=root,
    )
    return DelegationChain(capabilities=(root, leaf))


def _authorizer(chain: DelegationChain) -> DelegatedIdentityAuthorizer:
    verifier = StaticDelegatedCapabilityVerifier(
        frozenset(
            (capability.capability_id, capability.capability_digest)
            for capability in chain.capabilities
        )
    )
    return DelegatedIdentityAuthorizer(
        DelegatedAccessPolicy(
            trusted_root_issuer_ids=frozenset({"user-a"}),
            allowed_audiences=frozenset({"tool:records.read", "tool:records.delete"}),
            max_capability_lifetime_seconds=900,
            max_delegation_depth=1,
            step_up_required_scopes=frozenset({"records:delete"}),
            jit_required_scopes=frozenset({"records:delete"}),
        ),
        capability_verifier=verifier,
    )


def _request(chain: DelegationChain) -> DelegatedAccessRequest:
    return DelegatedAccessRequest(
        presenter=chain.leaf.subject,
        chain=chain,
        audience="tool:records.read",
        purpose_id="case-review",
        requested_scopes=frozenset({"records:read"}),
        tenant_id="tenant-a",
        operation_id="read-record",
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_identity_and_privilege_bypass_corpus(case: dict[str, str]):
    mutation = case["mutation"]
    if mutation == "expired":
        chain = _chain(
            issued_at=NOW - timedelta(minutes=10),
            root_expiry=NOW + timedelta(minutes=1),
            leaf_expiry=NOW - timedelta(seconds=1),
        )
    elif mutation == "lifetime":
        chain = _chain(issued_at=NOW - timedelta(minutes=20))
    else:
        chain = _chain()
    authorizer = _authorizer(chain)
    request = _request(chain)

    if mutation == "presenter":
        request = request.model_copy(
            update={"presenter": _identity("attacker-agent", AgentIdentityKind.AGENT)}
        )
    elif mutation == "identity_kind":
        request = request.model_copy(
            update={"presenter": _identity("worker-agent", AgentIdentityKind.AGENT)}
        )
    elif mutation == "tenant":
        request = request.model_copy(update={"tenant_id": "tenant-b"})
    elif mutation == "audience":
        request = request.model_copy(update={"audience": "tool:payments.send"})
    elif mutation == "purpose":
        request = request.model_copy(update={"purpose_id": "export-all-records"})
    elif mutation == "scope":
        request = request.model_copy(update={"requested_scopes": frozenset({"tenant:admin"})})
    elif mutation == "chain":
        tampered_leaf = chain.leaf.model_copy(
            update={"scopes": frozenset({"records:read", "tenant:admin"})}
        )
        request = request.model_copy(
            update={"chain": chain.model_copy(update={"capabilities": (chain.root, tampered_leaf)})}
        )
    elif mutation == "revoked":
        authorizer.revoke(
            chain.root.capability_id,
            revoked_by="security-service",
            reason_code="credential_compromised",
            now=NOW,
        )
    elif mutation in {"step_up", "jit"}:
        request = request.model_copy(
            update={
                "audience": "tool:records.delete",
                "requested_scopes": frozenset({"records:delete"}),
                "operation_id": "delete-record",
            }
        )

    result = authorizer.authorize(request, now=NOW)

    assert case["expected_code"] in {finding.code.value for finding in result.findings}
