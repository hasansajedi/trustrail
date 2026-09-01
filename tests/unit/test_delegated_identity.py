"""Unit tests for OWASP ASI03 delegated agent identity controls."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    AgentIdentity,
    AgentIdentityKind,
    DelegatedAccessCode,
    DelegatedAccessGrant,
    DelegatedAccessGrantKind,
    DelegatedAccessPolicy,
    DelegatedAccessRequest,
    DelegatedAccessResult,
    DelegatedCapability,
    DelegatedIdentityAuthorizer,
    DelegationChain,
    GuardAction,
    StaticDelegatedAccessGrantVerifier,
    StaticDelegatedCapabilityVerifier,
)

NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


def _identity(
    identity_id: str,
    kind: AgentIdentityKind,
    tenant_id: str = "tenant-a",
) -> AgentIdentity:
    return AgentIdentity(identity_id=identity_id, kind=kind, tenant_id=tenant_id)


def _chain(
    *,
    issued_at: datetime = NOW - timedelta(seconds=5),
    not_before: datetime = NOW - timedelta(seconds=5),
    root_expires_at: datetime = NOW + timedelta(minutes=10),
    leaf_expires_at: datetime = NOW + timedelta(minutes=5),
    child_scopes: frozenset[str] = frozenset({"documents:read", "documents:delete"}),
    child_audiences: frozenset[str] = frozenset({"tool:documents.read", "tool:documents.delete"}),
    child_purpose: str = "support-case-7",
) -> DelegationChain:
    human = _identity("user-7", AgentIdentityKind.HUMAN)
    agent = _identity("support-agent", AgentIdentityKind.AGENT)
    sub_agent = _identity("reader-agent", AgentIdentityKind.SUB_AGENT)
    root = DelegatedCapability.create(
        capability_id="cap-root",
        issuer=human,
        subject=agent,
        scopes=frozenset({"documents:read", "documents:delete"}),
        delegatable_scopes=frozenset({"documents:read", "documents:delete"}),
        audiences=frozenset({"tool:documents.read", "tool:documents.delete"}),
        purpose_id="support-case-7",
        issued_at=issued_at,
        not_before=not_before,
        expires_at=root_expires_at,
        delegation_depth=0,
        max_delegation_depth=2,
    )
    child = DelegatedCapability.create(
        capability_id="cap-child",
        issuer=agent,
        subject=sub_agent,
        scopes=child_scopes,
        audiences=child_audiences,
        purpose_id=child_purpose,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=leaf_expires_at,
        delegation_depth=1,
        max_delegation_depth=2,
        parent=root,
    )
    return DelegationChain(capabilities=(root, child))


def _policy(**updates: object) -> DelegatedAccessPolicy:
    policy = DelegatedAccessPolicy(
        trusted_root_issuer_ids=frozenset({"user-7", "identity-service"}),
        allowed_audiences=frozenset({"tool:documents.read", "tool:documents.delete"}),
        max_capability_lifetime_seconds=900,
        max_grant_lifetime_seconds=120,
        max_delegation_depth=2,
        authorization_ttl_seconds=60,
        step_up_required_scopes=frozenset({"documents:delete"}),
        jit_required_scopes=frozenset({"documents:delete"}),
        minimum_step_up_assurance=2,
    )
    return policy.model_copy(update=updates)


def _verifier(chain: DelegationChain) -> StaticDelegatedCapabilityVerifier:
    return StaticDelegatedCapabilityVerifier(
        frozenset(
            (capability.capability_id, capability.capability_digest)
            for capability in chain.capabilities
        )
    )


def _authorizer(
    chain: DelegationChain,
    *,
    policy: DelegatedAccessPolicy | None = None,
    grant_ids: frozenset[str] = frozenset(),
    revocation_provider: object | None = None,
) -> DelegatedIdentityAuthorizer:
    return DelegatedIdentityAuthorizer(
        policy or _policy(),
        capability_verifier=_verifier(chain),
        grant_verifier=StaticDelegatedAccessGrantVerifier(grant_ids),
        revocation_provider=revocation_provider,  # type: ignore[arg-type]
    )


def _request(
    chain: DelegationChain,
    *,
    scope: str = "documents:read",
    audience: str | None = None,
    purpose_id: str = "support-case-7",
    tenant_id: str = "tenant-a",
    operation_id: str = "read-document",
    presenter: AgentIdentity | None = None,
    grants: tuple[DelegatedAccessGrant, ...] = (),
) -> DelegatedAccessRequest:
    return DelegatedAccessRequest(
        presenter=presenter or chain.leaf.subject,
        chain=chain,
        audience=audience or f"tool:{scope.replace(':', '.')}",
        purpose_id=purpose_id,
        requested_scopes=frozenset({scope}),
        tenant_id=tenant_id,
        operation_id=operation_id,
        grants=grants,
    )


def _grant(
    request: DelegatedAccessRequest,
    kind: DelegatedAccessGrantKind,
    *,
    grant_id: str,
    assurance_level: int = 3,
    expires_at: datetime = NOW + timedelta(minutes=1),
) -> DelegatedAccessGrant:
    return DelegatedAccessGrant(
        grant_id=grant_id,
        kind=kind,
        request_digest=request.request_digest,
        subject_id=request.presenter.identity_id,
        tenant_id=request.tenant_id,
        approved_scopes=request.requested_scopes,
        assurance_level=assurance_level,
        issued_at=NOW - timedelta(seconds=1),
        expires_at=expires_at,
    )


def _codes(result: DelegatedAccessResult) -> set[DelegatedAccessCode]:
    return {finding.code for finding in result.findings}


def test_authorizes_identity_bound_short_lived_access_and_tool_principal():
    chain = _chain()
    authorizer = _authorizer(chain)
    request = _request(chain)

    result = authorizer.authorize(request, now=NOW)

    assert result.is_authorized
    assert result.authorization is not None
    assert result.authorization.actor_id == "reader-agent"
    assert result.authorization.initiator_id == "user-7"
    assert result.authorization.expires_at == NOW + timedelta(seconds=60)
    principal = authorizer.to_tool_principal(result.authorization, now=NOW)
    assert principal.actor_id == "reader-agent"
    assert principal.subject_id == "user-7"
    assert principal.scopes == frozenset({"documents:read"})


def test_fails_closed_without_capability_authenticity_verifier():
    chain = _chain()
    authorizer = DelegatedIdentityAuthorizer(_policy())

    result = authorizer.authorize(_request(chain), now=NOW)

    assert result.action == GuardAction.BLOCK
    assert DelegatedAccessCode.CAPABILITY_INVALID in _codes(result)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("presenter", DelegatedAccessCode.PRESENTER_MISMATCH),
        ("tenant", DelegatedAccessCode.TENANT_MISMATCH),
        ("audience", DelegatedAccessCode.AUDIENCE_DENIED),
        ("purpose", DelegatedAccessCode.PURPOSE_MISMATCH),
        ("scope", DelegatedAccessCode.SCOPE_DENIED),
    ],
)
def test_rejects_forwarding_confused_deputy_identity_and_scope_bypasses(
    mutation: str,
    expected_code: DelegatedAccessCode,
):
    chain = _chain()
    updates: dict[str, object] = {}
    if mutation == "presenter":
        updates["presenter"] = _identity("other-agent", AgentIdentityKind.AGENT)
    elif mutation == "tenant":
        updates["tenant_id"] = "tenant-b"
    elif mutation == "audience":
        updates["audience"] = "tool:payments.send"
    elif mutation == "purpose":
        updates["purpose_id"] = "unrelated-purpose"
    elif mutation == "scope":
        updates["scope"] = "documents:admin"

    result = _authorizer(chain).authorize(_request(chain, **updates), now=NOW)

    assert result.action == GuardAction.BLOCK
    assert expected_code in _codes(result)


@pytest.mark.parametrize(
    ("chain", "policy", "expected_code"),
    [
        (
            _chain(
                issued_at=NOW - timedelta(minutes=20),
                not_before=NOW - timedelta(minutes=20),
                root_expires_at=NOW - timedelta(minutes=1),
                leaf_expires_at=NOW - timedelta(minutes=2),
            ),
            _policy(max_capability_lifetime_seconds=2_000),
            DelegatedAccessCode.CAPABILITY_EXPIRED,
        ),
        (
            _chain(
                issued_at=NOW + timedelta(minutes=1),
                not_before=NOW + timedelta(minutes=1),
                root_expires_at=NOW + timedelta(minutes=10),
                leaf_expires_at=NOW + timedelta(minutes=5),
            ),
            _policy(),
            DelegatedAccessCode.CAPABILITY_NOT_YET_VALID,
        ),
        (
            _chain(
                issued_at=NOW - timedelta(minutes=20),
                not_before=NOW - timedelta(minutes=20),
                root_expires_at=NOW + timedelta(minutes=10),
                leaf_expires_at=NOW + timedelta(minutes=5),
            ),
            _policy(),
            DelegatedAccessCode.CAPABILITY_LIFETIME_EXCEEDED,
        ),
        (
            _chain(),
            _policy(max_delegation_depth=0),
            DelegatedAccessCode.DELEGATION_DEPTH_EXCEEDED,
        ),
    ],
)
def test_enforces_expiry_activation_lifetime_and_depth(
    chain: DelegationChain,
    policy: DelegatedAccessPolicy,
    expected_code: DelegatedAccessCode,
):
    result = _authorizer(chain, policy=policy).authorize(_request(chain), now=NOW)

    assert expected_code in _codes(result)


def test_rejects_integrity_tampering_even_when_model_copy_skips_validation():
    chain = _chain()
    tampered_leaf = chain.leaf.model_copy(
        update={"scopes": frozenset({"documents:read", "tenant:admin"})}
    )
    tampered_chain = chain.model_copy(update={"capabilities": (chain.root, tampered_leaf)})
    request = _request(chain).model_copy(update={"chain": tampered_chain})

    result = _authorizer(chain).authorize(request, now=NOW)

    assert DelegatedAccessCode.CHAIN_INTEGRITY_INVALID in _codes(result)
    assert DelegatedAccessCode.PRIVILEGE_AMPLIFICATION in _codes(result)


def test_empty_chain_model_copy_bypass_fails_closed():
    chain = _chain()
    empty_chain = chain.model_copy(update={"capabilities": ()})
    request = _request(chain).model_copy(update={"chain": empty_chain})

    result = _authorizer(chain).authorize(request, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert DelegatedAccessCode.CHAIN_INTEGRITY_INVALID in _codes(result)


def test_chain_model_rejects_scope_audience_purpose_and_expiry_amplification():
    root = _chain().root
    agent = root.subject
    sub_agent = _identity("reader-agent", AgentIdentityKind.SUB_AGENT)
    mutations = (
        {"scopes": frozenset({"tenant:admin"})},
        {"audiences": frozenset({"tool:payments.send"})},
        {"purpose_id": "other-purpose"},
        {"expires_at": root.expires_at + timedelta(seconds=1)},
        {"issued_at": root.issued_at - timedelta(seconds=1)},
    )
    for index, mutation in enumerate(mutations):
        child = DelegatedCapability.create(
            capability_id=f"child-{index}",
            issuer=agent,
            subject=sub_agent,
            scopes=mutation.get("scopes", frozenset({"documents:read"})),
            audiences=mutation.get("audiences", frozenset({"tool:documents.read"})),
            purpose_id=str(mutation.get("purpose_id", "support-case-7")),
            issued_at=mutation.get("issued_at", NOW - timedelta(seconds=5)),
            not_before=NOW - timedelta(seconds=5),
            expires_at=mutation.get("expires_at", NOW + timedelta(minutes=5)),
            delegation_depth=1,
            max_delegation_depth=2,
            parent=root,
        )
        with pytest.raises(ValidationError):
            DelegationChain(capabilities=(root, child))


def test_revoking_any_ancestor_invalidates_descendant_access():
    chain = _chain()
    authorizer = _authorizer(chain)
    assert authorizer.authorize(_request(chain), now=NOW).is_authorized

    revocation = authorizer.revoke(
        chain.root.capability_id,
        revoked_by="security-service",
        reason_code="session_terminated",
        now=NOW + timedelta(seconds=1),
    )
    result = authorizer.authorize(_request(chain), now=NOW + timedelta(seconds=1))

    assert revocation in authorizer.revocations
    assert DelegatedAccessCode.CAPABILITY_REVOKED in _codes(result)


def test_revocation_preserves_the_earliest_effective_time():
    chain = _chain()
    authorizer = _authorizer(chain)
    later = authorizer.revoke(
        chain.root.capability_id,
        revoked_by="security-service",
        reason_code="session_terminated",
        now=NOW + timedelta(seconds=10),
    )
    earlier = authorizer.revoke(
        chain.root.capability_id,
        revoked_by="security-service",
        reason_code="credential_compromised",
        now=NOW + timedelta(seconds=5),
    )
    repeated = authorizer.revoke(
        chain.root.capability_id,
        revoked_by="security-service",
        reason_code="late_retry",
        now=NOW + timedelta(seconds=20),
    )

    assert earlier.revoked_at < later.revoked_at
    assert repeated == earlier
    assert authorizer.revocations == (earlier,)


class FailingRevocationProvider:
    def is_revoked(self, capability_id: str, at: datetime) -> bool:
        raise TimeoutError(capability_id)


def test_fails_closed_when_shared_revocation_status_is_unavailable():
    chain = _chain()
    authorizer = _authorizer(chain, revocation_provider=FailingRevocationProvider())

    result = authorizer.authorize(_request(chain), now=NOW)

    assert DelegatedAccessCode.CAPABILITY_STATUS_UNAVAILABLE in _codes(result)


def test_requires_and_authenticates_step_up_and_jit_grants_for_high_impact_scope():
    chain = _chain()
    pending_request = _request(
        chain,
        scope="documents:delete",
        operation_id="delete-document",
    )
    authorizer = _authorizer(chain)
    pending = authorizer.authorize(pending_request, now=NOW)
    assert pending.action == GuardAction.REQUIRE_APPROVAL
    assert {
        DelegatedAccessCode.STEP_UP_REQUIRED,
        DelegatedAccessCode.JIT_ACCESS_REQUIRED,
    } == _codes(pending)

    step_up = _grant(
        pending_request,
        DelegatedAccessGrantKind.STEP_UP,
        grant_id="step-up-1",
    )
    jit = _grant(
        pending_request,
        DelegatedAccessGrantKind.JUST_IN_TIME,
        grant_id="jit-1",
    )
    approved_request = pending_request.model_copy(update={"grants": (step_up, jit)})
    authorizer = _authorizer(chain, grant_ids=frozenset({"step-up-1", "jit-1"}))

    allowed = authorizer.authorize(approved_request, now=NOW)
    replay = authorizer.authorize(approved_request, now=NOW)

    assert allowed.is_authorized
    assert DelegatedAccessCode.GRANT_REPLAYED in _codes(replay)


@pytest.mark.parametrize(
    "mutation",
    ["request", "subject", "scope", "over_scope", "assurance", "expiry"],
)
def test_rejects_rebound_under_scoped_or_expired_privilege_grants(mutation: str):
    chain = _chain()
    request = _request(chain, scope="documents:delete", operation_id="delete-document")
    step_up = _grant(
        request,
        DelegatedAccessGrantKind.STEP_UP,
        grant_id="step-up-1",
    )
    jit = _grant(
        request,
        DelegatedAccessGrantKind.JUST_IN_TIME,
        grant_id="jit-1",
    )
    if mutation == "request":
        step_up = step_up.model_copy(update={"request_digest": "0" * 64})
    elif mutation == "subject":
        step_up = step_up.model_copy(update={"subject_id": "other-agent"})
    elif mutation == "scope":
        jit = jit.model_copy(update={"approved_scopes": frozenset({"documents:read"})})
    elif mutation == "over_scope":
        jit = jit.model_copy(
            update={"approved_scopes": frozenset({"documents:delete", "tenant:admin"})}
        )
    elif mutation == "assurance":
        step_up = step_up.model_copy(update={"assurance_level": 1})
    elif mutation == "expiry":
        jit = jit.model_copy(update={"expires_at": NOW})
    approved = request.model_copy(update={"grants": (step_up, jit)})
    authorizer = _authorizer(chain, grant_ids=frozenset({"step-up-1", "jit-1"}))

    result = authorizer.authorize(approved, now=NOW)

    expected = (
        DelegatedAccessCode.GRANT_EXPIRED
        if mutation == "expiry"
        else DelegatedAccessCode.GRANT_INVALID
    )
    assert expected in _codes(result)


def test_concurrent_single_use_grant_authorizes_only_one_request():
    chain = _chain()
    request = _request(chain, scope="documents:delete", operation_id="delete-document")
    grants = (
        _grant(request, DelegatedAccessGrantKind.STEP_UP, grant_id="step-up-1"),
        _grant(request, DelegatedAccessGrantKind.JUST_IN_TIME, grant_id="jit-1"),
    )
    request = request.model_copy(update={"grants": grants})
    authorizer = _authorizer(chain, grant_ids=frozenset({"step-up-1", "jit-1"}))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: authorizer.authorize(request, now=NOW), range(2)))

    assert sum(result.is_authorized for result in results) == 1
    blocked = next(result for result in results if not result.is_authorized)
    assert DelegatedAccessCode.GRANT_REPLAYED in _codes(blocked)


def test_expired_authorization_cannot_be_converted_to_tool_principal():
    chain = _chain()
    authorizer = _authorizer(chain)
    authorization = authorizer.require(_request(chain), now=NOW)

    with pytest.raises(ValueError, match="expired"):
        authorizer.to_tool_principal(authorization, now=authorization.expires_at)
