# Step-up authentication and JIT AI privileges

`PrivilegedAccessManager` provides zero-standing-privilege activation for
high-risk AI platform actions. It implements application-layer controls for
OWASP AISVS 5.1.1 and 5.2.6 by requiring fresh step-up authentication, optional
independent approval, short-lived exact grants, and current backend authorization.

This control is for platform operations such as model deployment, weight export,
training-data access, training-pipeline modification, and production prompt,
safety-policy, or configuration changes. It complements delegated agent identity
and high-impact action previews; it does not replace them.

## Classify privileged operations

Every enabled privileged operation needs an explicit `PrivilegedOperationPolicy`.
An operation absent from the policy is denied. The rule declares exact scopes,
eligible roles, minimum authentication assurance, approver separation, maximum
session duration, evidence freshness, grant lifetime, and accepted risk.

```python
from trustrail import (
    AuthenticationAssurance,
    PrivilegedAccessPolicy,
    PrivilegedAIOperation,
    PrivilegedOperationPolicy,
)

policy = PrivilegedAccessPolicy(
    policy_id="production-ai-privileges",
    version=4,
    operations=(
        PrivilegedOperationPolicy(
            operation=PrivilegedAIOperation.MODEL_WEIGHT_EXPORT,
            required_scopes=frozenset({"models:weights:export"}),
            eligible_role_ids=frozenset({"model-security-admin"}),
            minimum_assurance=AuthenticationAssurance.PHISHING_RESISTANT,
            require_independent_approval=True,
            allowed_approver_ids=frozenset({"security-duty-manager"}),
            maximum_session_duration_seconds=900,
            maximum_step_up_age_seconds=120,
            maximum_grant_ttl_seconds=60,
            maximum_risk_score=20,
        ),
    ),
)
```

`AuthenticationAssurance` values are ordered application policy levels, not a
claim of conformance to a particular identity standard. Map authenticator and
identity-provider signals to them in a reviewed adapter.

## Integrate authoritative services

Configure the manager with trusted adapters for:

- `PrivilegedIdentityProvider`: current actor, tenant, session, identity version,
  roles, role version, activity, and session lifetime;
- `PrivilegedRiskProvider`: current session risk version, score, block state, and
  freshness;
- `BackendAuthorizationProvider`: authorization from the service that owns the
  exact target resource;
- `StepUpEvidenceVerifier`: authenticity of out-of-band authentication evidence;
- `PrivilegedApprovalVerifier`: authenticity of independent approval evidence;
- `PrivilegeGrantStateStore`: atomic grant registration, consumption, replay
  prevention, and revocation.

All providers fail closed on missing responses or exceptions. Use a shared,
durable `PrivilegeGrantStateStore` in multi-worker and multi-region deployments.
`MemoryPrivilegeGrantStateStore` is process-local and intended for development,
tests, or a single-worker deployment only.

## Bind the exact action

Construct `PrivilegedActionRequest` from authenticated server-side context. The
request digest binds actor, tenant, session, identity/role/risk versions,
operation, one-way target reference, purpose, exact scopes, policy ID/version/
digest, and nonce.

```python
from trustrail import PrivilegedActionRequest, PrivilegedActorContext

request = PrivilegedActionRequest(
    request_id="weight-export-42",
    actor=PrivilegedActorContext(
        actor_id="operator-17",
        tenant_id="tenant-a",
        session_id="session-42",
        identity_version="identity-v7",
        role_version="roles-v12",
        risk_version="risk-v3",
    ),
    operation=PrivilegedAIOperation.MODEL_WEIGHT_EXPORT,
    target_id="model-weights-42",
    purpose_id="incident-investigation",
    requested_scopes=frozenset({"models:weights:export"}),
    policy_id=policy.policy_id,
    policy_version=policy.version,
    policy_digest=policy.policy_digest,
    nonce="identity-service-nonce-8472",
)
```

The identity service must produce `StepUpAuthenticationEvidence` bound to
`request.request_digest`, the same actor, tenant, session, policy digest, and
nonce. When required, an independent approver supplies
`PrivilegedApprovalEvidence` with the same binding. The actor cannot approve their
own action.

## Issue and consume a JIT grant

Grant issuance and action execution are intentionally separate:

```python
grant = manager.require_grant(
    request,
    step_up=step_up_evidence,
    approval=approval_evidence,
)

# Rechecks identity, roles, session, risk, policy, and backend authorization,
# then atomically consumes the exact grant.
permit = manager.require_execution(request, grant)
```

Issuance queries current identity, risk, and backend authorization before storing
a narrow grant. Execution queries all three again and atomically consumes it.
Every grant is exact, short-lived, and single-use; a subsequent action requires a
new request nonce, step-up evidence, approval, and grant.

The returned `AuthorizedPrivilegedOperation` contains
`backend_authorization_revision`. Pass the permit to the authoritative backend and
require an atomic/conditional check that the revision is still current while the
operation executes. Do not merely check that a permit object exists.

## Revocation and failure behavior

The manager rejects or revokes access when identity, role, policy, risk, or
session versions change; a role becomes ineligible; risk rises; a session expires
or exceeds its maximum duration; the backend denies access; evidence is missing,
stale, forged, replayed, or rebound; an approver is not independent; or grant
state cannot be read atomically.

Call `revoke_session(session_id)` when an identity provider terminates a session.
Version comparisons automatically invalidate unused grants on subsequent access.
Distributed deployments should additionally push identity, role, policy, risk,
and session change events into their shared grant store for immediate revocation.

`PrivilegedAccessAuditEvent` contains one-way actor, tenant, target, request, and
grant references rather than raw identifiers.

## Security assumptions, limitations, and residual risk

- Authenticate users and workloads before constructing actor context. Client,
  prompt, model, tool, or header claims are selectors, not authorization evidence.
- Step-up and approval verifiers must validate signed or otherwise authenticated
  evidence from services outside the agent/model execution environment.
- Protect policy, provider configuration, trusted verifier roots, audit storage,
  and grant state. A compromised policy or identity authority can issue access.
- Completely mediate every privileged path, including consoles, CLIs, automation,
  background jobs, break-glass paths, and direct backend APIs.
- Backend services must reauthorize the exact actor, tenant, operation, target,
  scopes, and revision. Trustrail does not grant cloud IAM, database, model
  registry, training platform, or filesystem permissions itself.
- There is a time-of-check/time-of-use interval between authorization and action.
  Use short expiries, conditional backend revisions, transactions, and idempotency.
- Separation of IDs does not prove organizational independence or reviewer
  comprehension. Enforce approver eligibility, authentication, conflicts of
  interest, and secure non-spoofable review UX in the approval service.
- Risk scores and assurance mappings are only as reliable as their authoritative
  sources. Monitor anomalous issuance and execution and test failover behavior.
- Process-local state cannot prevent cross-worker replay. Shared atomic state and
  clock synchronization are required in distributed deployments.
- JIT access limits exposure but cannot undo an exported model, disclosed training
  data, deployed artifact, or completed configuration change. Apply encryption,
  egress controls, immutable audit, rollback, incident response, and data controls.
