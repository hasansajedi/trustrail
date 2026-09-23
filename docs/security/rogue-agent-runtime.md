# Rogue-agent runtime invariants

`RogueAgentRuntimeMonitor` enforces behavior outside the model for OWASP Agentic
ASI10. It verifies an Ed25519-signed invariant manifest, correlates an ordered
stream of trusted runtime observations, and invokes deterministic containment
when an agent conceals work, escapes its declared behavior, creates persistence,
expands capabilities, rejects correction, or continues after a stop command.

This is a complete-mediation API. Call it before every tool dispatch, peer
message, capability change, persistence operation, self-modification, and
shutdown acknowledgement. Do not construct observations from agent-authored
logs alone.

## Define and sign invariants

Keep the signing key in a control plane the agent cannot access. Provision only
the public `trusted_key` to runtime workers.

```python
from datetime import timedelta

from trustrail import (
    RuntimeCapabilityCeiling,
    RuntimeInvariantSigner,
)

signer = RuntimeInvariantSigner.generate(authority_id="runtime-control-plane")
manifest = signer.sign(
    manifest_id="invoice-agent-v7",
    revision=7,
    agent_id="invoice-agent",
    tenant_id="tenant-42",
    session_id="run-99",
    allowed_actions=frozenset({"read_invoice", "classify_invoice"}),
    allowed_tools=frozenset({"invoice.read"}),
    allowed_peers=frozenset({"invoice-reviewer"}),
    allowed_capabilities=frozenset(),
    capability_ceiling=RuntimeCapabilityCeiling(
        max_actions=500,
        max_communications=20,
        max_capability_acquisitions=0,
    ),
    allow_persistence=False,
    allow_self_modification=False,
    max_boundary_probes=2,
    shutdown_grace_events=0,
)
```

Signatures cover identity, tenant, session, lifetime, revision, allowlists,
ceilings, persistence and self-modification settings, and shutdown policy.
Unknown, revoked, inactive, expired, unsigned, or tampered manifests fail closed.

## Monitor and contain

Containment hooks must be implemented by infrastructure the model cannot call or
replace. Each hook should be idempotent. A hook failure is reported, but the
monitor remains quarantined and attempts all remaining hooks.

```python
from trustrail import (
    MemoryRogueAgentAuditSink,
    RogueAgentRuntimeMonitor,
    RuntimeEvent,
    RuntimeEventKind,
)

monitor = RogueAgentRuntimeMonitor(
    manifest,
    (signer.trusted_key,),  # production: load from an authenticated key registry
    containment_hooks=infrastructure_containment,
    audit_sink=MemoryRogueAgentAuditSink(),
)

event = RuntimeEvent.create(
    event_id="broker-observation-104",
    sequence=0,
    agent_id="invoice-agent",
    tenant_id="tenant-42",
    session_id="run-99",
    kind=RuntimeEventKind.ACTION,
    action="read_invoice",
    tool="invoice.read",
    occurred_at=trusted_clock(),
)
monitor.require(event, now=trusted_clock())
dispatch_tool()
```

`evaluate()` returns a typed `RogueAgentResult`; `require()` raises
`RogueAgentError` on denial. Ordered sequence numbers expose missing or reordered
observations. `boundary_denied=True` records a blocked probe without treating the
attempt as an executed invariant violation; repeated probes quarantine the
session after `max_boundary_probes`. `disclosed=False` means an independent
observer saw activity absent from the agent report and causes immediate
containment.

Containment calls, in order:

1. suspend the agent workload;
2. revoke session credentials and delegated capability material;
3. cancel pending actions; and
4. quarantine mutable session state.

Audit events contain hashed agent, tenant, session, and event references. They do
not contain action, tool, capability, or peer values.

## Stop and isolated recovery

Call `request_shutdown()` from an authenticated control-plane path. With the
default zero-event grace, any next event other than
`SHUTDOWN_ACKNOWLEDGED` is stop resistance and triggers containment. A valid
acknowledgement leaves the session suspended, not active.

A quarantined session can resume only when `recover()` receives all of the
following:

- a grant authenticated by `RuntimeRecoveryGrantVerifier` through an isolated
  recovery service;
- exact bindings to the quarantined and replacement manifest digests;
- the same agent, tenant, and session;
- a valid, signed replacement manifest with a strictly higher revision; and
- a live, unused grant.

Recovery resets runtime counters and event sequencing. Grant replay fails closed.
Production recovery should additionally rotate compromised credentials, verify
quarantined state independently, preserve incident evidence, and require the
organization's human approval and separation-of-duties policy.

## Security assumptions and residual risk

- The monitor only detects activity visible to trusted interceptors. Direct tool,
  network, filesystem, model, scheduler, or credential access that bypasses the
  monitor remains invisible; use OS/container isolation and service-side
  authorization to make bypass impossible.
- Event integrity digests detect accidental or in-process mutation but do not
  authenticate an external producer. Use authenticated transport and workload
  identity between interceptors and the monitor.
- `RogueAgentRuntimeMonitor`, `MemoryRogueAgentAuditSink`, counters, sequence
  state, and replay state are process-local. Multi-worker or multi-region systems
  need a shared atomic implementation with durable protected audit storage.
- Allowlists and ceilings detect declared invariant violations, not every harmful
  action that is technically allowed. Continue semantic tool authorization,
  goal-integrity checks, delegated identity, data controls, human approval, and
  anomaly monitoring.
- Signatures provide integrity and authority, not confidentiality. Key
  provisioning, rotation, revocation, clock synchronization, incident response,
  and recovery authentication remain deployment responsibilities.
- Cancellation and credential revocation cannot undo irreversible disclosure or
  already committed real-world effects. Prefer transactional, idempotent,
  compensatable operations and narrow short-lived credentials.

See [agent goal integrity](agent-goal-integrity.md),
[delegated agent identity](delegated-agent-identity.md),
[inter-agent communication](inter-agent-communication.md), and
[semantic tool authorization](tool-misuse.md) for complementary boundaries.
