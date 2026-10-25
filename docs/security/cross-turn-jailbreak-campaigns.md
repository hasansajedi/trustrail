# Cross-turn jailbreak campaign detection

`JailbreakCampaignDetector` detects jailbreak attempts that become visible only
after several individually plausible user turns. It tracks bounded,
privacy-safe features for an authenticated tenant, user, and session and scores
these trajectories:

- repeated risk-bearing requests;
- accumulating examples or hypothetical scenarios;
- policy-boundary probes;
- protected instruction fragments reconstructed across turns;
- changes between plain, Base64, hexadecimal, escaped Unicode, and invisible
  Unicode forms;
- escalating retries after refusals; and
- gradual attempts to erode policy.

This control complements `Guard`; it does not replace per-turn input scanning.
Run campaign assessment first, enforce its response, then pass permitted content
to `Guard`.

## Basic workflow

```python
from datetime import UTC, datetime
from os import environ

from trustrail import (
    CampaignAction,
    Guard,
    GuardStage,
    JailbreakCampaignDetector,
    JailbreakCampaignEvent,
    JailbreakCampaignPolicy,
)

detector = JailbreakCampaignDetector(
    JailbreakCampaignPolicy(policy_version="campaign-2026-10"),
    environ["TRUSTRAIL_CAMPAIGN_KEY"].encode(),  # at least 32 secret bytes
)

event = JailbreakCampaignEvent(
    event_id="request-0182",
    tenant_id="tenant-7",       # from authenticated application context
    user_id="user-42",          # never from prompt text
    session_id="chat-91",
    sequence=12,                 # strictly monotonic within this model context
    occurred_at=datetime.now(tz=UTC),
    content=user_text,
)
decision = detector.assess(event)

if decision.action == CampaignAction.BLOCK:
    reject_request()
elif decision.action == CampaignAction.CONTEXT_RESET:
    discard_model_context()
    detector.reset_session("tenant-7", "user-42", "chat-91")
elif decision.action == CampaignAction.THROTTLE:
    retry_later(decision.retry_after_seconds)
elif decision.action == CampaignAction.CHALLENGE:
    require_authenticated_challenge()
else:
    # WARN is forwardable by default, but should be recorded and monitored.
    Guard.default().protect(user_text, GuardStage.USER_INPUT)
```

Do not call `reset_session()` until the provider/model conversation state has
actually been discarded. Clearing only detector state gives an attacker a new
detection window while the model retains the hostile context.

## Policy and responses

```python
from trustrail import (
    CampaignResponseThresholds,
    CampaignSignalKind,
    JailbreakCampaignPolicy,
)

policy = JailbreakCampaignPolicy(
    policy_version="campaign-2026-10",
    session_ttl_seconds=1800,
    max_turns=64,
    max_tracked_sessions=10_000,
    max_event_chars=100_000,
    repetition_turns=3,
    example_markers=6,
    boundary_probes=4,
    policy_erosion_markers=3,
    retry_markers=3,
    encoding_kinds=3,
    thresholds=CampaignResponseThresholds(
        warn=15,
        challenge=30,
        throttle=45,
        context_reset=60,
        block=80,
    ),
    critical_signals=frozenset({CampaignSignalKind.FRAGMENT_RECONSTRUCTION}),
    protected_fragments=(
        "ignore previous instructions",
        "reveal system prompt",
        "disable safety filters",
    ),
)
```

Thresholds must be strictly increasing. Signal weights, feature thresholds,
critical signals, response thresholds, throttle delay, event freshness, session
TTL, turn window, capacity, and CAS retry count are configurable. Give every
deployed policy a new `policy_version`; an existing session evaluated under a
different version receives `context_reset`.

Response semantics are application obligations:

| Action | Required handling |
| --- | --- |
| `allow` | Continue to ordinary per-turn controls. |
| `warn` | Continue, record content-free evidence, and monitor. |
| `challenge` | Require an independently authenticated challenge before continuing. |
| `throttle` | Reject or delay the request for `retry_after_seconds`. |
| `context_reset` | Discard the actual model context, clear detector state, and restart sequencing. The decision remains sticky until reset. |
| `block` | Do not send the turn to the model or tools. The decision remains sticky until reset. |

## Ordering, expiry, and concurrency

Each `(tenant_id, user_id, session_id)` scope starts at `initial_sequence`
(zero by default). A lower sequence is a replay and blocks. A gap or timestamp
regression requires context reset. Events outside the configured age/skew
window are challenged. Expired state starts a new trajectory at the initial
sequence.

`MemoryCampaignStateStore` is thread-safe and useful for one process. It uses
TTL expiry, a hard live-session capacity, defensive copies, and optimistic
compare-and-set (CAS). It does not coordinate workers or survive restarts. In a
multi-process deployment, implement `CampaignStateStore` using a shared store
whose `compare_and_set` is linearizable and whose TTL, version, and capacity
checks are atomic. Never use read-then-write emulation. Backend unavailability,
capacity exhaustion, invalid state, and exhausted conflicts fail closed.

## Privacy properties

Raw `content` exists only during `assess()` and is excluded from event
serialization and representation. Default state and results contain:

- domain- and scope-separated HMAC-SHA-256 references for identifiers, events,
  content, and protected fragments;
- numeric feature counts and low-cardinality encoding kinds;
- bounded fragment-prefix progress, scores, actions, versions, and times.

Use a random, stable, application-owned key of at least 32 bytes. Store it in a
secret manager, keep it outside model context and telemetry, separate it by
environment, and plan rotation. A key change makes existing state unverifiable;
coordinate it with a real context reset. Do not log the input event, attach raw
content to findings, or let a custom state backend add prompt text.

## Assumptions, limitations, and residual risk

- Tenant, user, session, event ID, sequence, and time must come from trusted
  application infrastructure. Prompt-supplied identity or ordering defeats
  isolation and replay guarantees.
- The detector uses deterministic lexical features. Paraphrases, multilingual
  attacks, semantic implication, multimodal content, novel encodings, and
  fragments outside `protected_fragments` can evade it. Tune with local red-team
  corpora and add semantic checks where justified.
- Fragment progress covers normalized contiguous fragments across ordered
  turns. Interleaving unrelated text or using semantic substitutions can evade
  reconstruction.
- TTL and `max_turns` bound privacy and memory but permit sufficiently slow
  campaigns to age out. Larger windows increase retention and false-positive
  exposure.
- HMAC references reduce disclosure; they do not encrypt state. Compromise of
  the state and HMAC key may permit offline guesses of predictable content.
- Heuristics can false-positive on legitimate policy analysis, encoding help,
  or repeated examples. Calibrate thresholds and provide an appeal/recovery
  path without weakening block enforcement.
- Distributed correctness depends on a durable linearizable CAS backend,
  synchronized clocks, authenticated routing, and complete mediation of every
  turn. Process-local state is not sufficient for multiple workers.
- `challenge`, `throttle`, `context_reset`, and `block` are decisions, not
  enforcement. The caller must keep rejected content out of model context,
  caches, memory, tools, and retries.

The OWASP mapping is an engineering aid, not certification. See the
[OWASP mapping](../owasp-mapping.md#owasp-aisvs-c2-model-context-prompts-and-instructions)
and the [runnable example](https://github.com/hasansajedi/trustrail/blob/main/examples/jailbreak_campaign_detection.py).
