# Core concepts

trustrail separates content detection from security enforcement. `Guard` scans
and transforms content at model boundaries. The specialized APIs in the
[feature catalog](features.md) authorize identities, tools, resources,
credentials, approvals, persistent state, workflows, and MCP requests.

## Guard stages

Every value is checked in the context of where it came from or where it is
going. `GuardStage` selects the relevant rules and prevents one generic scan
from being treated as protection for every boundary.

| Stage | Typical value | Important checks |
| --- | --- | --- |
| `USER_INPUT` | Authenticated user's message | Direct injection, jailbreaks, secrets, PII, resource limits |
| `SYSTEM_PROMPT` | Application-composed instructions | Sensitive configuration, prompt boundaries, authorization data, leakage risk |
| `RAG_DOCUMENT` | One retrieved or ingested document | Indirect injection, poisoning markers, provenance, metadata bounds |
| `RAG_CONTEXT` | Assembled context envelope | Integrity of source and trust labels plus cross-document attacks |
| `TOOL_REQUEST` | Model-proposed tool name and arguments | Tool policy, URLs, secrets, argument and resource authorization |
| `TOOL_RESPONSE` | Data returned by a tool or MCP server | Indirect injection, sensitive data, provenance, destination handling |
| `LLM_RESPONSE` | Model-generated response | Unsafe content, sensitive data, prompt leakage, destination-specific injection |
| `MEMORY_WRITE` | Candidate persistent memory | Sensitive data, approval classification, provenance and taint controls |

Use the enum instead of free-form strings:

```python
from trustrail import Guard, GuardStage

guard = Guard.balanced()
result = guard.check(untrusted_document, GuardStage.RAG_DOCUMENT)
```

## Decisions and safe values

`Guard.check()` returns a `GuardResult` containing:

- `action`: an explicit `GuardAction` such as `ALLOW`, `WARN`, `REDACT`,
  `TRANSFORM`, `REQUIRE_APPROVAL`, `QUARANTINE`, `RETRY`, or `BLOCK`;
- `score`: the aggregate `RiskScore`;
- `findings`: typed, content-minimizing reasons; and
- `output_value`: the original value or its normalized/redacted transformation
  that may be forwarded when the decision permits it.

`Guard.protect()` is the fail-closed convenience API. It returns only the safe
value and raises `GuardrailBlockedError` or `ApprovalRequiredError` otherwise.
Never scan one value and then forward the original:

```python
safe_input = guard.protect(user_input, GuardStage.USER_INPUT)
response = model.generate(safe_input)
```

Specialized controls follow the same rule. Execute `AuthorizedToolCall`,
`AuthorizedHighImpactPlan`, `AuthorizedMCPOAuthRequest`, or another returned
authorization snapshot—not the earlier mutable proposal.

## Risk scoring

The default content-risk score is deterministic:

- `CRITICAL` produces a score of 100 and always blocks;
- each `HIGH` finding adds 30;
- each `MEDIUM` finding adds 15; and
- each `LOW` finding adds 5.

Default thresholds are `warn_at=40` and `block_at=80`. A policy may also assign
an explicit action, so callers should use `result.action` instead of deriving a
decision from the score themselves.

## Detection versus enforcement

A detector reports risk; an enforcement boundary controls an effect. For
example:

- an output rule can detect shell syntax, while `SafeOutputHandler` enforces the
  shell boundary;
- a credential detector can find a token, while `CredentialBroker` prevents the
  model from receiving the token in the first place;
- an MCP OAuth token can authorize a call, while the downstream service still
  authorizes the requested account and operation; and
- a human approval can bind an exact plan, while the executor and downstream
  system still enforce identity, limits, idempotency, and transaction rules.

Use defense in depth, but do not describe a detection result as proof that an
operation is authorized or safe.

## Trusted context

Security context must come from authenticated server-side state. Tenant IDs,
user IDs, subjects, ownership, scopes, approval records, policy versions,
resource identities, and signing keys must not be copied from prompt text,
retrieved documents, or model output.

`GuardContext` supplies trusted context to content rules. Specialized APIs use
typed request/context models and compare them against signed records, pinned
policy, external verifiers, or authoritative state.

## Fail modes

- `FailMode.CLOSED` blocks when a provider or state dependency fails. This is
  the default and appropriate for authorization and high-risk boundaries.
- `FailMode.OPEN` allows with a warning when the dependency fails. Use it only
  for an explicitly reviewed low-risk availability tradeoff.

Many security-critical APIs are unconditionally fail-closed and intentionally
do not offer an open mode.

## Replay and shared state

Single-use tokens, approvals, capabilities, workflow resumes, and ordered
messages require atomic claim state. In-memory stores are bounded and useful for
tests or one-process deployments. Multiple workers or regions need a shared,
durable implementation whose check-and-claim operation is atomic.

## Content-free evidence

Findings and audit events prefer stable codes, counts, classifications, digests,
and one-way references over raw prompts, secrets, identifiers, or outputs. This
reduces exposure but does not make telemetry harmless: protect audit access,
retention, transport, and correlation data as security-sensitive information.

## What trustrail does not replace

The library does not replace authentication, TLS, KMS/HSM-backed key custody,
vaults, network egress controls, sandbox/container isolation, database row-level
authorization, transactions, rate limiting at the edge, monitoring, or incident
response. Each security guide states the external controls and residual risks
for its API.
