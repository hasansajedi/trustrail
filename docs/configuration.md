# Configuration

## Guard Profiles

```python
Guard.default()  # block_at=80, warn_at=40, fail_mode=CLOSED
Guard.balanced()  # block_at=60, warn_at=30, fail_mode=CLOSED
Guard.strict()  # block_at=40, warn_at=20, fail_mode=CLOSED
Guard.from_profile("paranoid")  # block_at=20, warn_at=5
Guard.from_profile("permissive")  # block_at=95, warn_at=70, fail_mode=OPEN
```

## GuardConfig

```python
from trustrail import GuardConfig, FailMode, SensitiveDataMode

config = GuardConfig(
    fail_mode=FailMode.CLOSED,
    block_at=70,
    warn_at=35,
    max_text_length=50_000,
    timeout_seconds=5.0,
    provider_timeout_seconds=2.0,
    max_async_concurrency=8,
    audit_enabled=True,
    sensitive_data_mode=SensitiveDataMode.DEFAULT,
    strip_invisible_unicode=True,
    require_rag_context_labels=True,
    require_memory_write_approval=True,
    max_prompt_segments=64,
    prompt_boundary_window=512,
)

guard = Guard(config=config)
```

## Policy and rule controls

`GuardConfig` validates policy and rule IDs when `Guard` is constructed, so a
misspelled ID or unsupported `params` key raises `ConfigurationError` before any
request is scanned. The built-in policy IDs are `prompt_injection`,
`sensitive_data`, `supply_chain`, `output_safety`, `content_safety`, `resource`,
`rag`, `memory`, `tools`, and `agent`.

```python
from trustrail import (
    FailMode,
    Guard,
    GuardAction,
    GuardConfig,
    GuardPolicy,
    RuleCategory,
    RuleConfig,
    Severity,
)

guard = Guard(
    GuardConfig(
        policies={
            "resource": GuardPolicy(
                fail_mode=FailMode.CLOSED,
                default_action=GuardAction.BLOCK,
                params={"max_chars": 20_000, "max_tokens": 4_096},
                rules={
                    "RL-001": RuleConfig(
                        action=GuardAction.WARN,
                        severity_override=Severity.LOW,
                        threshold=0.8,
                        params={"max_bytes": 80_000},
                    )
                },
            )
        },
        # Global rule overrides have the highest precedence.
        rule_overrides={"RL-001": RuleConfig(action=GuardAction.BLOCK)},
        enabled_categories=[RuleCategory.RESOURCE, RuleCategory.PROMPT_INJECTION],
        disabled_categories=[RuleCategory.PROMPT_INJECTION],
    )
)
```

Configuration precedence is deterministic:

1. A policy must be enabled.
2. `enabled_categories`, when present, acts as an allowlist.
3. `disabled_categories` is applied next and always wins, including when the
   same category is allowlisted.
4. A policy `default_action` applies to its detected findings.
5. A policy-local `rules[rule_id]` override replaces explicitly supplied fields.
6. A global `rule_overrides[rule_id]` replaces explicitly supplied policy-rule
   fields and has the highest precedence.

Rule `enabled`, `action`, `severity_override`, `threshold`, and validated
rule-specific `params` are applied during evaluation. A confidence below
`threshold` is ignored. `REDACT` or `TRANSFORM` fails closed when a detector
cannot produce replacement text. Stateful rules are constructed once per
`Guard`, so session counters persist across calls; create separate guards when
independent state is required.

`timeout_seconds` bounds both `check()` and `acheck()`. A timeout returns
`BLOCK` in closed mode and an allowed `WARN` result in open mode, with a
content-free `SYS-001` finding. Python cannot forcibly stop arbitrary synchronous
rule code, so a timed-out custom rule may finish in its isolated daemon thread;
custom rules should still implement their own I/O deadlines and cancellation.

`provider_timeout_seconds` is the default per-call deadline for async rules and
external safety providers; `ProviderRegistration` and `AsyncRuleRegistration`
can override it for one check. `max_async_concurrency` bounds independent async
checks within each evaluation. The whole evaluation remains bounded by
`timeout_seconds`. See [external safety providers](integrations/external-safety-providers.md)
for ordering, cancellation, fail-mode, and synchronous-call behavior.

When `audit_include_metadata=False`, audit events omit request, session, user,
tenant, and tag fields. Finding summaries, timing, stage, action, score, and
input length remain available. Arbitrary `GuardContext.metadata` values are
never copied to audit events.

## Risk Scoring

- CRITICAL finding → score = 100 (always block)
- HIGH finding → +30
- MEDIUM finding → +15
- LOW finding → +5
- INFO finding → +0

Default thresholds: block_at=80, warn_at=40.

## YAML Config

```yaml
fail_mode: closed
block_at: 70
warn_at: 35
max_text_length: 100000
timeout_seconds: 10.0
provider_timeout_seconds: 5.0
max_async_concurrency: 4
audit_enabled: true
sensitive_data_mode: default
strip_invisible_unicode: true
require_rag_context_labels: true
require_memory_write_approval: true
max_prompt_segments: 64
prompt_boundary_window: 512
```

`sensitive_data_mode` accepts `default`, `redact`, `block`, or `allow`.
`default` preserves each detector's native action. Use `redact` to sanitize all
detected values or `block` for a strict no-disclosure boundary. `allow` still
emits content-free findings but deliberately returns the original value; reserve
it for an explicitly accepted trusted workflow. See
[Sensitive information disclosure](security/sensitive-data.md).

`require_rag_context_labels` is enabled by default. It rejects plain joined text
at `GuardStage.RAG_CONTEXT`; use `Guard.build_rag_context()` and
`Guard.protect_rag_context()` to preserve document provenance and trust labels.

`require_memory_write_approval` is also enabled by default. Persistent writes
return `REQUIRE_APPROVAL` and must pass through `Guard.authorize_memory_write()`.
Disabling it leaves injection and sensitive-data scanning enabled, but removes the
human approval gate.

`max_prompt_segments` limits work performed by the structured prompt scanner.
`prompt_boundary_window` controls how many trailing and leading characters are
checked on each side of a source boundary. Lower it for tightly bounded latency;
raise it only after testing representative workloads and bypass cases.

## Delegated agent identity policy

Agent identity and privilege lifecycle use a typed policy because trusted
issuance, authenticated presenters, revocation, and step-up/JIT grants are not
model content or text-rule configuration:

```python
from trustrail import DelegatedAccessPolicy, DelegatedIdentityAuthorizer

identity_authorizer = DelegatedIdentityAuthorizer(
    DelegatedAccessPolicy(
        trusted_root_issuer_ids=frozenset({"customer-identity-service"}),
        allowed_audiences=frozenset({"tool:orders.read", "tool:payments.send"}),
        max_capability_lifetime_seconds=300,
        max_grant_lifetime_seconds=120,
        max_delegation_depth=2,
        authorization_ttl_seconds=30,
        step_up_required_scopes=frozenset({"payments:send"}),
        jit_required_scopes=frozenset({"payments:send"}),
        minimum_step_up_assurance=3,
    ),
    capability_verifier=production_capability_verifier,
    grant_verifier=production_grant_verifier,
    revocation_provider=shared_revocation_provider,
)
```

The configured lifetimes are hard upper bounds; a capability or grant does not
become valid merely because it has not expired. Its exact issuance must also be
authenticated. See [delegated agent identity](security/delegated-agent-identity.md)
for delegation narrowing, elevation flow, revocation, and production assumptions.

## Resource consumption policy

Model and agent budgets use a typed policy because authenticated identities,
exact tokenizer counts, operation IDs, and concurrency state are not text-rule
configuration:

```python
from trustrail import ConsumptionBudgetPolicy, ResourceBudgetManager

resource_manager = ResourceBudgetManager(
    ConsumptionBudgetPolicy(
        max_input_chars=100_000,
        max_input_bytes=400_000,
        max_input_tokens=8_192,
        max_output_chars=100_000,
        max_output_bytes=400_000,
        max_output_tokens=4_096,
        max_nesting_depth=100,
        max_compressed_bytes=10_000_000,
        max_decompressed_bytes=50_000_000,
        max_decompression_ratio=100,
        max_concurrent_operations_per_principal=2,
        max_concurrent_operations_per_tenant=20,
        max_retries_per_operation=2,
        max_tool_actions_per_session=100,
        max_session_duration_seconds=300,
        max_session_tokens=100_000,
        request_window_seconds=60,
        max_requests_per_principal_window=60,
        max_requests_per_tenant_window=600,
        lease_timeout_seconds=30,
    )
)
```

Use the same manager for all requests in one process. Distributed deployments
must repeat these checks in an atomic shared gateway or budget service. See
[bounded resource consumption](security/resource-consumption.md) for the full
reservation, completion, decompression, audit, and cancellation flow.

## System prompt policy

System-prompt construction and output comparison use typed policies rather than
`GuardConfig` because they require application-owned templates and references:

```python
from trustrail import (
    SystemPromptLeakageDetector,
    SystemPromptLeakagePolicy,
    SystemPromptPolicy,
    SystemPromptValidator,
)

prompt_validator = SystemPromptValidator(
    SystemPromptPolicy(max_prompt_chars=16_000)
)
leakage_detector = SystemPromptLeakageDetector(
    SystemPromptLeakagePolicy(
        min_fragment_chars=32,
        fragment_words=8,
        max_fragments_per_prompt=512,
        detect_encoded_output=True,
        detect_structured_echo=True,
    )
)
```

The construction policy rejects personal, internal, security, authorization,
credential, and secret classifications by default. Keep those defaults unless a
documented risk decision demonstrates that the value is safe to expose; changing
a classification does not make prompt content confidential. See
[system prompt leakage](security/system-prompt-leakage.md).

## Vector retrieval policy

Vector authorization uses a typed policy because authenticated identity,
resource grants, approved indexes, and trusted embeddings are application-owned
state rather than text guard configuration:

```python
from trustrail import SecureVectorWorkflow, VectorRetrievalPolicy

vector_workflow = SecureVectorWorkflow(
    VectorRetrievalPolicy(
        allowed_index_ids=frozenset({"support-index-v3"}),
        allowed_embedding_model_ids=frozenset({"embed-reviewed-v2"}),
        max_hits=10,
        max_catalog_entries=1_000,
        max_embedding_dimensions=3_072,
        similarity_tolerance=1e-5,
        max_identical_content_hits=1,
        require_sequential_ranks=True,
    )
)
```

Allowlists are required and empty policies are invalid. Tighten hit, dimension,
duplicate, and tolerance limits for the deployed embedding model and vector
store. See [vector and embedding security](security/vector-embedding-security.md)
for the full request/catalog flow and residual risks.

## Evidence grounding policy

Grounding uses a typed policy because trusted assessors, reviewers, evidence,
and impact classifications are application-owned state:

```python
from trustrail import EvidenceGroundingVerifier, GroundingPolicy, TrustLevel

grounding_verifier = EvidenceGroundingVerifier(
    GroundingPolicy(
        trusted_assessor_ids=frozenset({"fact-checker-v3"}),
        trusted_reviewer_ids=frozenset({"medical-review", "risk-review"}),
        minimum_evidence_trust=TrustLevel.SEMI_TRUSTED,
        max_evidence_age_seconds=2_592_000,
        minimum_support_confidence=0.8,
        contradiction_threshold=0.6,
        uncertainty_disclosure_threshold=0.8,
        minimum_high_impact_sources=2,
        require_citations=True,
        max_output_chars=100_000,
        max_claims=100,
        max_evidence_items=200,
    )
)
```

Assessor and reviewer allowlists are required. Tune thresholds against
domain-specific calibration data, not a model's claimed confidence. The default
high-impact set covers medical, legal, financial, security, safety, employment,
and explicitly classified high-impact claims. See
[misinformation and unsafe overreliance](security/misinformation-overreliance.md).

Validate with CLI:
```bash
trustrail validate-config guardrails.yaml
```

## Least-privilege tool authorization policy

Tool authorization is configured separately from text scanning because it must
run with authenticated application state immediately before execution:

```python
from trustrail import (
    ToolArgumentConstraint,
    ToolArgumentKind,
    ToolAuthorizationPolicy,
    ToolCapability,
    ToolEffect,
)

tool_policy = ToolAuthorizationPolicy(
    capabilities=(
        ToolCapability(
            name="documents.read",
            version="2026-08-01",
            effects=frozenset({ToolEffect.READ}),
            required_scopes=frozenset({"documents:read"}),
            arguments={
                "document_id": ToolArgumentConstraint(
                    kind=ToolArgumentKind.STRING,
                    pattern=r"doc-[a-z0-9]{8}",
                )
            },
            required_arguments=frozenset({"document_id"}),
            resource_id_argument="document_id",
            require_owned_resource=True,
            allow_autonomous=True,
        ),
    ),
    max_tool_calls=20,
    max_chain_actions=5,
    max_retries_per_operation=1,
    max_parallel_calls=2,
    max_autonomous_actions=5,
)
```

Capabilities default to denying autonomous use and cannot delegate any scope
unless explicitly configured. Delete, external-communication, and
permission-change effects require authenticated approval by default. See
[Excessive agency](security/excessive-agency.md) for request construction,
approval handling, and security assumptions.

For calls whose meaning or observed side effects matter, attach a separate
semantic policy. This example requires the proposed document identifier to match
a trusted user selection and requires the adapter to attest retrieval:

```python
from trustrail import (
    ToolArgumentBinding,
    ToolAuthorizer,
    ToolPostconditionPolicy,
    ToolPreconditionPolicy,
    ToolSemanticAuthorizationPolicy,
    ToolSemanticOperationPolicy,
)

semantic_tool_policy = ToolSemanticAuthorizationPolicy(
    operations=(
        ToolSemanticOperationPolicy(
            tool_name="documents.read",
            preconditions=ToolPreconditionPolicy(
                expected_facts={"account_active": True},
                argument_bindings=(
                    ToolArgumentBinding(
                        argument="document_id",
                        trusted_fact="selected_document_id",
                    ),
                ),
            ),
            postconditions=ToolPostconditionPolicy(
                expected_facts={"retrieved": True},
            ),
        ),
    ),
)
authorizer = ToolAuthorizer(
    tool_policy,
    semantic_policy=semantic_tool_policy,
    compensator=production_compensator,
)
```

The semantic policy must cover every capability in `tool_policy`; operation and
argument names are checked when the authorizer is created. Construct runtime `ToolSemanticContext` and
`ToolExecutionReport` records from trusted application state. See
[semantic tool authorization](security/tool-misuse.md) for sequence and data-flow
rules, post-execution verification, compensation, and residual risk.

## Agent goal-integrity policy

Goal integrity is configured separately from text scanning because the manifest,
identity, approval context, execution state, and plan sequence must come from
trusted orchestration code:

```python
from trustrail import GoalIntegrityGuard, GoalIntegrityPolicy

goal_guard = GoalIntegrityGuard(
    GoalIntegrityPolicy(
        max_steps_per_execution=100,
        max_mutations_per_execution=3,
        max_step_chars=10_000,
        max_drift_history_chars=50_000,
        require_all_constraint_bindings=True,
        detect_encoded_hijacking=True,
        detect_split_hijacking=True,
    ),
    approval_verifier=production_goal_approval_verifier,
    audit_sink=production_goal_audit_sink,
)
```

Keep one application-owned `GoalExecutionState` for the full execution. Lower
limits to the smallest values supported by the workflow, and retain exact
constraint binding unless an application-specific design documents why partial
binding is safe. See [agent goal integrity](security/agent-goal-integrity.md).

## Destination-aware output policy

`OutputHandlingPolicy` is separate from `GuardConfig` because it describes where
an already-scanned model value will be used:

```python
from pathlib import Path

from trustrail import OutputHandlingPolicy, SafeOutputHandler

output_handler = SafeOutputHandler(
    OutputHandlingPolicy(
        max_output_chars=50_000,
        allowed_url_schemes=frozenset({"https"}),
        allowed_url_hosts=frozenset({"docs.example.com"}),
        allow_relative_urls=False,
        allow_markdown_links=True,
        allow_markdown_images=False,
        path_root=Path("/srv/app/generated"),
        max_structured_depth=12,
        max_structured_nodes=5_000,
        allow_code_for_review=False,
    )
)
```

Empty URL allowlists and missing path roots fail closed. Enabling `allow_code_for_review`
returns `REQUIRE_APPROVAL`; it does not enable code execution.

## AI artifact verification policy

Supply-chain verification is configured separately from text guardrails because
it runs before a model, dataset, prompt, adapter, plugin, package, service, or
retrieved artifact is loaded:

```python
from trustrail import ArtifactVerificationPolicy, TrustLevel

artifact_policy = ArtifactVerificationPolicy(
    minimum_trust=TrustLevel.TRUSTED,
    require_approval=True,
    require_pinned_revision=True,
    reject_deprecated=True,
    require_license=True,
    allowed_suppliers=frozenset({"internal-ml", "reviewed-provider"}),
)
```

File-backed artifact kinds require SHA-256, SHA-384, or SHA-512 integrity
evidence by default. External services use exact supplier, endpoint, and API
revision metadata because there are no local bytes to hash. See
[Supply-chain security](security/supply-chain.md) for manifest and verification
examples.

## Data poisoning policy

Configure ingestion separately because it runs before data reaches a training
job, index, prompt, persistent store, or model loader:

```python
from trustrail import (
    DataAssetKind,
    DataPoisoningPolicy,
    DataPoisoningVerifier,
    DataSourcePolicy,
    TrustLevel,
)

poisoning_policy = DataPoisoningPolicy(
    sources=(
        DataSourcePolicy(
            source_id="knowledge-export",
            source_uri="https://content.example.com/export",
            allowed_kinds=frozenset({DataAssetKind.RAG_DOCUMENT}),
            trust_level=TrustLevel.SEMI_TRUSTED,
            authorized_writers=frozenset({"ingestion-service"}),
            allowed_tenants=frozenset({"tenant-a"}),
            allowed_purposes=frozenset({"rag-index"}),
            allowed_versions=frozenset({"snapshot-8f71c2"}),
        ),
    ),
    anomaly_threshold=0.8,
    max_scan_chars=100_000,
    max_metadata_depth=8,
    max_metadata_nodes=1_000,
)
poisoning_verifier = DataPoisoningVerifier(poisoning_policy)
```

Training data, fine-tuning data, and model artifacts require a separately trusted
expected digest by default. See
[Data and model poisoning](security/data-model-poisoning.md) for complete RAG,
memory, model, lineage, and custom detector examples.
