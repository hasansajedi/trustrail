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

Validate with CLI:
```bash
trustrail validate-config guardrails.yaml
```

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
