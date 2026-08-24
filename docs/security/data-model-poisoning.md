# Data and model poisoning

Data and model poisoning is an integrity attack. Manipulated training snapshots,
fine-tuning examples, RAG documents, metadata, persistent memory, or model files
can bias behavior, add hidden triggers, or preserve an attack across sessions.

trustrail provides two complementary boundaries:

- `DataPoisoningVerifier` validates data provenance, authorization, integrity,
  transformation lineage, anomaly signals, and suspicious instructions before an
  asset is indexed, stored, trained on, or loaded.
- `Guard` scans text again at its runtime stage and applies structured RAG and
  persistent-memory controls.

Use both boundaries. Passing ingestion verification does not make content a
trusted instruction.

## Configure trusted sources

Source policy must come from application-controlled configuration, not from the
payload, model output, document metadata, or writer request.

```python
from trustrail import (
    DataAssetKind,
    DataPoisoningPolicy,
    DataPoisoningVerifier,
    DataSourcePolicy,
    TrustLevel,
)

policy = DataPoisoningPolicy(
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
)
verifier = DataPoisoningVerifier(policy)
```

Exact comparisons are intentional. Source URI lookalikes, writer case changes,
tenant suffixes, and unapproved versions fail closed. If `allowed_versions` is
omitted, mutable references such as `latest`, `main`, ranges, and wildcards are
rejected by default.

## Verify RAG data before indexing

Create the record at the first trusted ingestion boundary. `from_content()`
captures a SHA-256 digest of the exact bytes seen there.

```python
from trustrail import (
    DataAssetKind,
    DataIngestionRecord,
    DataProvenance,
    Document,
    Guard,
    IngestionAuthorization,
    TrustLevel,
)

record = DataIngestionRecord.from_content(
    item_id="document-42",
    kind=DataAssetKind.RAG_DOCUMENT,
    content=retrieved_text,
    provenance=DataProvenance(
        source_id="knowledge-export",
        source_uri="https://content.example.com/export",
        version="snapshot-8f71c2",
        trust_level=TrustLevel.SEMI_TRUSTED,
    ),
    authorization=IngestionAuthorization(
        writer_id="ingestion-service",
        tenant_id="tenant-a",
        purpose="rag-index",
    ),
    metadata=parser_metadata,
    anomaly_score=upstream_anomaly_score,
)

accepted = verifier.require(record)  # raises before indexing when quarantined
assert isinstance(accepted.content, str)

document = Document(
    id=accepted.item_id,
    content=accepted.content,
    source=accepted.provenance.source_id,
    source_url=accepted.provenance.source_uri,
    trust_level=accepted.provenance.trust_level,
)
envelope = Guard.strict().build_rag_context([document])
```

`verify()` returns a content-free `DataPoisoningResult` when an application needs
to route quarantined assets for review. The result identifies `item_id` and
`source_id`, but findings do not copy content, metadata values, URLs, writer IDs,
or tenant IDs.

## Link transformations

For extraction, parsing, filtering, labeling, or chunking jobs, attach an
integrity-linked transformation history:

```python
from trustrail import ArtifactDigest, DataTransformation

transformation = DataTransformation(
    name="html-to-text",
    version="2.4.1",
    actor_id="parser-service",
    input_digest=ArtifactDigest.from_bytes(raw_html),
    output_digest=ArtifactDigest.from_bytes(extracted_text.encode()),
)
```

Put this entry in `DataProvenance(transformations=(transformation,))`. Adjacent
transformations must link output-to-input, and the final output must match the
record digest. This detects accidental gaps or changed intermediate outputs; it
does not prove that a compromised transformer produced honest content.

## Pin training data and model artifacts

Training data, fine-tuning data, and model artifacts require a digest from the
trusted policy by default. The digest must arrive through a control-plane channel
separate from the bytes being checked.

```python
from trustrail import ArtifactDigest, DataPoisoningPolicy

policy = DataPoisoningPolicy(
    sources=trusted_sources,
    expected_digests={
        "fine-tune-2026-08": ArtifactDigest.from_bytes(approved_snapshot_bytes),
        "model-release-17": ArtifactDigest.from_bytes(approved_model_bytes),
    },
)
```

Use `ArtifactVerifier` as well when supplier approval, license inventory,
revocation, package provenance, or manifest fingerprint controls are required.
Do not deserialize untrusted pickle-like model formats merely to inspect them;
verify bytes first and load them in a restricted environment.

## Protect persistent memory

Poisoning authorization and human approval solve different problems. Verify the
writer, tenant, purpose, source, version, and content before calling the existing
memory approval workflow:

```python
accepted = memory_poisoning_verifier.require(memory_record)
assert isinstance(accepted.content, str)
safe_value = await guard.authorize_memory_write(accepted.content)
await memory_backend.set(memory_key, safe_value)
```

Bind the memory key and authenticated owner in application state. Never accept a
writer ID, tenant ID, trust label, approval, or persistence flag from model output.
Re-scan memory on read, expire stale values, and support user inspection,
correction, and deletion.

## Add an anomaly detector

Statistical and domain-specific detection belongs close to the data. A detector
hook receives the record and returns only a severity, so its finding cannot echo
the payload:

```python
from trustrail import DataIngestionRecord, Severity


class DistributionShiftDetector:
    detector_id = "distribution-shift-v3"

    def detect(self, record: DataIngestionRecord) -> Severity | None:
        score = score_against_baseline(record.content)
        return Severity.HIGH if score >= 0.9 else None


verifier = DataPoisoningVerifier(policy, detectors=(DistributionShiftDetector(),))
```

Detector failures are quarantined. Keep detector identifiers non-sensitive and
send detailed diagnostics to a separate access-controlled monitoring system.

## Detection and containment behavior

The verifier quarantines:

- unknown or substituted source locations;
- disallowed asset kinds, trust labels, versions, writers, tenants, or purposes;
- content that changed after digest capture;
- missing or mismatched control-plane digests for training/model assets;
- broken transformation chains;
- direct, invisible-Unicode, and base64-obfuscated model instructions;
- suspicious nested metadata or metadata exceeding configured scan bounds;
- upstream anomaly scores at or above the configured threshold; and
- custom detector signals or detector failures.

Quarantine means the application must keep the asset out of training jobs,
indexes, prompts, memory stores, and model loaders. Store quarantined content only
in a restricted review system with retention limits.

## Assumptions, limitations, and residual risk

- Provenance and authorization fields are claims until the application binds
  them to authenticated control-plane state. trustrail performs exact policy
  comparison; it does not authenticate network peers or issue identities.
- A digest proves byte equality, not safety or factual correctness. A malicious
  asset can be correctly hashed and approved.
- Pattern scanning is heuristic and cannot detect every semantic instruction,
  bias, sleeper trigger, label error, coordinated contributor attack, or subtle
  distribution shift. It can also flag legitimate security documentation.
- An anomaly score is only as reliable as its upstream detector and baseline.
  Monitor drift, calibrate thresholds, and retain independent evaluation sets.
- Nested metadata is scanned at verification time. Do not mutate a record's
  contained dictionaries afterward; rebuild and re-verify the record instead.
- Transformation links detect integrity gaps but do not attest transformer code.
  Pin and verify the transformer through supply-chain controls.
- Model behavior must still be evaluated with held-out, adversarial, bias, and
  backdoor-trigger tests. Run red-team campaigns and monitor training loss and
  production behavior.
- Keep tenant-isolated indexes, least-privilege storage, restricted network
  egress, dataset version control, rollback, quarantine, and index rebuild
  procedures outside the library.

These controls implement important mitigations from
[OWASP LLM04:2025 Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/),
but they are not proof that a dataset or model is poison-free.
