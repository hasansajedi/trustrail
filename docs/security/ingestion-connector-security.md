# Ingestion connector admission and continuous verification

Loaders, parsers, OCR systems, crawlers, feeds, and synchronization jobs execute
inside the RAG data plane. Treating their output as ordinary trusted documents
lets a compromised package, changed parser, expanded credential, unexpected
source, or partial job silently poison every later chunk, embedding, index, and
answer. `IngestionConnectorGuard` makes those transitions explicit and
fail-closed.

This control complements, rather than replaces, [AI artifact
verification](supply-chain.md), [data/model poisoning](data-model-poisoning.md),
[RAG document protection](rag-security.md), and [secure vector
retrieval](vector-embedding-security.md).

## Enforced lifecycle

1. A publisher signs an `IngestionConnectorManifest` containing the exact
   artifact, dependency lock, parser, allowed sources, credential references,
   ordered transforms, schedule, network destinations, expected content types,
   granted scopes, sandbox controls, and per-sync limits.
2. An independent assessor signs `ConnectorAdmissionEvidence` for that exact
   manifest and configuration. Admission requires artifact integrity,
   dependency policy, sandboxing, least privilege, and source ownership
   evidence.
3. Immediately before every synchronization, the application supplies a fresh
   `ConnectorEffectiveState`. Any change to the connector, parser, credentials,
   transforms, schedule, network access, content types, scopes, or sandbox
   declaration prevents authorization.
4. Every emitted `ConnectorDocument` is checked against the short-lived sync
   authorization. A single unambiguous pinned parser, allowed source and content
   type, byte limit, and exact content digest are required.
5. The control plane signs `ConnectorDocumentProvenance`, binding document bytes
   to the connector, manifest, effective state, parser, source, and sync.
   `verify_downstream()` rechecks that binding immediately before indexing,
   retrieval, or model use.
6. `complete_sync()` consumes the authorization. Partial, failed, inconsistent,
   or replayed reports quarantine every recorded document and registered
   descendant. `quarantine_connector()` performs the same transitive response
   when external monitoring reports compromise.

All rejection findings contain stable codes and one-way connector references;
they do not include document content, credential references, source URIs, keys,
or raw connector identities.

## Manifest and admission configuration

```python
from datetime import UTC, datetime, timedelta

from trustrail import (
    ArtifactDigest,
    ConnectorArtifactIdentity,
    ConnectorConfiguration,
    ConnectorNetworkDestination,
    ConnectorParserIdentity,
    ConnectorSandboxControl,
    ConnectorSchedule,
    IngestionConnectorKind,
    IngestionConnectorSigner,
)

now = datetime.now(tz=UTC)
publisher = IngestionConnectorSigner.generate(authority_id="publisher")
assessor = IngestionConnectorSigner.generate(authority_id="assessor")

configuration = ConnectorConfiguration(
    artifact=ConnectorArtifactIdentity(
        artifact_id="docs-loader",
        publisher="knowledge-team",
        source_uri="https://packages.example.com/docs-loader.whl",
        revision="2.4.1",
        artifact_digest=ArtifactDigest.from_bytes(reviewed_wheel_bytes),
        dependency_lock_digest=reviewed_lock_sha256,
    ),
    parser=ConnectorParserIdentity(
        parser_id="markdown-parser",
        version="3.2.0",
        implementation_digest=parser_sha256,
        configuration_digest=parser_config_sha256,
    ),
    allowed_source_uris=frozenset({"https://docs.example.com/export"}),
    credential_references=frozenset({"vault:docs-read"}),
    schedule=ConnectorSchedule(schedule_id="hourly", interval_seconds=3600),
    network_destinations=(
        ConnectorNetworkDestination(scheme="https", host="docs.example.com"),
    ),
    expected_content_types=frozenset({"text/markdown"}),
    granted_scopes=frozenset({"documents:read"}),
    sandbox_controls=frozenset(ConnectorSandboxControl),
)
manifest = publisher.sign_manifest(
    manifest_id="docs-loader-2.4.1",
    connector_id="docs-production",
    kind=IngestionConnectorKind.DOCUMENT_LOADER,
    configuration=configuration,
    issued_at=now,
    expires_at=now + timedelta(hours=4),
)
evidence = assessor.sign_evidence(
    evidence_id="review-42",
    connector_id=manifest.connector_id,
    manifest_digest=manifest.manifest_digest,
    configuration=configuration,
    issued_at=now,
)
```

The complete offline workflow is runnable as
[`examples/ingestion_connector_security.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/ingestion_connector_security.py).

## Production integration

- Construct manifests and evidence in trusted control-plane services, not in
  connector code or from model output. Pin trusted Ed25519 public keys through a
  protected configuration channel.
- Build `ConnectorEffectiveState` from independently observed deployed state.
  Do not let the connector self-report the artifact digest, credentials,
  network policy, sandbox, parser, or scopes without verification.
- Call `authorize_sync()` before opening the source, and use only its returned
  authorization. Call `verify_document()` before persistence and use only the
  returned document with signed provenance.
- Register each downstream chunk, embedding, index entry, cache record, and
  derived artifact with `register_downstream_artifact()`. Unregistered outputs
  cannot be found during incident impact analysis.
- Call `complete_sync()` even for empty and failed jobs. Never publish output
  until it returns `ALLOW`; stage writes transactionally when the storage system
  supports it.
- Call `verify_downstream()` immediately before each sensitive use. Then apply
  `DataPoisoningVerifier`, tenant/vector authorization, content scanning, and
  RAG context controls to the returned document.
- Feed package revocation, vulnerability intelligence, source takeover,
  credential compromise, and parser incidents into `quarantine_connector()`.

`MemoryConnectorLineageStore` and active synchronization authorization state are
process-local. A multi-worker or multi-region deployment must route a sync to
one worker or provide a shared, durable, atomic `ConnectorLineageStore` and a
coordinated authorization lifecycle. Bound storage and impact-query sizes;
capacity or backend errors deliberately fail closed.

## Decision codes

Codes distinguish manifest/key/signature/freshness failures, incomplete or
stale evidence, unverified ownership, admission mismatch, effective-state
drift, disallowed source or schedule, invalid/expired/replayed authorization,
document limits, content type, parser ambiguity or substitution, digest
mismatch, missing/invalid provenance, partial or inconsistent completion,
unavailable lineage, and quarantined artifacts. Check the typed
`IngestionConnectorCode` enum instead of matching human-readable messages.

## Assumptions and limitations

- A valid signature authenticates bytes and signer identity; it does not prove
  that a publisher or assessor is competent or honest. Protect private keys,
  rotate/revoke them, separate publisher/assessor/control roles, and audit
  issuance.
- The library validates declared network, credential, scope, schedule, and
  sandbox state. The operating system, container platform, scheduler, secret
  broker, and egress proxy must enforce those declarations.
- Source ownership evidence must come from an authoritative validation process.
  An allowlisted URI alone does not prevent DNS, cloud-account, repository, or
  upstream-feed takeover.
- Exact hashes detect changed artifacts, dependencies, parsers, transforms, and
  content. They do not find vulnerabilities, malicious behavior, parser bugs,
  semantic poisoning, steganography, or factual errors. Continue vulnerability
  scanning, sandboxing, content analysis, anomaly detection, and human review.
- The schedule check validates that the request is within the configured skew;
  the application scheduler remains authoritative for cadence and duplicate-job
  prevention.
- Lineage is complete only when every derivative is registered. Already copied,
  exported, prompted, or acted-on data cannot be recalled by quarantine.
- A signed provenance record describes a verified boundary observation, not
  eternal truth. Reverify it at use time and combine it with current
  authorization, tenant isolation, retention/deletion, and incident state.
- Partial sync quarantine cannot undo non-transactional side effects. Prefer
  staging areas and atomic publication after a complete report.

## OWASP relationship

This control addresses the connector-specific supply-chain and ingestion
boundaries shared by OWASP LLM03 (Supply Chain), LLM04 (Data and Model
Poisoning), LLM08 (Vector and Embedding Weaknesses), and RAG pipeline guidance:
admit every ingestion component, continuously compare its effective state,
preserve parser/source provenance, and trace affected descendants. See the
[OWASP mapping](../owasp-mapping.md) for the exact coverage and remaining
controls.

The security regression corpus is
[`tests/security_corpus/ingestion_connectors.json`](https://github.com/hasansajedi/trustrail/blob/main/tests/security_corpus/ingestion_connectors.json).
Add every connector incident or bypass to that corpus and run the security
suite before deployment.
