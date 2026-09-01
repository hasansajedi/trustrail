# Isolated agent code execution (OWASP ASI05:2026)

trustrail's dynamic-execution boundary addresses
[OWASP ASI05:2026 Unexpected Code Execution](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
and complements the
[OWASP Secure AI Model Ops Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_AI_Model_Ops_Cheat_Sheet.html).
Generated code is active untrusted input. Content scanning or human-readable
review alone does not turn it into a safe process, and running it in the
application worker can convert prompt injection into credential theft,
persistence, remote code execution, or cross-tenant compromise.

`CodeExecutionAuthorizer` is an admission and result-verification boundary. It
does not evaluate code, invoke a command, install a package, render a template,
or create an OS sandbox.

## Declare the exact runtime and isolation policy

Inventory an immutable interpreter or fixed native entrypoint by language,
version, executable digest, sandbox profile, and permitted artifact kinds. The
request must separately declare its filesystem paths, network endpoints,
environment variable names, package records, resource limits, and exit/output
conditions.

```python
from trustrail import (
    CodeExecutionPolicy,
    ExecutionArtifactKind,
    ExecutionLanguage,
    ExecutionResourceLimits,
    ExecutionRuntime,
    FilesystemPolicy,
    NetworkEndpoint,
    NetworkPolicy,
)

runtime = ExecutionRuntime(
    runtime_id="python-3.12-microvm",
    language=ExecutionLanguage.PYTHON,
    version="3.12.0",
    executable_digest=trusted_python_sha256,
    sandbox_profile_id="microvm-v3",
    allowed_artifact_kinds=frozenset(
        {ExecutionArtifactKind.CODE, ExecutionArtifactKind.SCRIPT}
    ),
)
policy = CodeExecutionPolicy(
    runtimes=(runtime,),
    allowed_artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
    filesystem=FilesystemPolicy(
        readable_prefixes=frozenset({"inputs"}),
        writable_prefixes=frozenset({"outputs"}),
        max_read_paths=2,
        max_write_paths=1,
    ),
    network=NetworkPolicy(
        allowed_endpoints=frozenset(
            {NetworkEndpoint(host="api.example.com", port=443)}
        )
    ),
    environment={"allowed_names": frozenset({"PUBLIC_CONFIG"})},
    max_resources=ExecutionResourceLimits(
        wall_time_ms=5_000,
        cpu_time_ms=2_000,
        memory_bytes=128 * 1024 * 1024,
        output_bytes=1_100_000,
        process_count=1,
        thread_count=4,
        file_count=16,
        written_bytes=1_000_000,
    ),
    allowed_python_imports=frozenset({"json", "math"}),
    trusted_sandbox_providers=frozenset({"production-sandbox"}),
)
```

An empty filesystem prefix set, network endpoint set, or environment-name set
means deny all. Paths are POSIX-relative to the sandbox root and cannot contain
absolute paths, parent traversal, or backslashes. Network endpoints are exact;
wildcards are rejected. Environment values are deliberately absent from the
request and must be resolved by the trusted broker after admission.

Package installation is disabled by default. Enabling it still requires every
`ExecutionPackage` to match an application-approved normalized name, exact
version, and SHA-256 digest. The sandbox broker must install from a trusted,
hash-verifying repository without dependency substitution. Treat the complete
transitive dependency closure as the package request and approved inventory, or
disable dependency resolution; an undeclared transitive install is a policy
bypass.

## Build an explicit request

Use `CodeExecutionRequest.create()` so the source digest is bound into the
request. Source content is excluded from normal Pydantic serialization and
representations; decisions and findings contain only identifiers, digests, and
content-free reason codes.

```python
from trustrail import (
    CodeExecutionRequest,
    ExecutionArtifactKind,
    ExecutionLanguage,
    FilesystemAccess,
    NetworkAccess,
)

request = CodeExecutionRequest.create(
    request_id="calculation-request",
    actor_id=authenticated_agent.identity_id,
    tenant_id=authenticated_agent.tenant_id,
    purpose_id="summarize-approved-input",
    operation_id="calculation-once",
    artifact_kind=ExecutionArtifactKind.CODE,
    language=ExecutionLanguage.PYTHON,
    runtime_id=runtime.runtime_id,
    source=generated_source,
    filesystem=FilesystemAccess(
        read_paths=("inputs/records.json",),
        write_paths=("outputs/summary.json",),
    ),
    network=NetworkAccess(),
    environment_names=frozenset({"PUBLIC_CONFIG"}),
)
```

There is no API that accepts a raw command string. Command requests use an
explicit argv tuple and a fixed runtime inventory entry. Shell runtimes are
always rejected, as are shell expansion and control syntax in arguments. Python
source is parsed as an AST: imports are denied unless explicitly allowlisted,
and host-access modules, dynamic evaluation, interpreter introspection, and
process-launch primitives are rejected. Other source languages and templates
require a configured `CodeInspector`; missing or failing inspection blocks the
request.

These checks reduce common bypasses but are not a language security proof. The
attested OS sandbox remains mandatory even for code that passes inspection.

## Require authenticated sandbox evidence

The broker must return a short-lived `SandboxAttestation` bound to the request
digest, tenant, runtime ID and executable digest, sandbox profile and instance,
and every required `SandboxControl`. Configure a
`SandboxAttestationVerifier` that checks the provider's signature or protected
issuance record.

```python
from trustrail import CodeExecutionAuthorizer

authorizer = CodeExecutionAuthorizer(
    policy,
    attestation_verifier=production_sandbox_broker,
    report_verifier=production_sandbox_broker,
    admission_hooks=(organization_policy_hook,),
    output_validator=application_output_validator,
)
authorization = authorizer.require(request, sandbox_attestation)
```

Missing, expired, long-lived, incomplete, rebound, replayed, or unverifiable
attestations fail closed. Admission hooks run against the exact request, runtime,
and attestation; a denial, exception, or timeout blocks execution. The returned
`AuthorizedCodeExecution` is short-lived and single-use. Dispatch the original
request and authorization only to the attested broker—never to a local
`eval`, `exec`, shell, template renderer, notebook kernel, or subprocess.

## Verify completion before using output

After the sandbox terminates, require an authenticated `CodeExecutionReport`
that binds the authorization, request, runtime, attestation, and sandbox
instance. It must report terminal status, exit code, actual resource usage,
stdout/stderr sizes and digests, and cleanup evidence.

```python
from trustrail import ExecutionOutput

raw_output = ExecutionOutput(
    stdout=broker_response.stdout,
    stderr=broker_response.stderr,
)
verified = authorizer.require_completion(
    authorization,
    broker_response.report,
    raw_output,
)
downstream_value = verified.stdout
```

Output is released only when:

- the report is authentic, integrity-valid, single-use, and bound to the lease;
- execution began before authorization expiry and did not time out;
- status, exit code, and stderr behavior satisfy the declared exit conditions;
- observed CPU, wall time, memory, processes, threads, files, writes, and output
  remain within the authorized ceilings;
- returned bytes match the report and pass UTF-8 or strict JSON structure checks
  when requested;
- the optional application output validator succeeds; and
- the authenticated report confirms sandbox destruction, process termination,
  workspace discard, network removal, and credential revocation.

Any failure returns `GuardAction.QUARANTINE`; the output is absent and the lease
is closed. Treat even verified bytes as untrusted for their next destination.
For example, scan text before an LLM prompt, validate JSON with a strict domain
schema, encode HTML, and authorize any proposed tool call independently.

## Security assumptions, limitations, and residual risk

- trustrail does not provide containers, microVMs, seccomp, namespaces, cgroups,
  a WebAssembly runtime, syscall filtering, network proxies, package mirrors,
  malware analysis, or hardware attestation. The broker must enforce those
  controls outside the application process.
- Attestation and report digests detect field mutation but are not signatures.
  Their verifiers must authenticate exact evidence using protected provider
  state or cryptographic verification. The static helpers are only for tests.
- Python AST checks are defense in depth, not proof of safety. Allowed libraries
  may expose file, network, native-code, deserialization, or resource-abuse paths.
  Non-Python inspectors have the same limitation. Keep privileges minimal and
  test the sandbox against escapes.
- Relative path and endpoint checks describe intended policy. Only the broker
  can prevent symlink, mount, DNS-rebinding, redirect, proxy, loopback, metadata
  service, and alternate-protocol bypasses at runtime.
- Environment names do not authenticate values or prevent a compromised broker
  from exposing extra credentials. Use workload identity, short-lived secrets,
  no host mounts, no ambient cloud credentials, and post-run revocation.
- Admission/replay state is process-local. Distributed workers need shared,
  atomic lease, attestation, and report consumption with equivalent fail-closed
  behavior and durable content-free audit events.
- A provider can forge usage or cleanup evidence unless its control plane and
  signing keys are trusted. Monitor independent infrastructure telemetry and
  destroy or quarantine instances when evidence is missing.
- Cleanup cannot reverse data already exfiltrated or external side effects.
  Deny network by default, use disposable tenants and credentials, and apply
  downstream authorization, rate, cost, and transaction limits.

See the runnable
[`isolated_code_execution.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/isolated_code_execution.py)
example and [destination-aware output handling](output-handling.md).
