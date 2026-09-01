"""Admit generated code only for an attested sandbox and verify its result."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    CodeExecutionAuthorizer,
    CodeExecutionPolicy,
    CodeExecutionReport,
    CodeExecutionRequest,
    CodeExecutionStatus,
    ExecutionArtifactKind,
    ExecutionCleanupEvidence,
    ExecutionLanguage,
    ExecutionOutput,
    ExecutionResourceUsage,
    ExecutionRuntime,
    SandboxAttestation,
    SandboxControl,
)


class LocalEvidenceVerifier:
    """Example-only store standing in for an authenticated sandbox provider."""

    def __init__(self) -> None:
        self.attestations: set[tuple[str, str]] = set()
        self.reports: set[tuple[str, str]] = set()

    def verify_attestation(self, attestation: SandboxAttestation) -> bool:
        return (
            attestation.attestation_id,
            attestation.attestation_digest,
        ) in self.attestations

    def verify_report(self, report: CodeExecutionReport) -> bool:
        return (report.report_id, report.report_digest) in self.reports


now = datetime.now(tz=UTC)
runtime = ExecutionRuntime(
    runtime_id="python-3.12-microvm",
    language=ExecutionLanguage.PYTHON,
    version="3.12.0",
    executable_digest="a" * 64,
    sandbox_profile_id="microvm-v3",
    allowed_artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
)
request = CodeExecutionRequest.create(
    request_id="calculation-request",
    actor_id="analysis-agent",
    tenant_id="tenant-a",
    purpose_id="bounded-calculation",
    operation_id="calculation-once",
    artifact_kind=ExecutionArtifactKind.CODE,
    language=ExecutionLanguage.PYTHON,
    runtime_id=runtime.runtime_id,
    source="import math\nprint(math.sqrt(16))",
)

# A real sandbox broker authenticates the workload, provisions OS isolation,
# binds these controls to the request digest, and signs the attestation.
attestation = SandboxAttestation.create(
    attestation_id="attestation-example",
    provider_id="sandbox-service",
    sandbox_instance_id="microvm-example",
    sandbox_profile_id=runtime.sandbox_profile_id,
    request_digest=request.request_digest,
    runtime_id=runtime.runtime_id,
    runtime_digest=runtime.executable_digest,
    tenant_id=request.tenant_id,
    controls=frozenset(SandboxControl),
    issued_at=now - timedelta(seconds=1),
    expires_at=now + timedelta(seconds=30),
)
evidence = LocalEvidenceVerifier()
evidence.attestations.add((attestation.attestation_id, attestation.attestation_digest))
authorizer = CodeExecutionAuthorizer(
    CodeExecutionPolicy(
        runtimes=(runtime,),
        allowed_artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
        allowed_python_imports=frozenset({"math"}),
        trusted_sandbox_providers=frozenset({"sandbox-service"}),
    ),
    attestation_verifier=evidence,
    report_verifier=evidence,
)
authorization = authorizer.require(request, attestation, now=now)

# This local example never evaluates request.source. The fixed bytes represent a
# response returned by the authenticated external sandbox broker.
raw_output = ExecutionOutput(stdout=b"4.0\n")
report = CodeExecutionReport.create(
    output=raw_output,
    report_id="report-example",
    authorization_id=authorization.authorization_id,
    request_digest=authorization.request_digest,
    sandbox_attestation_id=authorization.sandbox_attestation_id,
    sandbox_instance_id=authorization.sandbox_instance_id,
    runtime_id=authorization.runtime_id,
    status=CodeExecutionStatus.SUCCEEDED,
    exit_code=0,
    started_at=now + timedelta(milliseconds=1),
    completed_at=now + timedelta(milliseconds=10),
    usage=ExecutionResourceUsage(
        wall_time_ms=9,
        cpu_time_ms=4,
        peak_memory_bytes=1_024,
        process_count=1,
        thread_count=1,
        file_count=0,
        written_bytes=0,
    ),
    cleanup=ExecutionCleanupEvidence(
        sandbox_destroyed=True,
        processes_terminated=True,
        filesystem_discarded=True,
        network_revoked=True,
        credentials_revoked=True,
    ),
)
evidence.reports.add((report.report_id, report.report_digest))
verified = authorizer.require_completion(
    authorization,
    report,
    raw_output,
    now=now + timedelta(milliseconds=20),
)
print(f"Verified sandbox output: {verified.stdout.decode().strip()}")
