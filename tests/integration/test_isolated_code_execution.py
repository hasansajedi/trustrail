"""End-to-end admission and verified-output flow through a sandbox broker."""

from __future__ import annotations

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
    FilesystemAccess,
    FilesystemPolicy,
    SandboxAttestation,
    SandboxControl,
)

NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


class FakeAuthenticatedSandboxBroker:
    """Contract fake: it returns evidence and never evaluates generated source."""

    def __init__(self) -> None:
        self.attestations: set[tuple[str, str]] = set()
        self.reports: set[tuple[str, str]] = set()

    def prepare(
        self,
        request: CodeExecutionRequest,
        runtime: ExecutionRuntime,
    ) -> SandboxAttestation:
        attestation = SandboxAttestation.create(
            attestation_id="attestation-integration",
            provider_id="sandbox-service",
            sandbox_instance_id="microvm-integration",
            sandbox_profile_id=runtime.sandbox_profile_id,
            request_digest=request.request_digest,
            runtime_id=runtime.runtime_id,
            runtime_digest=runtime.executable_digest,
            tenant_id=request.tenant_id,
            controls=frozenset(SandboxControl),
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=30),
        )
        self.attestations.add((attestation.attestation_id, attestation.attestation_digest))
        return attestation

    def verify_attestation(self, attestation: SandboxAttestation) -> bool:
        return (
            attestation.attestation_id,
            attestation.attestation_digest,
        ) in self.attestations

    def report_success(
        self,
        authorization: object,
        output: ExecutionOutput,
    ) -> CodeExecutionReport:
        report = CodeExecutionReport.create(
            output=output,
            report_id="report-integration",
            authorization_id=authorization.authorization_id,
            request_digest=authorization.request_digest,
            sandbox_attestation_id=authorization.sandbox_attestation_id,
            sandbox_instance_id=authorization.sandbox_instance_id,
            runtime_id=authorization.runtime_id,
            status=CodeExecutionStatus.SUCCEEDED,
            exit_code=0,
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=2),
            usage=ExecutionResourceUsage(
                wall_time_ms=20,
                cpu_time_ms=10,
                peak_memory_bytes=2_048,
                process_count=1,
                thread_count=1,
                file_count=1,
                written_bytes=10,
            ),
            cleanup=ExecutionCleanupEvidence(
                sandbox_destroyed=True,
                processes_terminated=True,
                filesystem_discarded=True,
                network_revoked=True,
                credentials_revoked=True,
            ),
        )
        self.reports.add((report.report_id, report.report_digest))
        return report

    def verify_report(self, report: CodeExecutionReport) -> bool:
        return (report.report_id, report.report_digest) in self.reports


def test_exact_request_is_admitted_and_only_verified_output_is_released():
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
        purpose_id="summarize-approved-input",
        operation_id="calculation-once",
        artifact_kind=ExecutionArtifactKind.CODE,
        language=ExecutionLanguage.PYTHON,
        runtime_id=runtime.runtime_id,
        source="import json\nprint(json.dumps({'count': 3}))",
        filesystem=FilesystemAccess(
            read_paths=("inputs/records.json",),
            write_paths=("outputs/summary.json",),
        ),
        environment_names=frozenset({"PUBLIC_CONFIG"}),
    )
    policy = CodeExecutionPolicy(
        runtimes=(runtime,),
        allowed_artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
        filesystem=FilesystemPolicy(
            readable_prefixes=frozenset({"inputs"}),
            writable_prefixes=frozenset({"outputs"}),
            max_read_paths=1,
            max_write_paths=1,
        ),
        environment={"allowed_names": frozenset({"PUBLIC_CONFIG"})},
        allowed_python_imports=frozenset({"json"}),
        trusted_sandbox_providers=frozenset({"sandbox-service"}),
    )
    broker = FakeAuthenticatedSandboxBroker()
    attestation = broker.prepare(request, runtime)
    authorizer = CodeExecutionAuthorizer(
        policy,
        attestation_verifier=broker,
        report_verifier=broker,
    )

    authorization = authorizer.require(request, attestation, now=NOW)
    # A real broker runs the source in the attested OS sandbox. This test fake
    # deliberately returns predetermined bytes and cannot execute source code.
    raw_output = ExecutionOutput(stdout=b'{"count": 3}\n')
    report = broker.report_success(authorization, raw_output)
    verified = authorizer.require_completion(
        authorization,
        report,
        raw_output,
        now=NOW + timedelta(seconds=3),
    )

    assert verified.stdout == b'{"count": 3}\n'
    assert verified.stdout_digest == raw_output.stdout_digest
