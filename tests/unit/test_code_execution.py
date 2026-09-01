"""Unit tests for OWASP ASI05 isolated dynamic-execution controls."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    CodeExecutionAuthorizer,
    CodeExecutionCode,
    CodeExecutionPolicy,
    CodeExecutionReport,
    CodeExecutionRequest,
    CodeExecutionStatus,
    ExecutionArtifactKind,
    ExecutionCleanupEvidence,
    ExecutionExitConditions,
    ExecutionLanguage,
    ExecutionOutput,
    ExecutionOutputFormat,
    ExecutionPackage,
    ExecutionResourceLimits,
    ExecutionResourceUsage,
    ExecutionRuntime,
    FilesystemAccess,
    FilesystemPolicy,
    GuardAction,
    NetworkAccess,
    NetworkEndpoint,
    NetworkPolicy,
    SandboxAttestation,
    SandboxControl,
    StaticSandboxAttestationVerifier,
)

NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)
RUNTIME_DIGEST = "a" * 64


def _runtime(
    *,
    runtime_id: str = "python-3.12-isolated",
    language: ExecutionLanguage = ExecutionLanguage.PYTHON,
    artifact_kinds: frozenset[ExecutionArtifactKind] = frozenset(
        {ExecutionArtifactKind.CODE, ExecutionArtifactKind.SCRIPT}
    ),
) -> ExecutionRuntime:
    return ExecutionRuntime(
        runtime_id=runtime_id,
        language=language,
        version="3.12.0",
        executable_digest=RUNTIME_DIGEST,
        sandbox_profile_id="microvm-v3",
        allowed_artifact_kinds=artifact_kinds,
    )


def _policy(runtime: ExecutionRuntime | None = None, **updates: object) -> CodeExecutionPolicy:
    endpoint = NetworkEndpoint(host="api.example.com", port=443)
    policy = CodeExecutionPolicy(
        runtimes=(runtime or _runtime(),),
        allowed_artifact_kinds=frozenset(
            {
                ExecutionArtifactKind.CODE,
                ExecutionArtifactKind.SCRIPT,
                ExecutionArtifactKind.COMMAND,
                ExecutionArtifactKind.TEMPLATE,
                ExecutionArtifactKind.PACKAGE_INSTALL,
            }
        ),
        filesystem=FilesystemPolicy(
            readable_prefixes=frozenset({"inputs"}),
            writable_prefixes=frozenset({"outputs"}),
            max_read_paths=2,
            max_write_paths=2,
        ),
        network=NetworkPolicy(allowed_endpoints=frozenset({endpoint})),
        environment={"allowed_names": frozenset({"PUBLIC_CONFIG"})},
        max_resources=ExecutionResourceLimits(),
        allowed_python_imports=frozenset({"json", "math"}),
        trusted_sandbox_providers=frozenset({"sandbox-service"}),
    )
    return policy.model_copy(update=updates)


def _request(**updates: object) -> CodeExecutionRequest:
    values: dict[str, object] = {
        "request_id": "request-1",
        "actor_id": "analysis-agent",
        "tenant_id": "tenant-a",
        "purpose_id": "calculate-summary",
        "operation_id": "calculation-1",
        "artifact_kind": ExecutionArtifactKind.CODE,
        "language": ExecutionLanguage.PYTHON,
        "runtime_id": "python-3.12-isolated",
        "source": "import math\nprint(math.sqrt(16))",
    }
    values.update(updates)
    source = values.pop("source", None)
    return CodeExecutionRequest.create(source=source if isinstance(source, str) else None, **values)


def _attestation(
    request: CodeExecutionRequest,
    runtime: ExecutionRuntime | None = None,
    **updates: object,
) -> SandboxAttestation:
    selected_runtime = runtime or _runtime()
    values: dict[str, object] = {
        "attestation_id": "attestation-1",
        "provider_id": "sandbox-service",
        "sandbox_instance_id": "sandbox-8472",
        "sandbox_profile_id": selected_runtime.sandbox_profile_id,
        "request_digest": request.request_digest,
        "runtime_id": selected_runtime.runtime_id,
        "runtime_digest": selected_runtime.executable_digest,
        "tenant_id": request.tenant_id,
        "controls": frozenset(SandboxControl),
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(seconds=30),
    }
    values.update(updates)
    return SandboxAttestation.create(**values)


class MutableReportVerifier:
    def __init__(self) -> None:
        self.valid: set[tuple[str, str]] = set()

    def trust(self, report: CodeExecutionReport) -> None:
        self.valid.add((report.report_id, report.report_digest))

    def verify_report(self, report: CodeExecutionReport) -> bool:
        return (report.report_id, report.report_digest) in self.valid


def _authorizer(
    request: CodeExecutionRequest,
    attestation: SandboxAttestation,
    *,
    policy: CodeExecutionPolicy | None = None,
    report_verifier: object | None = None,
    **updates: object,
) -> CodeExecutionAuthorizer:
    return CodeExecutionAuthorizer(
        policy or _policy(),
        attestation_verifier=StaticSandboxAttestationVerifier(
            frozenset({(attestation.attestation_id, attestation.attestation_digest)})
        ),
        report_verifier=report_verifier,  # type: ignore[arg-type]
        **updates,  # type: ignore[arg-type]
    )


def _cleanup(**updates: bool) -> ExecutionCleanupEvidence:
    values = {
        "sandbox_destroyed": True,
        "processes_terminated": True,
        "filesystem_discarded": True,
        "network_revoked": True,
        "credentials_revoked": True,
    }
    values.update(updates)
    return ExecutionCleanupEvidence(**values)


def _usage(**updates: int) -> ExecutionResourceUsage:
    values = {
        "wall_time_ms": 10,
        "cpu_time_ms": 5,
        "peak_memory_bytes": 1_024,
        "process_count": 1,
        "thread_count": 1,
        "file_count": 0,
        "written_bytes": 0,
    }
    values.update(updates)
    return ExecutionResourceUsage(**values)


def _report(
    authorization: object,
    output: ExecutionOutput,
    **updates: object,
) -> CodeExecutionReport:
    values: dict[str, object] = {
        "report_id": "report-1",
        "authorization_id": authorization.authorization_id,
        "request_digest": authorization.request_digest,
        "sandbox_attestation_id": authorization.sandbox_attestation_id,
        "sandbox_instance_id": authorization.sandbox_instance_id,
        "runtime_id": authorization.runtime_id,
        "status": CodeExecutionStatus.SUCCEEDED,
        "exit_code": 0,
        "started_at": NOW + timedelta(seconds=1),
        "completed_at": NOW + timedelta(seconds=2),
        "usage": _usage(),
        "cleanup": _cleanup(),
    }
    values.update(updates)
    return CodeExecutionReport.create(output=output, **values)


def _admitted(
    *,
    request: CodeExecutionRequest | None = None,
    policy: CodeExecutionPolicy | None = None,
    output_validator: object | None = None,
) -> tuple[
    CodeExecutionAuthorizer,
    object,
    MutableReportVerifier,
    CodeExecutionRequest,
]:
    proposal = request or _request()
    active_policy = policy or _policy()
    runtime = next(
        item for item in active_policy.runtimes if item.runtime_id == proposal.runtime_id
    )
    attestation = _attestation(proposal, runtime)
    verifier = MutableReportVerifier()
    authorizer = _authorizer(
        proposal,
        attestation,
        policy=active_policy,
        report_verifier=verifier,
        output_validator=output_validator,
    )
    authorization = authorizer.require(proposal, attestation, now=NOW)
    return authorizer, authorization, verifier, proposal


def _codes(result: object) -> set[CodeExecutionCode]:
    return {finding.code for finding in result.findings}


def test_authorizes_exact_python_request_without_retaining_source_in_lease():
    request = _request()
    attestation = _attestation(request)
    authorizer = _authorizer(request, attestation)

    result = authorizer.authorize(request, attestation, now=NOW)

    assert result.is_authorized
    assert result.authorization is not None
    assert result.authorization.source_digest == request.source_digest
    assert "source" not in request.model_dump()
    assert request.source not in repr(request)
    assert not hasattr(result.authorization, "source")


def test_request_model_rejects_implicit_or_ambiguous_execution_shapes():
    with pytest.raises(ValidationError, match="source artifacts require"):
        CodeExecutionRequest(
            request_id="request-1",
            actor_id="agent",
            tenant_id="tenant-a",
            purpose_id="purpose",
            operation_id="operation",
            artifact_kind=ExecutionArtifactKind.CODE,
            language=ExecutionLanguage.PYTHON,
            runtime_id="python",
        )
    with pytest.raises(ValidationError, match="explicit argv"):
        _request(
            artifact_kind=ExecutionArtifactKind.COMMAND,
            language=ExecutionLanguage.NATIVE,
            source=None,
            argv=(),
        )


def test_models_reject_path_escape_and_unpinned_package_specifier():
    with pytest.raises(ValidationError, match="sandbox root"):
        FilesystemAccess(read_paths=("inputs/../../etc/passwd",))
    with pytest.raises(ValidationError):
        ExecutionPackage(name="requests", version=">=2", digest="b" * 64)


def test_model_copy_source_tampering_fails_closed():
    request = _request()
    attestation = _attestation(request)
    tampered = request.model_copy(update={"source": "import os\nos.system('id')"})

    result = _authorizer(request, attestation).authorize(tampered, attestation, now=NOW)

    assert CodeExecutionCode.REQUEST_INTEGRITY_INVALID in _codes(result)
    assert result.action == GuardAction.BLOCK


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import os as math\nprint(math)", CodeExecutionCode.DANGEROUS_IMPORT),
        ("from subprocess import run as calculate", CodeExecutionCode.DANGEROUS_IMPORT),
        ("import requests", CodeExecutionCode.IMPORT_NOT_ALLOWED),
        ("eval('1 + 1')", CodeExecutionCode.DANGEROUS_CONSTRUCT),
        ("getattr(object, '__class__')", CodeExecutionCode.DANGEROUS_CONSTRUCT),
        ("print((1).__class__)", CodeExecutionCode.DANGEROUS_CONSTRUCT),
        ("def broken(", CodeExecutionCode.SOURCE_SYNTAX_INVALID),
    ],
)
def test_rejects_dangerous_imports_dynamic_execution_and_bypasses(
    source: str,
    expected: CodeExecutionCode,
):
    request = _request(source=source)
    attestation = _attestation(request)

    result = _authorizer(request, attestation).authorize(request, attestation, now=NOW)

    assert expected in _codes(result)


def test_non_python_source_requires_a_fail_closed_inspector():
    runtime = _runtime(
        runtime_id="javascript-isolate",
        language=ExecutionLanguage.JAVASCRIPT,
        artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
    )
    policy = _policy(runtime)
    request = _request(
        language=ExecutionLanguage.JAVASCRIPT,
        runtime_id=runtime.runtime_id,
        source="console.log(4)",
    )
    attestation = _attestation(request, runtime)

    result = _authorizer(request, attestation, policy=policy).authorize(
        request, attestation, now=NOW
    )

    assert CodeExecutionCode.INSPECTION_UNAVAILABLE in _codes(result)


class Inspector:
    def __init__(self, result: bool | Exception) -> None:
        self.result = result

    def inspect(self, request: CodeExecutionRequest) -> bool:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_approved_non_python_source_uses_configured_inspector():
    runtime = _runtime(
        runtime_id="javascript-isolate",
        language=ExecutionLanguage.JAVASCRIPT,
        artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
    )
    policy = _policy(runtime)
    request = _request(
        language=ExecutionLanguage.JAVASCRIPT,
        runtime_id=runtime.runtime_id,
        source="console.log(4)",
    )
    attestation = _attestation(request, runtime)
    authorizer = _authorizer(
        request,
        attestation,
        policy=policy,
        inspectors={ExecutionLanguage.JAVASCRIPT: Inspector(True)},
    )

    assert authorizer.authorize(request, attestation, now=NOW).is_authorized


def test_fixed_native_command_uses_argv_without_a_shell():
    runtime = _runtime(
        runtime_id="fixed-json-renderer",
        language=ExecutionLanguage.NATIVE,
        artifact_kinds=frozenset({ExecutionArtifactKind.COMMAND}),
    )
    policy = _policy(runtime)
    request = _request(
        artifact_kind=ExecutionArtifactKind.COMMAND,
        language=ExecutionLanguage.NATIVE,
        runtime_id=runtime.runtime_id,
        source=None,
        argv=("--format", "json"),
    )
    attestation = _attestation(request, runtime)

    result = _authorizer(request, attestation, policy=policy).authorize(
        request, attestation, now=NOW
    )

    assert result.is_authorized


@pytest.mark.parametrize(
    ("inspection", "expected"),
    [
        (False, CodeExecutionCode.DANGEROUS_CONSTRUCT),
        (TimeoutError(), CodeExecutionCode.INSPECTION_UNAVAILABLE),
    ],
)
def test_custom_inspector_rejection_and_failure_are_closed(
    inspection: bool | Exception,
    expected: CodeExecutionCode,
):
    runtime = _runtime(
        runtime_id="javascript-isolate",
        language=ExecutionLanguage.JAVASCRIPT,
        artifact_kinds=frozenset({ExecutionArtifactKind.CODE}),
    )
    policy = _policy(runtime)
    request = _request(
        language=ExecutionLanguage.JAVASCRIPT,
        runtime_id=runtime.runtime_id,
        source="console.log(4)",
    )
    attestation = _attestation(request, runtime)
    authorizer = _authorizer(
        request,
        attestation,
        policy=policy,
        inspectors={ExecutionLanguage.JAVASCRIPT: Inspector(inspection)},
    )

    result = authorizer.authorize(request, attestation, now=NOW)

    assert expected in _codes(result)


@pytest.mark.parametrize(
    ("proposal", "policy", "expected"),
    [
        (
            _request(argv=("$(id)",)),
            _policy(),
            CodeExecutionCode.SHELL_EXPANSION_DENIED,
        ),
        (
            _request(filesystem=FilesystemAccess(read_paths=("private/secret",))),
            _policy(),
            CodeExecutionCode.FILESYSTEM_ACCESS_DENIED,
        ),
        (
            _request(
                network=NetworkAccess(endpoints=(NetworkEndpoint(host="evil.example", port=443),))
            ),
            _policy(),
            CodeExecutionCode.NETWORK_ACCESS_DENIED,
        ),
        (
            _request(environment_names=frozenset({"AWS_SECRET_ACCESS_KEY"})),
            _policy(),
            CodeExecutionCode.ENVIRONMENT_ACCESS_DENIED,
        ),
        (
            _request(resources=ExecutionResourceLimits(memory_bytes=256 * 1024 * 1024)),
            _policy(),
            CodeExecutionCode.RESOURCE_LIMIT_EXCEEDED,
        ),
    ],
)
def test_enforces_shell_filesystem_network_environment_and_resource_boundaries(
    proposal: CodeExecutionRequest,
    policy: CodeExecutionPolicy,
    expected: CodeExecutionCode,
):
    attestation = _attestation(proposal)

    result = _authorizer(proposal, attestation, policy=policy).authorize(
        proposal, attestation, now=NOW
    )

    assert expected in _codes(result)


def test_shell_runtime_is_rejected_even_if_present_in_runtime_inventory():
    runtime = _runtime(
        runtime_id="bash",
        language=ExecutionLanguage.SHELL,
        artifact_kinds=frozenset({ExecutionArtifactKind.COMMAND}),
    )
    policy = _policy(runtime)
    request = _request(
        artifact_kind=ExecutionArtifactKind.COMMAND,
        language=ExecutionLanguage.SHELL,
        runtime_id="bash",
        source=None,
        argv=("echo", "safe"),
    )
    attestation = _attestation(request, runtime)

    result = _authorizer(request, attestation, policy=policy).authorize(
        request, attestation, now=NOW
    )

    assert CodeExecutionCode.UNSAFE_INTERPRETER in _codes(result)


def test_package_installation_requires_enablement_and_exact_approval():
    package = ExecutionPackage(name="safe-math", version="1.2.3", digest="b" * 64)
    request = _request(packages=(package,))
    attestation = _attestation(request)
    disabled = _authorizer(request, attestation).authorize(request, attestation, now=NOW)
    assert CodeExecutionCode.PACKAGE_INSTALL_DENIED in _codes(disabled)

    unapproved_policy = _policy(allow_package_installation=True)
    unapproved = _authorizer(request, attestation, policy=unapproved_policy).authorize(
        request, attestation, now=NOW
    )
    assert CodeExecutionCode.PACKAGE_UNAPPROVED in _codes(unapproved)

    approved_policy = _policy(
        allow_package_installation=True,
        approved_packages=(package,),
    )
    allowed = _authorizer(request, attestation, policy=approved_policy).authorize(
        request, attestation, now=NOW
    )
    assert allowed.is_authorized


def test_missing_or_unverifiable_attestation_fails_closed():
    request = _request()
    attestation = _attestation(request)
    missing = _authorizer(request, attestation).authorize(request, None, now=NOW)
    unverifiable = CodeExecutionAuthorizer(_policy()).authorize(request, attestation, now=NOW)

    assert CodeExecutionCode.ATTESTATION_REQUIRED in _codes(missing)
    assert CodeExecutionCode.ATTESTATION_INVALID in _codes(unverifiable)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"expires_at": NOW}, CodeExecutionCode.ATTESTATION_EXPIRED),
        (
            {
                "issued_at": NOW - timedelta(minutes=2),
                "expires_at": NOW + timedelta(seconds=1),
            },
            CodeExecutionCode.ATTESTATION_INVALID,
        ),
        ({"provider_id": "attacker-sandbox"}, CodeExecutionCode.ATTESTATION_MISMATCH),
        ({"request_digest": "b" * 64}, CodeExecutionCode.ATTESTATION_MISMATCH),
        (
            {"controls": frozenset({SandboxControl.OS_ISOLATION})},
            CodeExecutionCode.SANDBOX_CONTROL_MISSING,
        ),
    ],
)
def test_rejects_expired_rebound_or_incomplete_sandbox_attestation(
    changes: dict[str, object],
    expected: CodeExecutionCode,
):
    request = _request()
    attestation = _attestation(request, **changes)

    result = _authorizer(request, attestation).authorize(request, attestation, now=NOW)

    assert expected in _codes(result)


def test_attestation_tampering_and_concurrent_replay_fail_closed():
    request = _request()
    attestation = _attestation(request)
    tampered = attestation.model_copy(update={"tenant_id": "tenant-b"})
    tampered_result = _authorizer(request, attestation).authorize(request, tampered, now=NOW)
    assert CodeExecutionCode.ATTESTATION_INVALID in _codes(tampered_result)

    authorizer = _authorizer(request, attestation)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: authorizer.authorize(request, attestation, now=NOW), range(2))
        )
    assert sum(result.is_authorized for result in results) == 1
    blocked = next(result for result in results if result.is_blocked)
    assert CodeExecutionCode.ATTESTATION_REPLAYED in _codes(blocked)


class AdmissionHook:
    def __init__(self, result: bool | Exception) -> None:
        self.result = result

    def admit(self, request: object, runtime: object, attestation: object) -> bool:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.mark.parametrize(
    ("hook_result", "expected"),
    [
        (False, CodeExecutionCode.ADMISSION_HOOK_REJECTED),
        (TimeoutError(), CodeExecutionCode.ADMISSION_HOOK_UNAVAILABLE),
    ],
)
def test_external_admission_hook_rejection_and_failure_are_closed(
    hook_result: bool | Exception,
    expected: CodeExecutionCode,
):
    request = _request()
    attestation = _attestation(request)
    authorizer = _authorizer(
        request,
        attestation,
        admission_hooks=(AdmissionHook(hook_result),),
    )

    result = authorizer.authorize(request, attestation, now=NOW)

    assert expected in _codes(result)


def test_verifies_success_exit_resources_output_and_cleanup_before_release():
    authorizer, authorization, verifier, _ = _admitted()
    output = ExecutionOutput(stdout=b"result: 4\n")
    report = _report(authorization, output)
    verifier.trust(report)

    outcome = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )

    assert outcome.is_verified
    assert outcome.output is not None
    assert outcome.output.stdout == b"result: 4\n"
    assert "stdout" not in outcome.output.model_dump()


def test_completion_requires_authentic_report():
    request = _request()
    attestation = _attestation(request)
    authorizer = _authorizer(request, attestation)
    authorization = authorizer.require(request, attestation, now=NOW)
    output = ExecutionOutput(stdout=b"4")
    report = _report(authorization, output)

    outcome = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )

    assert CodeExecutionCode.REPORT_UNVERIFIABLE in _codes(outcome)
    assert outcome.is_quarantined


@pytest.mark.parametrize(
    ("report_changes", "expected"),
    [
        ({"request_digest": "b" * 64}, CodeExecutionCode.REPORT_MISMATCH),
        (
            {"status": CodeExecutionStatus.TIMED_OUT, "exit_code": None},
            CodeExecutionCode.EXECUTION_TIMED_OUT,
        ),
        (
            {"status": CodeExecutionStatus.FAILED, "exit_code": 1},
            CodeExecutionCode.EXIT_CONDITION_FAILED,
        ),
        (
            {"usage": _usage(peak_memory_bytes=512 * 1024 * 1024)},
            CodeExecutionCode.RESOURCE_USAGE_EXCEEDED,
        ),
        (
            {"cleanup": _cleanup(filesystem_discarded=False)},
            CodeExecutionCode.CLEANUP_UNVERIFIED,
        ),
    ],
)
def test_quarantines_mismatched_timeout_failed_overuse_and_unclean_reports(
    report_changes: dict[str, object],
    expected: CodeExecutionCode,
):
    authorizer, authorization, verifier, _ = _admitted()
    output = ExecutionOutput(stdout=b"4")
    report = _report(authorization, output, **report_changes)
    verifier.trust(report)

    outcome = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )

    assert expected in _codes(outcome)
    assert outcome.output is None


def test_tampered_report_and_output_digest_mismatch_are_quarantined():
    authorizer, authorization, verifier, _ = _admitted()
    output = ExecutionOutput(stdout=b"expected")
    report = _report(authorization, output)
    verifier.trust(report)
    tampered_report = report.model_copy(update={"exit_code": 7})
    tampered = authorizer.verify_completion(
        authorization,
        tampered_report,
        output,
        now=NOW + timedelta(seconds=3),
    )
    assert CodeExecutionCode.REPORT_INVALID in _codes(tampered)

    authorizer, authorization, verifier, _ = _admitted()
    report = _report(authorization, output)
    verifier.trust(report)
    mismatch = authorizer.verify_completion(
        authorization,
        report,
        ExecutionOutput(stdout=b"different"),
        now=NOW + timedelta(seconds=3),
    )
    assert CodeExecutionCode.OUTPUT_MISMATCH in _codes(mismatch)


@pytest.mark.parametrize(
    ("output", "conditions", "expected"),
    [
        (
            ExecutionOutput(stdout=b"too long"),
            ExecutionExitConditions(max_stdout_bytes=3, max_stderr_bytes=0),
            CodeExecutionCode.OUTPUT_LIMIT_EXCEEDED,
        ),
        (
            ExecutionOutput(stdout=b"{not-json}"),
            ExecutionExitConditions(output_format=ExecutionOutputFormat.JSON),
            CodeExecutionCode.OUTPUT_INVALID,
        ),
        (
            ExecutionOutput(stdout=b"ok", stderr=b"warning"),
            ExecutionExitConditions(),
            CodeExecutionCode.EXIT_CONDITION_FAILED,
        ),
    ],
)
def test_output_limits_format_and_stderr_are_verified_before_release(
    output: ExecutionOutput,
    conditions: ExecutionExitConditions,
    expected: CodeExecutionCode,
):
    request = _request(exit_conditions=conditions)
    authorizer, authorization, verifier, _ = _admitted(request=request)
    report = _report(authorization, output)
    verifier.trust(report)

    outcome = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )

    assert expected in _codes(outcome)


class OutputValidator:
    def __init__(self, result: bool | Exception) -> None:
        self.result = result

    def validate_output(self, output: object, authorization: object) -> bool:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.mark.parametrize(
    ("validation", "expected"),
    [
        (False, CodeExecutionCode.OUTPUT_VALIDATOR_REJECTED),
        (TimeoutError(), CodeExecutionCode.OUTPUT_VALIDATOR_UNAVAILABLE),
    ],
)
def test_application_output_validator_rejection_and_failure_quarantine_output(
    validation: bool | Exception,
    expected: CodeExecutionCode,
):
    authorizer, authorization, verifier, _ = _admitted(output_validator=OutputValidator(validation))
    output = ExecutionOutput(stdout=b"4")
    report = _report(authorization, output)
    verifier.trust(report)

    outcome = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )

    assert expected in _codes(outcome)


def test_execution_authorization_and_report_are_single_use():
    authorizer, authorization, verifier, _ = _admitted()
    output = ExecutionOutput(stdout=b"4")
    report = _report(authorization, output)
    verifier.trust(report)

    first = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )
    replay = authorizer.verify_completion(
        authorization, report, output, now=NOW + timedelta(seconds=3)
    )

    assert first.is_verified
    assert {
        CodeExecutionCode.AUTHORIZATION_REPLAYED,
        CodeExecutionCode.REPORT_REPLAYED,
    }.issubset(_codes(replay))
