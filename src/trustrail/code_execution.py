"""Fail-closed admission and completion checks for isolated dynamic execution."""

from __future__ import annotations

import ast
import json
import re
import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import ValidationError

from trustrail.exceptions import CodeExecutionError
from trustrail.models.code_execution import (
    AuthorizedCodeExecution,
    CodeExecutionCode,
    CodeExecutionDecision,
    CodeExecutionFinding,
    CodeExecutionOutcome,
    CodeExecutionPolicy,
    CodeExecutionReport,
    CodeExecutionRequest,
    CodeExecutionStatus,
    ExecutionLanguage,
    ExecutionOutput,
    ExecutionOutputFormat,
    ExecutionRuntime,
    SandboxAttestation,
    VerifiedExecutionOutput,
)
from trustrail.models.enums import GuardAction, Severity

_FORBIDDEN_PYTHON_IMPORTS = frozenset(
    {
        "builtins",
        "ctypes",
        "importlib",
        "marshal",
        "multiprocessing",
        "os",
        "pathlib",
        "pickle",
        "resource",
        "shutil",
        "signal",
        "socket",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
    }
)
_FORBIDDEN_PYTHON_CALLS = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "globals",
        "input",
        "locals",
        "open",
        "setattr",
        "vars",
    }
)
_FORBIDDEN_PYTHON_ATTRIBUTES = frozenset(
    {
        "__bases__",
        "__builtins__",
        "__class__",
        "__code__",
        "__dict__",
        "__globals__",
        "__mro__",
        "__subclasses__",
    }
)
_SHELL_EXPANSION_RE = re.compile(r"(?:\$\(|\$\{|`|&&|\|\||[;<>|])")


class SandboxAttestationVerifier(Protocol):
    """Authenticate sandbox attestation evidence against a trusted provider."""

    def verify_attestation(self, attestation: SandboxAttestation) -> bool:
        """Return whether a provider issued this exact attestation."""
        ...


class CodeExecutionAdmissionHook(Protocol):
    """Application-owned policy hook run before an execution lease is issued."""

    def admit(
        self,
        request: CodeExecutionRequest,
        runtime: ExecutionRuntime,
        attestation: SandboxAttestation,
    ) -> bool:
        """Return whether trusted external policy admits the exact request."""
        ...


class CodeInspector(Protocol):
    """Language-specific static analysis hook for non-Python source artifacts."""

    def inspect(self, request: CodeExecutionRequest) -> bool:
        """Return whether the exact source is acceptable for sandbox execution."""
        ...


class CodeExecutionReportVerifier(Protocol):
    """Authenticate a terminal execution report from the sandbox provider."""

    def verify_report(self, report: CodeExecutionReport) -> bool:
        """Return whether the sandbox provider issued this exact report."""
        ...


class ExecutionOutputValidator(Protocol):
    """Application-specific output validation performed before output release."""

    def validate_output(
        self,
        output: ExecutionOutput,
        authorization: AuthorizedCodeExecution,
    ) -> bool:
        """Return whether output is safe for the application's next boundary."""
        ...


class CodeExecutionAuthorizer:
    """Admit exact sandbox requests and quarantine unverifiable outcomes."""

    def __init__(
        self,
        policy: CodeExecutionPolicy,
        *,
        attestation_verifier: SandboxAttestationVerifier | None = None,
        report_verifier: CodeExecutionReportVerifier | None = None,
        admission_hooks: tuple[CodeExecutionAdmissionHook, ...] = (),
        inspectors: Mapping[ExecutionLanguage, CodeInspector] | None = None,
        output_validator: ExecutionOutputValidator | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._attestation_verifier = attestation_verifier
        self._report_verifier = report_verifier
        self._admission_hooks = admission_hooks
        self._inspectors = dict(inspectors or {})
        self._output_validator = output_validator
        self._runtimes = {runtime.runtime_id: runtime for runtime in self._policy.runtimes}
        self._approved_packages = {
            package.name: package for package in self._policy.approved_packages
        }
        self._used_attestation_ids: set[str] = set()
        self._used_report_ids: set[str] = set()
        self._active_authorizations: dict[str, str] = {}
        self._lock = threading.Lock()

    @property
    def policy(self) -> CodeExecutionPolicy:
        """Return a defensive copy of the active execution policy."""
        return self._policy.model_copy(deep=True)

    def authorize(
        self,
        request: CodeExecutionRequest,
        attestation: SandboxAttestation | None,
        *,
        now: datetime | None = None,
    ) -> CodeExecutionDecision:
        """Authorize one explicit request without executing its source or argv."""
        current_time = self._current_time(now)
        findings = self._request_integrity_findings(request)
        runtime = self._runtimes.get(request.runtime_id)
        findings.extend(self._runtime_findings(request, runtime))
        findings.extend(self._policy_boundary_findings(request))
        findings.extend(self._source_findings(request, runtime))
        findings.extend(self._attestation_findings(request, runtime, attestation, current_time))
        if not findings and runtime is not None and attestation is not None:
            findings.extend(self._hook_findings(request, runtime, attestation))
        findings = self._deduplicate(findings)
        if findings or runtime is None or attestation is None:
            return self._blocked(findings)

        with self._lock:
            if attestation.attestation_id in self._used_attestation_ids:
                return self._blocked(
                    [
                        self._finding(
                            CodeExecutionCode.ATTESTATION_REPLAYED,
                            Severity.CRITICAL,
                            "Sandbox attestation has already been consumed",
                        )
                    ]
                )
            self._used_attestation_ids.add(attestation.attestation_id)
            authorization = AuthorizedCodeExecution.create(
                authorization_id=str(uuid.uuid4()),
                request_digest=request.request_digest,
                source_digest=request.source_digest,
                actor_id=request.actor_id,
                tenant_id=request.tenant_id,
                purpose_id=request.purpose_id,
                operation_id=request.operation_id,
                artifact_kind=request.artifact_kind,
                runtime_id=runtime.runtime_id,
                runtime_digest=runtime.executable_digest,
                sandbox_attestation_id=attestation.attestation_id,
                sandbox_instance_id=attestation.sandbox_instance_id,
                resources=request.resources,
                exit_conditions=request.exit_conditions,
                issued_at=current_time,
                expires_at=min(
                    attestation.expires_at,
                    current_time + timedelta(seconds=self._policy.authorization_ttl_seconds),
                ),
            )
            self._active_authorizations[authorization.authorization_id] = (
                authorization.authorization_digest
            )
        return CodeExecutionDecision(
            action=GuardAction.ALLOW,
            authorization=authorization,
        )

    def require(
        self,
        request: CodeExecutionRequest,
        attestation: SandboxAttestation | None,
        *,
        now: datetime | None = None,
    ) -> AuthorizedCodeExecution:
        """Return a single-use execution lease or raise before sandbox dispatch."""
        result = self.authorize(request, attestation, now=now)
        if not result.is_authorized or result.authorization is None:
            raise CodeExecutionError(decision=result)
        return result.authorization

    def verify_completion(
        self,
        authorization: AuthorizedCodeExecution,
        report: CodeExecutionReport,
        output: ExecutionOutput,
        *,
        now: datetime | None = None,
    ) -> CodeExecutionOutcome:
        """Verify a terminal report, cleanup, and output before releasing bytes."""
        current_time = self._current_time(now)
        findings = self._authorization_findings(authorization)
        findings.extend(self._report_integrity_findings(report))
        findings.extend(self._report_binding_findings(authorization, report, current_time))
        findings.extend(self._terminal_findings(authorization, report))
        findings.extend(self._output_findings(authorization, report, output))

        with self._lock:
            active_digest = self._active_authorizations.get(authorization.authorization_id)
            if report.report_id in self._used_report_ids:
                findings.append(
                    self._finding(
                        CodeExecutionCode.REPORT_REPLAYED,
                        Severity.CRITICAL,
                        "Execution report has already been consumed",
                    )
                )
            if active_digest is None:
                findings.append(
                    self._finding(
                        CodeExecutionCode.AUTHORIZATION_REPLAYED,
                        Severity.CRITICAL,
                        "Execution authorization is no longer active",
                    )
                )
            elif active_digest != authorization.authorization_digest:
                findings.append(
                    self._finding(
                        CodeExecutionCode.AUTHORIZATION_INVALID,
                        Severity.CRITICAL,
                        "Execution authorization differs from the issued lease",
                    )
                )
            else:
                self._active_authorizations.pop(authorization.authorization_id, None)
                self._used_report_ids.add(report.report_id)

        findings = self._deduplicate(findings)
        if not findings:
            findings.extend(self._output_validator_findings(authorization, output))
        if findings:
            return CodeExecutionOutcome(
                action=GuardAction.QUARANTINE,
                findings=tuple(findings),
            )
        return CodeExecutionOutcome(
            action=GuardAction.ALLOW,
            output=VerifiedExecutionOutput(
                authorization_id=authorization.authorization_id,
                report_id=report.report_id,
                stdout=output.stdout,
                stderr=output.stderr,
                stdout_digest=output.stdout_digest,
                stderr_digest=output.stderr_digest,
                completed_at=report.completed_at,
            ),
        )

    def require_completion(
        self,
        authorization: AuthorizedCodeExecution,
        report: CodeExecutionReport,
        output: ExecutionOutput,
        *,
        now: datetime | None = None,
    ) -> VerifiedExecutionOutput:
        """Return verified bytes or raise while keeping failed output quarantined."""
        outcome = self.verify_completion(authorization, report, output, now=now)
        if not outcome.is_verified or outcome.output is None:
            raise CodeExecutionError(outcome=outcome)
        return outcome.output

    @staticmethod
    def _current_time(value: datetime | None) -> datetime:
        current = value or datetime.now(tz=UTC)
        if not hasattr(current, "tzinfo") or current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must be a timezone-aware datetime")
        return current

    def _request_integrity_findings(
        self,
        request: CodeExecutionRequest,
    ) -> list[CodeExecutionFinding]:
        try:
            values = request.model_dump()
            values["source"] = request.source
            CodeExecutionRequest.model_validate(values)
        except (ValidationError, ValueError, TypeError):
            return [
                self._finding(
                    CodeExecutionCode.REQUEST_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Execution request shape or source integrity is invalid",
                )
            ]
        return []

    def _runtime_findings(
        self,
        request: CodeExecutionRequest,
        runtime: ExecutionRuntime | None,
    ) -> list[CodeExecutionFinding]:
        if runtime is None:
            return [
                self._finding(
                    CodeExecutionCode.RUNTIME_DENIED,
                    Severity.CRITICAL,
                    "Execution runtime is not present in the approved inventory",
                )
            ]
        findings: list[CodeExecutionFinding] = []
        if request.language != runtime.language:
            findings.append(
                self._finding(
                    CodeExecutionCode.RUNTIME_MISMATCH,
                    Severity.CRITICAL,
                    "Requested language does not match the approved runtime",
                )
            )
        if runtime.language == ExecutionLanguage.SHELL:
            findings.append(
                self._finding(
                    CodeExecutionCode.UNSAFE_INTERPRETER,
                    Severity.CRITICAL,
                    "Shell interpreters are not admitted for agent-generated execution",
                )
            )
        if request.artifact_kind not in runtime.allowed_artifact_kinds:
            findings.append(
                self._finding(
                    CodeExecutionCode.ARTIFACT_KIND_DENIED,
                    Severity.CRITICAL,
                    "Runtime is not approved for the requested artifact kind",
                )
            )
        return findings

    def _policy_boundary_findings(
        self,
        request: CodeExecutionRequest,
    ) -> list[CodeExecutionFinding]:
        findings: list[CodeExecutionFinding] = []
        if request.artifact_kind not in self._policy.allowed_artifact_kinds:
            findings.append(
                self._finding(
                    CodeExecutionCode.ARTIFACT_KIND_DENIED,
                    Severity.CRITICAL,
                    "Artifact kind is not allowed by execution policy",
                )
            )
        if (
            request.source is not None
            and len(request.source.encode()) > self._policy.max_source_bytes
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.SOURCE_TOO_LARGE,
                    Severity.HIGH,
                    "Generated source exceeds the configured byte limit",
                )
            )
        if any(_SHELL_EXPANSION_RE.search(argument) for argument in request.argv):
            findings.append(
                self._finding(
                    CodeExecutionCode.SHELL_EXPANSION_DENIED,
                    Severity.CRITICAL,
                    "Command arguments contain shell expansion or control syntax",
                )
            )
        if not self._filesystem_allowed(request):
            findings.append(
                self._finding(
                    CodeExecutionCode.FILESYSTEM_ACCESS_DENIED,
                    Severity.CRITICAL,
                    "Requested filesystem access exceeds the sandbox allowlist",
                )
            )
        if any(
            endpoint not in self._policy.network.allowed_endpoints
            for endpoint in request.network.endpoints
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.NETWORK_ACCESS_DENIED,
                    Severity.CRITICAL,
                    "Requested network access exceeds the exact endpoint allowlist",
                )
            )
        if not request.environment_names.issubset(self._policy.environment.allowed_names):
            findings.append(
                self._finding(
                    CodeExecutionCode.ENVIRONMENT_ACCESS_DENIED,
                    Severity.CRITICAL,
                    "Requested environment names exceed the sandbox allowlist",
                )
            )
        if self._resources_exceed(request):
            findings.append(
                self._finding(
                    CodeExecutionCode.RESOURCE_LIMIT_EXCEEDED,
                    Severity.CRITICAL,
                    "Requested resources exceed execution policy",
                )
            )
        if request.packages and not self._policy.allow_package_installation:
            findings.append(
                self._finding(
                    CodeExecutionCode.PACKAGE_INSTALL_DENIED,
                    Severity.CRITICAL,
                    "Dynamic package installation is disabled",
                )
            )
        elif any(
            self._approved_packages.get(package.name) != package for package in request.packages
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.PACKAGE_UNAPPROVED,
                    Severity.CRITICAL,
                    "Requested package is not exactly pinned in the approved inventory",
                )
            )
        return findings

    def _source_findings(
        self,
        request: CodeExecutionRequest,
        runtime: ExecutionRuntime | None,
    ) -> list[CodeExecutionFinding]:
        if request.source is None or runtime is None:
            return []
        if runtime.language == ExecutionLanguage.PYTHON:
            return self._inspect_python(request.source)
        inspector = self._inspectors.get(runtime.language)
        if inspector is None:
            return [
                self._finding(
                    CodeExecutionCode.INSPECTION_UNAVAILABLE,
                    Severity.CRITICAL,
                    "No fail-closed inspector is configured for this source language",
                )
            ]
        try:
            accepted = inspector.inspect(request)
        except Exception:
            return [
                self._finding(
                    CodeExecutionCode.INSPECTION_UNAVAILABLE,
                    Severity.CRITICAL,
                    "Source inspection is unavailable",
                )
            ]
        if accepted:
            return []
        return [
            self._finding(
                CodeExecutionCode.DANGEROUS_CONSTRUCT,
                Severity.CRITICAL,
                "Source inspector rejected the generated artifact",
            )
        ]

    def _inspect_python(self, source: str) -> list[CodeExecutionFinding]:
        try:
            tree = ast.parse(source, mode="exec")
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            return [
                self._finding(
                    CodeExecutionCode.SOURCE_SYNTAX_INVALID,
                    Severity.HIGH,
                    "Generated Python source is not valid bounded syntax",
                )
            ]
        findings: list[CodeExecutionFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    findings.extend(self._python_import_findings(alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.level or node.module is None:
                    findings.append(
                        self._finding(
                            CodeExecutionCode.IMPORT_NOT_ALLOWED,
                            Severity.CRITICAL,
                            "Relative or unresolved imports are not allowed",
                        )
                    )
                else:
                    findings.extend(self._python_import_findings(node.module))
            elif isinstance(node, ast.Call):
                name = self._python_call_name(node.func)
                if name in _FORBIDDEN_PYTHON_CALLS or name.rsplit(".", 1)[-1] in {
                    "system",
                    "popen",
                    "fork",
                    "spawn",
                }:
                    findings.append(
                        self._finding(
                            CodeExecutionCode.DANGEROUS_CONSTRUCT,
                            Severity.CRITICAL,
                            "Generated Python uses a dynamic or host execution primitive",
                        )
                    )
            elif isinstance(node, ast.Attribute) and (
                node.attr.startswith("__") or node.attr in _FORBIDDEN_PYTHON_ATTRIBUTES
            ):
                findings.append(
                    self._finding(
                        CodeExecutionCode.DANGEROUS_CONSTRUCT,
                        Severity.CRITICAL,
                        "Generated Python accesses interpreter internals",
                    )
                )
            elif isinstance(node, ast.Name) and node.id == "__builtins__":
                findings.append(
                    self._finding(
                        CodeExecutionCode.DANGEROUS_CONSTRUCT,
                        Severity.CRITICAL,
                        "Generated Python accesses interpreter builtins indirectly",
                    )
                )
        return self._deduplicate(findings)

    def _python_import_findings(self, module: str) -> list[CodeExecutionFinding]:
        root = module.casefold().split(".", 1)[0]
        if root in _FORBIDDEN_PYTHON_IMPORTS:
            return [
                self._finding(
                    CodeExecutionCode.DANGEROUS_IMPORT,
                    Severity.CRITICAL,
                    "Generated Python imports a host-access or dynamic-execution module",
                )
            ]
        if root not in self._policy.allowed_python_imports:
            return [
                self._finding(
                    CodeExecutionCode.IMPORT_NOT_ALLOWED,
                    Severity.HIGH,
                    "Generated Python import is not in the explicit allowlist",
                )
            ]
        return []

    @staticmethod
    def _python_call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = [node.attr]
            current = node.value
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _attestation_findings(
        self,
        request: CodeExecutionRequest,
        runtime: ExecutionRuntime | None,
        attestation: SandboxAttestation | None,
        now: datetime,
    ) -> list[CodeExecutionFinding]:
        if attestation is None:
            return [
                self._finding(
                    CodeExecutionCode.ATTESTATION_REQUIRED,
                    Severity.CRITICAL,
                    "Authenticated sandbox attestation is required before execution",
                )
            ]
        try:
            SandboxAttestation.model_validate(attestation.model_dump())
        except (ValidationError, ValueError, TypeError):
            return [
                self._finding(
                    CodeExecutionCode.ATTESTATION_INVALID,
                    Severity.CRITICAL,
                    "Sandbox attestation integrity is invalid",
                )
            ]
        findings: list[CodeExecutionFinding] = []
        if now < attestation.issued_at or now >= attestation.expires_at:
            findings.append(
                self._finding(
                    CodeExecutionCode.ATTESTATION_EXPIRED,
                    Severity.CRITICAL,
                    "Sandbox attestation is outside its validity window",
                )
            )
        if (
            attestation.expires_at - attestation.issued_at
        ).total_seconds() > self._policy.max_attestation_lifetime_seconds:
            findings.append(
                self._finding(
                    CodeExecutionCode.ATTESTATION_INVALID,
                    Severity.CRITICAL,
                    "Sandbox attestation lifetime exceeds policy",
                )
            )
        if (
            runtime is None
            or attestation.request_digest != request.request_digest
            or attestation.runtime_id != request.runtime_id
            or attestation.runtime_digest != runtime.executable_digest
            or attestation.sandbox_profile_id != runtime.sandbox_profile_id
            or attestation.tenant_id != request.tenant_id
            or attestation.provider_id not in self._policy.trusted_sandbox_providers
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.ATTESTATION_MISMATCH,
                    Severity.CRITICAL,
                    "Sandbox evidence is not bound to the exact request and runtime",
                )
            )
        if not self._policy.required_sandbox_controls.issubset(attestation.controls):
            findings.append(
                self._finding(
                    CodeExecutionCode.SANDBOX_CONTROL_MISSING,
                    Severity.CRITICAL,
                    "Sandbox evidence omits a required isolation control",
                )
            )
        if not self._verify_attestation(attestation):
            findings.append(
                self._finding(
                    CodeExecutionCode.ATTESTATION_INVALID,
                    Severity.CRITICAL,
                    "Sandbox attestation authenticity could not be verified",
                )
            )
        return findings

    def _hook_findings(
        self,
        request: CodeExecutionRequest,
        runtime: ExecutionRuntime,
        attestation: SandboxAttestation,
    ) -> list[CodeExecutionFinding]:
        findings: list[CodeExecutionFinding] = []
        for hook in self._admission_hooks:
            try:
                admitted = hook.admit(request, runtime, attestation)
            except Exception:
                findings.append(
                    self._finding(
                        CodeExecutionCode.ADMISSION_HOOK_UNAVAILABLE,
                        Severity.CRITICAL,
                        "External execution admission policy is unavailable",
                    )
                )
                continue
            if not admitted:
                findings.append(
                    self._finding(
                        CodeExecutionCode.ADMISSION_HOOK_REJECTED,
                        Severity.CRITICAL,
                        "External execution admission policy rejected the request",
                    )
                )
        return findings

    def _authorization_findings(
        self,
        authorization: AuthorizedCodeExecution,
    ) -> list[CodeExecutionFinding]:
        try:
            AuthorizedCodeExecution.model_validate(authorization.model_dump())
        except (ValidationError, ValueError, TypeError):
            return [
                self._finding(
                    CodeExecutionCode.AUTHORIZATION_INVALID,
                    Severity.CRITICAL,
                    "Execution authorization integrity is invalid",
                )
            ]
        return []

    def _report_integrity_findings(
        self,
        report: CodeExecutionReport,
    ) -> list[CodeExecutionFinding]:
        try:
            CodeExecutionReport.model_validate(report.model_dump())
        except (ValidationError, ValueError, TypeError):
            return [
                self._finding(
                    CodeExecutionCode.REPORT_INVALID,
                    Severity.CRITICAL,
                    "Execution report integrity is invalid",
                )
            ]
        if not self._verify_report(report):
            return [
                self._finding(
                    CodeExecutionCode.REPORT_UNVERIFIABLE,
                    Severity.CRITICAL,
                    "Execution report authenticity could not be verified",
                )
            ]
        return []

    def _report_binding_findings(
        self,
        authorization: AuthorizedCodeExecution,
        report: CodeExecutionReport,
        now: datetime,
    ) -> list[CodeExecutionFinding]:
        if (
            report.authorization_id != authorization.authorization_id
            or report.request_digest != authorization.request_digest
            or report.sandbox_attestation_id != authorization.sandbox_attestation_id
            or report.sandbox_instance_id != authorization.sandbox_instance_id
            or report.runtime_id != authorization.runtime_id
            or report.started_at < authorization.issued_at
            or report.completed_at > now + timedelta(seconds=5)
        ):
            return [
                self._finding(
                    CodeExecutionCode.REPORT_MISMATCH,
                    Severity.CRITICAL,
                    "Execution report is not bound to the issued lease and sandbox",
                )
            ]
        if report.started_at >= authorization.expires_at:
            return [
                self._finding(
                    CodeExecutionCode.AUTHORIZATION_EXPIRED,
                    Severity.CRITICAL,
                    "Execution began after its authorization lease expired",
                )
            ]
        return []

    def _terminal_findings(
        self,
        authorization: AuthorizedCodeExecution,
        report: CodeExecutionReport,
    ) -> list[CodeExecutionFinding]:
        findings: list[CodeExecutionFinding] = []
        if report.status == CodeExecutionStatus.TIMED_OUT:
            findings.append(
                self._finding(
                    CodeExecutionCode.EXECUTION_TIMED_OUT,
                    Severity.CRITICAL,
                    "Sandbox execution timed out",
                )
            )
        elif (
            report.status != CodeExecutionStatus.SUCCEEDED
            or report.exit_code not in authorization.exit_conditions.allowed_exit_codes
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.EXIT_CONDITION_FAILED,
                    Severity.HIGH,
                    "Execution did not satisfy its declared terminal conditions",
                )
            )
        if self._usage_exceeds(authorization, report):
            findings.append(
                self._finding(
                    CodeExecutionCode.RESOURCE_USAGE_EXCEEDED,
                    Severity.CRITICAL,
                    "Observed execution usage exceeded the authorized resource ceiling",
                )
            )
        if not report.cleanup.is_complete:
            findings.append(
                self._finding(
                    CodeExecutionCode.CLEANUP_UNVERIFIED,
                    Severity.CRITICAL,
                    "Sandbox cleanup and privilege revocation are incomplete",
                )
            )
        return findings

    def _output_findings(
        self,
        authorization: AuthorizedCodeExecution,
        report: CodeExecutionReport,
        output: ExecutionOutput,
    ) -> list[CodeExecutionFinding]:
        findings: list[CodeExecutionFinding] = []
        if (
            report.stdout_size != len(output.stdout)
            or report.stdout_digest != output.stdout_digest
            or report.stderr_size != len(output.stderr)
            or report.stderr_digest != output.stderr_digest
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.OUTPUT_MISMATCH,
                    Severity.CRITICAL,
                    "Returned bytes do not match the authenticated execution report",
                )
            )
        conditions = authorization.exit_conditions
        if (
            len(output.stdout) > conditions.max_stdout_bytes
            or len(output.stderr) > conditions.max_stderr_bytes
            or len(output.stdout) + len(output.stderr) > authorization.resources.output_bytes
        ):
            findings.append(
                self._finding(
                    CodeExecutionCode.OUTPUT_LIMIT_EXCEEDED,
                    Severity.CRITICAL,
                    "Execution output exceeds its authorized byte limit",
                )
            )
        if output.stderr and not conditions.allow_stderr:
            findings.append(
                self._finding(
                    CodeExecutionCode.EXIT_CONDITION_FAILED,
                    Severity.HIGH,
                    "Execution produced stderr when none was allowed",
                )
            )
        if not self._valid_output_format(output.stdout, conditions.output_format):
            findings.append(
                self._finding(
                    CodeExecutionCode.OUTPUT_INVALID,
                    Severity.HIGH,
                    "Execution stdout does not match the declared output format",
                )
            )
        return findings

    def _output_validator_findings(
        self,
        authorization: AuthorizedCodeExecution,
        output: ExecutionOutput,
    ) -> list[CodeExecutionFinding]:
        if self._output_validator is None:
            return []
        try:
            accepted = self._output_validator.validate_output(output, authorization)
        except Exception:
            return [
                self._finding(
                    CodeExecutionCode.OUTPUT_VALIDATOR_UNAVAILABLE,
                    Severity.CRITICAL,
                    "Application output validation is unavailable",
                )
            ]
        if accepted:
            return []
        return [
            self._finding(
                CodeExecutionCode.OUTPUT_VALIDATOR_REJECTED,
                Severity.CRITICAL,
                "Application output validation rejected sandbox output",
            )
        ]

    def _filesystem_allowed(self, request: CodeExecutionRequest) -> bool:
        policy = self._policy.filesystem
        if (
            len(request.filesystem.read_paths) > policy.max_read_paths
            or len(request.filesystem.write_paths) > policy.max_write_paths
        ):
            return False
        return all(
            self._path_allowed(path, policy.readable_prefixes)
            for path in request.filesystem.read_paths
        ) and all(
            self._path_allowed(path, policy.writable_prefixes)
            for path in request.filesystem.write_paths
        )

    @staticmethod
    def _path_allowed(path: str, prefixes: frozenset[str]) -> bool:
        return any(path == prefix or path.startswith(f"{prefix}/") for prefix in prefixes)

    def _resources_exceed(self, request: CodeExecutionRequest) -> bool:
        requested = request.resources
        maximum = self._policy.max_resources
        return any(
            (
                requested.wall_time_ms > maximum.wall_time_ms,
                requested.cpu_time_ms > maximum.cpu_time_ms,
                requested.memory_bytes > maximum.memory_bytes,
                requested.output_bytes > maximum.output_bytes,
                requested.process_count > maximum.process_count,
                requested.thread_count > maximum.thread_count,
                requested.file_count > maximum.file_count,
                requested.written_bytes > maximum.written_bytes,
            )
        )

    @staticmethod
    def _usage_exceeds(
        authorization: AuthorizedCodeExecution,
        report: CodeExecutionReport,
    ) -> bool:
        limits = authorization.resources
        usage = report.usage
        elapsed_ms = (report.completed_at - report.started_at).total_seconds() * 1_000
        return any(
            (
                elapsed_ms > limits.wall_time_ms,
                usage.wall_time_ms > limits.wall_time_ms,
                usage.cpu_time_ms > limits.cpu_time_ms,
                usage.peak_memory_bytes > limits.memory_bytes,
                usage.process_count > limits.process_count,
                usage.thread_count > limits.thread_count,
                usage.file_count > limits.file_count,
                usage.written_bytes > limits.written_bytes,
            )
        )

    @staticmethod
    def _valid_output_format(output: bytes, output_format: ExecutionOutputFormat) -> bool:
        if output_format == ExecutionOutputFormat.BINARY:
            return True
        try:
            text = output.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if output_format == ExecutionOutputFormat.TEXT:
            return True

        def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        def reject_constant(_: str) -> None:
            raise ValueError("non-finite JSON number")

        try:
            json.loads(
                text,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_constant,
            )
        except (json.JSONDecodeError, RecursionError, ValueError):
            return False
        return True

    def _verify_attestation(self, attestation: SandboxAttestation) -> bool:
        if self._attestation_verifier is None:
            return False
        try:
            return self._attestation_verifier.verify_attestation(attestation)
        except Exception:
            return False

    def _verify_report(self, report: CodeExecutionReport) -> bool:
        if self._report_verifier is None:
            return False
        try:
            return self._report_verifier.verify_report(report)
        except Exception:
            return False

    @staticmethod
    def _blocked(findings: list[CodeExecutionFinding]) -> CodeExecutionDecision:
        return CodeExecutionDecision(action=GuardAction.BLOCK, findings=tuple(findings))

    @staticmethod
    def _finding(
        code: CodeExecutionCode,
        severity: Severity,
        message: str,
    ) -> CodeExecutionFinding:
        return CodeExecutionFinding(code=code, severity=severity, message=message)

    @staticmethod
    def _deduplicate(findings: list[CodeExecutionFinding]) -> list[CodeExecutionFinding]:
        unique: dict[CodeExecutionCode, CodeExecutionFinding] = {}
        for finding in findings:
            unique.setdefault(finding.code, finding)
        return list(unique.values())


class StaticSandboxAttestationVerifier:
    """Test/example verifier backed by exact attestation IDs and digests."""

    def __init__(self, valid_attestations: frozenset[tuple[str, str]]) -> None:
        self._valid_attestations = valid_attestations

    def verify_attestation(self, attestation: SandboxAttestation) -> bool:
        return (
            attestation.attestation_id,
            attestation.attestation_digest,
        ) in self._valid_attestations


class StaticCodeExecutionReportVerifier:
    """Test/example verifier backed by exact report IDs and digests."""

    def __init__(self, valid_reports: frozenset[tuple[str, str]]) -> None:
        self._valid_reports = valid_reports

    def verify_report(self, report: CodeExecutionReport) -> bool:
        return (report.report_id, report.report_digest) in self._valid_reports
