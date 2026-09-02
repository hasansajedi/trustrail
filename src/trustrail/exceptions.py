"""trustrail exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from trustrail.models.agency import ToolAuthorizationResult
    from trustrail.models.code_execution import (
        CodeExecutionDecision,
        CodeExecutionOutcome,
    )
    from trustrail.models.delegated_identity import DelegatedAccessResult
    from trustrail.models.failure_containment import FailureContainmentResult
    from trustrail.models.goal import GoalIntegrityResult
    from trustrail.models.grounding import GroundingResult
    from trustrail.models.memory import MemoryDecision
    from trustrail.models.output_handling import OutputHandlingResult
    from trustrail.models.poisoning import DataPoisoningResult
    from trustrail.models.resource import DecompressionResult, ResourceBudgetResult
    from trustrail.models.supply_chain import ArtifactVerificationResult
    from trustrail.models.system_prompt import (
        SystemPromptLeakageResult,
        SystemPromptValidationResult,
    )
    from trustrail.models.vector import VectorVerificationResult

from trustrail.models.enums import GuardStage, Severity


class AegisRailError(Exception):
    """Base class for all trustrail exceptions."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message)
        self.details: dict[str, Any] = kwargs


class ConfigurationError(AegisRailError):
    """Raised when the guard configuration is invalid."""

    pass


class GuardrailBlockedError(AegisRailError):
    """Raised by Guard.protect() when content is blocked.

    Contains the GuardResult for introspection.
    """

    def __init__(
        self,
        message: str = "Content blocked by guardrail",
        stage: GuardStage | None = None,
        findings: list[Any] | None = None,
        score: int = 0,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.stage = stage
        self.findings = findings or []
        self.score = score


class ArtifactVerificationError(AegisRailError):
    """Raised when an AI supply-chain artifact fails verification."""

    def __init__(self, result: ArtifactVerificationResult) -> None:
        super().__init__("AI artifact verification failed")
        self.result = result


class DataPoisoningError(AegisRailError):
    """Raised when an ingested data or model asset must be quarantined."""

    def __init__(self, result: DataPoisoningResult) -> None:
        super().__init__("Data asset failed poisoning controls and was quarantined")
        self.result = result


class GroundingVerificationError(AegisRailError):
    """Raised when claims lack support or mandatory review is incomplete."""

    def __init__(self, result: GroundingResult) -> None:
        super().__init__("Generated claims failed grounding verification")
        self.result = result


class GoalIntegrityError(AegisRailError):
    """Raised when a plan step or goal mutation is not authorized."""

    def __init__(self, result: GoalIntegrityResult) -> None:
        super().__init__("Agent goal-integrity check did not authorize the proposal")
        self.result = result


class DelegatedIdentityError(AegisRailError):
    """Raised when an agent identity or delegated privilege is not authorized."""

    def __init__(self, result: DelegatedAccessResult) -> None:
        super().__init__("Delegated agent identity was not authorized")
        self.result = result


class CodeExecutionError(AegisRailError):
    """Raised when dynamic execution is denied or its result is quarantined."""

    def __init__(
        self,
        *,
        decision: CodeExecutionDecision | None = None,
        outcome: CodeExecutionOutcome | None = None,
    ) -> None:
        super().__init__("Agent-generated execution was not verified")
        self.decision = decision
        self.outcome = outcome


class FailureContainmentError(AegisRailError):
    """Raised when dependency dispatch is denied by containment policy."""

    def __init__(self, result: FailureContainmentResult) -> None:
        super().__init__("Dependency attempt was denied by failure containment")
        self.result = result


class MemoryTaintError(AegisRailError):
    """Raised when a persistent-memory operation fails taint controls."""

    def __init__(self, result: MemoryDecision) -> None:
        super().__init__("Persistent memory operation was not authorized")
        self.result = result


class OutputHandlingError(AegisRailError):
    """Raised when model output is unsafe for its destination."""

    def __init__(self, result: OutputHandlingResult) -> None:
        super().__init__("Model output is unsafe for the requested destination")
        self.result = result


class ToolAuthorizationError(AegisRailError):
    """Raised when a tool invocation is blocked or still needs approval."""

    def __init__(self, result: ToolAuthorizationResult) -> None:
        super().__init__("Tool invocation was not authorized")
        self.result = result


class SystemPromptValidationError(AegisRailError):
    """Raised when sensitive or security-critical data enters a system prompt."""

    def __init__(self, result: SystemPromptValidationResult) -> None:
        super().__init__("System prompt failed validation")
        self.result = result


class SystemPromptLeakageError(AegisRailError):
    """Raised when generated output reproduces protected prompt material."""

    def __init__(self, result: SystemPromptLeakageResult) -> None:
        super().__init__("Generated output may disclose a system prompt")
        self.result = result


class VectorVerificationError(AegisRailError):
    """Raised when retrieved vector content fails authorization or integrity checks."""

    def __init__(self, result: VectorVerificationResult) -> None:
        super().__init__("Vector retrieval failed security verification")
        self.result = result


class ProviderError(AegisRailError):
    """Raised when an external provider (moderation, injection, etc.) fails."""

    def __init__(
        self,
        message: str,
        provider_name: str = "",
        original_error: Exception | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.provider_name = provider_name
        self.original_error = original_error


class ApprovalRequiredError(AegisRailError):
    """Raised when content requires human approval before proceeding."""

    def __init__(
        self,
        message: str = "Human approval required",
        stage: GuardStage | None = None,
        severity: Severity = Severity.HIGH,
        request_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.stage = stage
        self.severity = severity
        self.request_id = request_id


class AsyncGuardRequiredError(AegisRailError):
    """Raised when synchronous evaluation would skip configured async checks."""

    pass


class RateLimitError(AegisRailError):
    """Raised when a rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after_seconds: float | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after_seconds = retry_after_seconds


class StateBackendError(AegisRailError):
    """Raised when durable guard state cannot be read or updated safely."""

    def __init__(self, message: str, operation: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.operation = operation


class ResourceLimitError(AegisRailError):
    """Raised when a resource limit (token count, length) is exceeded."""

    pass


class ResourceBudgetError(ResourceLimitError):
    """Raised when a typed resource reservation or decompression is denied."""

    def __init__(self, result: ResourceBudgetResult | DecompressionResult) -> None:
        super().__init__("Resource consumption budget exhausted")
        self.result = result
