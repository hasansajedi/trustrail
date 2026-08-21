"""aiRail exception hierarchy."""

from __future__ import annotations

from typing import Any

from aiRail.models.enums import GuardStage, Severity


class AegisRailError(Exception):
    """Base class for all aiRail exceptions."""

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


class ResourceLimitError(AegisRailError):
    """Raised when a resource limit (token count, length) is exceeded."""

    pass
