"""aiRail — Production-grade Python library for GenAI/LLM guardrails.

Quick start:

    from aiRail import Guard, GuardStage

    guard = Guard.balanced()
    result = guard.check("Hello, world!", GuardStage.USER_INPUT)
    print(result.action)  # GuardAction.ALLOW
"""

from importlib.metadata import PackageNotFoundError, version

from aiRail.audit import LoggingAuditSink, MemoryAuditSink, NullAuditSink
from aiRail.exceptions import (
    AegisRailError,
    ApprovalRequiredError,
    ConfigurationError,
    GuardrailBlockedError,
    ProviderError,
    RateLimitError,
    ResourceLimitError,
)
from aiRail.guard import Guard
from aiRail.models.config import GuardConfig, GuardPolicy, RuleConfig
from aiRail.models.core import (
    AuditEvent,
    Document,
    GuardContext,
    GuardDecision,
    GuardFinding,
    GuardResult,
    Message,
    RiskScore,
    ToolCall,
    ToolResult,
)
from aiRail.models.enums import (
    FailMode,
    GuardAction,
    GuardStage,
    MemoryWriteClassification,
    OutputContext,
    RuleCategory,
    RulePhase,
    Severity,
    TrustLevel,
)
from aiRail.models.rag import ProvenanceLabel, RAGContextEnvelope, RAGContextSegment
from aiRail.protocols import (
    ApprovalProvider,
    AsyncGuardRule,
    AuditSink,
    ContentSafetyProvider,
    GroundingVerifier,
    GuardRule,
    PromptInjectionProvider,
    SensitiveDataProvider,
    StateBackend,
    TokenCounter,
)

try:
    __version__ = version("aiRail")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
__all__ = [
    # Exceptions
    "AegisRailError",
    "ApprovalProvider",
    "ApprovalRequiredError",
    "AsyncGuardRule",
    # Data models
    "AuditEvent",
    "AuditSink",
    "ConfigurationError",
    "ContentSafetyProvider",
    "Document",
    "FailMode",
    "GroundingVerifier",
    # Core
    "Guard",
    "GuardAction",
    "GuardConfig",
    # Context / results
    "GuardContext",
    "GuardDecision",
    "GuardFinding",
    "GuardPolicy",
    "GuardResult",
    # Protocols
    "GuardRule",
    # Enums
    "GuardStage",
    "GuardrailBlockedError",
    # Audit sinks
    "LoggingAuditSink",
    "MemoryAuditSink",
    "MemoryWriteClassification",
    "Message",
    "NullAuditSink",
    "OutputContext",
    "PromptInjectionProvider",
    "ProvenanceLabel",
    "ProviderError",
    "RAGContextEnvelope",
    "RAGContextSegment",
    "RateLimitError",
    "ResourceLimitError",
    "RiskScore",
    "RuleCategory",
    "RuleConfig",
    "RulePhase",
    "SensitiveDataProvider",
    "Severity",
    "StateBackend",
    "TokenCounter",
    "ToolCall",
    "ToolResult",
    "TrustLevel",
    # Version
    "__version__",
]
