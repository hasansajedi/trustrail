"""trustrail — Production-grade Python library for GenAI/LLM guardrails.

Quick start:

    from trustrail import Guard, GuardStage

    guard = Guard.balanced()
    result = guard.check("Hello, world!", GuardStage.USER_INPUT)
    print(result.action)  # GuardAction.ALLOW
"""

from importlib.metadata import PackageNotFoundError, version

from trustrail.audit import LoggingAuditSink, MemoryAuditSink, NullAuditSink
from trustrail.exceptions import (
    AegisRailError,
    ApprovalRequiredError,
    ArtifactVerificationError,
    ConfigurationError,
    DataPoisoningError,
    GuardrailBlockedError,
    ProviderError,
    RateLimitError,
    ResourceLimitError,
)
from trustrail.guard import Guard
from trustrail.models.config import GuardConfig, GuardPolicy, RuleConfig
from trustrail.models.core import (
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
from trustrail.models.enums import (
    FailMode,
    GuardAction,
    GuardStage,
    MemoryWriteClassification,
    OutputContext,
    RuleCategory,
    RulePhase,
    SensitiveDataMode,
    Severity,
    TrustLevel,
)
from trustrail.models.poisoning import (
    DataAssetKind,
    DataIngestionRecord,
    DataPoisoningPolicy,
    DataPoisoningResult,
    DataProvenance,
    DataSourcePolicy,
    DataTransformation,
    IngestionAuthorization,
    PoisoningCode,
    PoisoningFinding,
)
from trustrail.models.prompt import (
    PromptScanResult,
    PromptSegment,
    PromptSegmentResult,
    PromptSource,
)
from trustrail.models.rag import ProvenanceLabel, RAGContextEnvelope, RAGContextSegment
from trustrail.models.sensitive_data import ProtectedData
from trustrail.models.supply_chain import (
    ArtifactDigest,
    ArtifactKind,
    ArtifactManifest,
    ArtifactObservation,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactVerificationCode,
    ArtifactVerificationFinding,
    ArtifactVerificationPolicy,
    ArtifactVerificationResult,
    DigestAlgorithm,
)
from trustrail.poisoning import DataPoisoningVerifier, PoisoningDetector
from trustrail.protocols import (
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
from trustrail.supply_chain import ArtifactVerifier

try:
    __version__ = version("trustrail")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
__all__ = [
    # Exceptions
    "AegisRailError",
    "ApprovalProvider",
    "ApprovalRequiredError",
    "ArtifactDigest",
    "ArtifactKind",
    "ArtifactManifest",
    "ArtifactObservation",
    "ArtifactRecord",
    "ArtifactStatus",
    "ArtifactVerificationCode",
    "ArtifactVerificationError",
    "ArtifactVerificationFinding",
    "ArtifactVerificationPolicy",
    "ArtifactVerificationResult",
    "ArtifactVerifier",
    "AsyncGuardRule",
    # Data models
    "AuditEvent",
    "AuditSink",
    "ConfigurationError",
    "ContentSafetyProvider",
    "DataAssetKind",
    "DataIngestionRecord",
    "DataPoisoningError",
    "DataPoisoningPolicy",
    "DataPoisoningResult",
    "DataPoisoningVerifier",
    "DataProvenance",
    "DataSourcePolicy",
    "DataTransformation",
    "DigestAlgorithm",
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
    "IngestionAuthorization",
    # Audit sinks
    "LoggingAuditSink",
    "MemoryAuditSink",
    "MemoryWriteClassification",
    "Message",
    "NullAuditSink",
    "OutputContext",
    "PoisoningCode",
    "PoisoningDetector",
    "PoisoningFinding",
    "PromptInjectionProvider",
    "PromptScanResult",
    "PromptSegment",
    "PromptSegmentResult",
    "PromptSource",
    "ProtectedData",
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
    "SensitiveDataMode",
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
