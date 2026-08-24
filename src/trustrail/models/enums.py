"""trustrail enumeration types."""

from enum import StrEnum


class GuardStage(StrEnum):
    """Stage in the LLM pipeline where a guard check is applied."""

    USER_INPUT = "user_input"
    SYSTEM_PROMPT = "system_prompt"
    EXTERNAL_CONTENT = "external_content"
    RAG_DOCUMENT = "rag_document"
    RAG_CONTEXT = "rag_context"
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"
    TOOL_REQUEST = "tool_request"
    TOOL_RESPONSE = "tool_response"
    AGENT_ACTION = "agent_action"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    STREAM = "stream"
    FINAL_OUTPUT = "final_output"


class GuardAction(StrEnum):
    """Action taken by the guard engine after evaluation."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    TRANSFORM = "transform"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"
    RETRY = "retry"


class SensitiveDataMode(StrEnum):
    """How detected sensitive data is handled by the guard engine."""

    DEFAULT = "default"
    REDACT = "redact"
    BLOCK = "block"
    ALLOW = "allow"


class Severity(StrEnum):
    """Severity level of a finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(StrEnum):
    """Trust level for content sources."""

    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"


class MemoryWriteClassification(StrEnum):
    """Security classification assigned to a proposed memory write."""

    GENERAL = "general"
    PREFERENCE = "preference"
    PROFILE = "profile"
    INSTRUCTION = "instruction"
    SENSITIVE = "sensitive"


class FailMode(StrEnum):
    """Behavior when a provider or rule fails."""

    OPEN = "open"  # Allow on failure with warning
    CLOSED = "closed"  # Block on failure


class RuleCategory(StrEnum):
    """Category of a guard rule."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_DATA = "sensitive_data"
    SECRET = "secret"  # noqa: S105
    OUTPUT_SAFETY = "output_safety"
    URL_SSRF = "url_ssrf"
    RAG = "rag"
    TOOL = "tool"
    AGENT = "agent"
    RESOURCE = "resource"
    CONTENT_SAFETY = "content_safety"
    FAIRNESS = "fairness"
    GROUNDING = "grounding"
    MEMORY = "memory"


class RulePhase(StrEnum):
    """Evaluation phase within the guard pipeline."""

    NORMALIZE = "normalize"
    VALIDATE = "validate"
    DETECT = "detect"
    POLICY = "policy"
    TRANSFORM = "transform"
    FINAL_VALIDATE = "final_validate"
    AUDIT = "audit"


class OutputContext(StrEnum):
    """Context in which LLM output will be rendered."""

    TEXT = "text"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    URL = "url"
    PATH = "path"
    SQL = "sql"
    SHELL = "shell"
    CODE = "code"
