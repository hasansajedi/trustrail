"""Output safety rules: XSS, path traversal, shell injection, unsafe URLs."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry

# ── HTML/XSS ─────────────────────────────────────────────────────────────────

_XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\s*script[\s>]", re.IGNORECASE),
    re.compile(r"</\s*script\s*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"']", re.IGNORECASE),  # onerror=, onclick=, etc.
    re.compile(r"<\s*iframe[\s>]", re.IGNORECASE),
    re.compile(r"<\s*object[\s>]", re.IGNORECASE),
    re.compile(r"<\s*embed[\s>]", re.IGNORECASE),
    re.compile(r"<\s*form[\s>]", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"data\s*:\s*application/", re.IGNORECASE),
    re.compile(r"&#\d+;", re.IGNORECASE),  # HTML entity encoding of dangerous chars
    re.compile(r"&\w+;", re.IGNORECASE),  # Named HTML entities
    re.compile(r"expression\s*\(", re.IGNORECASE),  # CSS expression()
    re.compile(r"url\s*\(\s*[\"']?\s*javascript", re.IGNORECASE),
]


@registry.register
class HtmlInjectionRule(BaseRule):
    """Detects HTML injection and XSS in LLM output."""

    rule_id: ClassVar[str] = "OS-001"
    rule_name: ClassVar[str] = "HTML Injection / XSS"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects HTML injection and XSS in output."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _XSS_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    "HTML injection / XSS pattern detected in output",
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
        return self._allow()


# ── Path Traversal ────────────────────────────────────────────────────────────

_PATH_TRAVERSAL_RE = re.compile(
    r"(?:"
    r"\.\.[\\/]"
    r"|[\\/]\.\.[\\/]"
    r"|\.\.%2[fF]"
    r"|%2[eE]%2[eE][\\/]"
    r"|\.\.%5[cC]"
    r"|/etc/(?:passwd|shadow|hosts|sudoers|group|gshadow)"
    r"|/proc/(?:self|net|sys)"
    r"|/dev/(?:null|zero|random|urandom|mem|kmem)"
    r"|\\\\windows\\\\system32"
    r")",
    re.IGNORECASE,
)


@registry.register
class PathTraversalRule(BaseRule):
    """Detects path traversal sequences in output."""

    rule_id: ClassVar[str] = "OS-002"
    rule_name: ClassVar[str] = "Path Traversal"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects path traversal patterns in output."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _PATH_TRAVERSAL_RE.search(text)
        if m:
            return self._block(
                "Path traversal pattern detected in output",
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


# ── Shell Metacharacters ──────────────────────────────────────────────────────

_SHELL_META_RE = re.compile(
    r"""
    (?:
        \$\([^)]{0,200}\)|      # $(command)
        `[^`]{0,200}`|          # `command`
        ;\s*(?:rm|dd|curl|wget|nc|bash|sh|python|perl|ruby)\b|
        \|\s*(?:bash|sh|python|nc|netcat)\b|
        >\s*/dev/|              # redirect to /dev/
        2>&1|                   # stderr redirect
        &\s*(?:bash|sh|cmd)     # background bash
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


@registry.register
class ShellMetacharRule(BaseRule):
    """Detects shell metacharacters and injection in output."""

    rule_id: ClassVar[str] = "OS-003"
    rule_name: ClassVar[str] = "Shell Metachar Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects shell metacharacters in output."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _SHELL_META_RE.search(text)
        if m:
            return self._block(
                "Shell metacharacter injection detected in output",
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


# ── Suspicious URLs ───────────────────────────────────────────────────────────

_SUSPICIOUS_URL_RE = re.compile(
    r"""
    https?://
    (?:[^@\s/]+@)?               # embedded credentials
    (?:
        (?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)/[^\s]{0,100}|  # URL shorteners
        \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|     # raw IP
        [a-z0-9\-]{1,63}\.(?:xyz|tk|ml|ga|cf|onion)\b   # suspicious TLDs
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


@registry.register
class SuspiciousUrlRule(BaseRule):
    """Detects suspicious URLs in output (URL shorteners, raw IPs, suspicious TLDs)."""

    rule_id: ClassVar[str] = "OS-004"
    rule_name: ClassVar[str] = "Suspicious URL"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Detects suspicious URLs in output."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _SUSPICIOUS_URL_RE.search(text)
        if m:
            return self._block(
                "Suspicious URL detected in output",
                severity=Severity.MEDIUM,
                action=GuardAction.WARN,
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


# ── Unsafe Protocols ──────────────────────────────────────────────────────────

_UNSAFE_PROTO_RE = re.compile(
    r"\b(?:file|gopher|dict|ftp|ldap|ldaps|tftp|netdoc)\s*://",
    re.IGNORECASE,
)


@registry.register
class UnsafeProtocolRule(BaseRule):
    """Detects unsafe URL protocols in output."""

    rule_id: ClassVar[str] = "OS-005"
    rule_name: ClassVar[str] = "Unsafe Protocol"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects dangerous URL protocols in output."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _UNSAFE_PROTO_RE.search(text)
        if m:
            return self._block(
                f"Unsafe URL protocol detected: {m.group(0).strip()}",
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


# ── Markdown External Images ──────────────────────────────────────────────────

_MD_EXT_IMG_RE = re.compile(
    r"!\[[^\]]{0,200}\]\(https?://[^\s)]{0,500}\)",
    re.IGNORECASE,
)


@registry.register
class MarkdownExternalImageRule(BaseRule):
    """Detects external images in Markdown output (potential tracking pixels)."""

    rule_id: ClassVar[str] = "OS-006"
    rule_name: ClassVar[str] = "Markdown External Image"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.LOW
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Detects external images in Markdown (tracking pixel risk)."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _MD_EXT_IMG_RE.search(text)
        if m:
            return self._block(
                "External image in Markdown output detected",
                severity=Severity.LOW,
                action=GuardAction.WARN,
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


# ── Dangerous code constructs in generated code ───────────────────────────────
# Detect backdoor/execution patterns in Python, JavaScript, and shell code
# that the LLM may generate and that could be run without review.

_CODE_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Python execution primitives
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bimportlib\.import_module\s*\("),
    re.compile(r"\bcompile\s*\([^,]+,\s*['\"]<", re.IGNORECASE),
    # subprocess / os execution
    re.compile(r"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\s*\("),
    re.compile(r"\bos\.(?:system|popen|execv?[ep]?[lp]?)\s*\("),
    # JavaScript dangerous patterns
    re.compile(r"\bchild_process\b"),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bsetTimeout\s*\(\s*['\"]", re.IGNORECASE),
    re.compile(r"\bsetInterval\s*\(\s*['\"]", re.IGNORECASE),
    # Shell one-liners that download and execute
    re.compile(r"(?:curl|wget)\s+[^\s]+\s*\|\s*(?:bash|sh|python)", re.IGNORECASE),
    re.compile(r"\bchmod\s+\+x\s+", re.IGNORECASE),
    re.compile(r"\brm\s+-[rf]{1,2}\s+/", re.IGNORECASE),
]


# ── SQL Injection ─────────────────────────────────────────────────────────────

_SQL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"'\s*OR\s+'?\d+'?\s*=\s*'?\d+'?", re.IGNORECASE),
    re.compile(r"'\s*OR\s+'[^']+'\s*=\s*'[^']+'", re.IGNORECASE),
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
    re.compile(
        r";\s*(?:DROP|DELETE|TRUNCATE|ALTER|CREATE)\s+(?:TABLE|DATABASE|INDEX)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bINSERT\s+INTO\s+\w+\s*\([^)]{0,200}\)\s*VALUES", re.IGNORECASE),
    re.compile(r"\bEXEC(?:UTE)?\s*\(\s*['@]", re.IGNORECASE),
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
    re.compile(r"\bINFORMATION_SCHEMA\b", re.IGNORECASE),
    re.compile(r"--\s*$", re.MULTILINE),
    re.compile(r"/\*.*?\*/", re.DOTALL),
    re.compile(r"\bWAITFOR\s+DELAY\b", re.IGNORECASE),
    re.compile(r"\bSLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"\bBENCHMARK\s*\(", re.IGNORECASE),
    re.compile(r"'\s*;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.IGNORECASE),
]


@registry.register
class SqlInjectionRule(BaseRule):
    """Detects SQL injection patterns in LLM output.

    Flags classic and blind SQLi payloads including UNION SELECT, stacked
    queries, time-based injection, and comment-based bypass sequences.
    Covers OWASP LLM05 (Improper Output Handling).
    """

    rule_id: ClassVar[str] = "OS-008"
    rule_name: ClassVar[str] = "SQL Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects SQL injection patterns in LLM output."
    owasp: ClassVar[list[str]] = ["LLM05"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _SQL_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"SQL injection pattern detected: '{m.group(0)[:60]}'",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_pattern=m.group(0)[:60],
                )
        return self._allow()


# ── Server-Side Template Injection ────────────────────────────────────────────

_SSTI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\{\{[\s\S]{0,100}\}\}"),
    re.compile(r"\$\{[\s\S]{0,100}\}"),
    re.compile(r"<%=[\s\S]{0,100}%>"),
    re.compile(r"#\{[\s\S]{0,100}\}"),
    re.compile(r"\*\{[\s\S]{0,100}\}"),
    re.compile(r"@\{[\s\S]{0,100}\}"),
    re.compile(r"<#\s*(?:assign|list|if|include|import)\b", re.IGNORECASE),
    re.compile(r"#set\s*\(", re.IGNORECASE),
    re.compile(r"#(?:foreach|if|macro|parse)\s*\(", re.IGNORECASE),
    re.compile(r"\{\%[\s\S]{0,200}\%\}"),
]


@registry.register
class SstiDetectionRule(BaseRule):
    """Detects Server-Side Template Injection (SSTI) patterns in LLM output.

    Matches Jinja2, Twig, Freemarker, Velocity, ERB, and Spring SpEL expression
    syntax that could trigger remote code execution if rendered server-side.
    Covers OWASP LLM05 (Improper Output Handling).
    """

    rule_id: ClassVar[str] = "OS-009"
    rule_name: ClassVar[str] = "Server-Side Template Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects SSTI expression syntax in LLM output."
    owasp: ClassVar[list[str]] = ["LLM05"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _SSTI_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"SSTI pattern detected: '{m.group(0)[:60]}'",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_pattern=m.group(0)[:60],
                )
        return self._allow()


# ── Log Injection ─────────────────────────────────────────────────────────────

_LOG_INJECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\r\n|\r(?!\n)", re.IGNORECASE),
    re.compile(
        r"(?<!\A)(?<!\n)\s*\[(?:ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|CRITICAL|FATAL)\]",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?<!\A)(?<!\n)\s*(?:ERROR|WARN(?:ING)?|INFO|DEBUG)\s+"
        r"\d{4}-\d{2}-\d{2}",
        re.IGNORECASE,
    ),
]


@registry.register
class LogInjectionRule(BaseRule):
    """Detects log injection patterns in LLM output.

    Flags CRLF sequences and forged log-level prefixes that could allow
    attackers to inject fake entries into application logs or SIEM systems.
    Covers OWASP LLM05 (Improper Output Handling).
    """

    rule_id: ClassVar[str] = "OS-010"
    rule_name: ClassVar[str] = "Log Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Detects CRLF and forged log-level sequences in LLM output."
    owasp: ClassVar[list[str]] = ["LLM05"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _LOG_INJECT_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"Log injection pattern detected: '{repr(m.group(0))[:60]}'",
                    severity=Severity.MEDIUM,
                    action=GuardAction.WARN,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
        return self._allow()


# ── LDAP Injection ────────────────────────────────────────────────────────────

_LDAP_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\*\)\s*\((?:uid|cn|dc|ou|mail)\s*=\s*\*", re.IGNORECASE),
    re.compile(r"\)\s*\(\s*\|\s*\(", re.IGNORECASE),
    re.compile(r"\(\s*&\s*\(\s*objectClass\s*=\s*\*\s*\)", re.IGNORECASE),
    re.compile(r"\(\s*\|\s*\(objectClass\s*=\s*\*", re.IGNORECASE),
    re.compile(r"\x00"),
    re.compile(r"\bcount\s*\(", re.IGNORECASE),
    re.compile(r"\bstring-length\s*\(", re.IGNORECASE),
    re.compile(r"\btranslate\s*\(\s*@", re.IGNORECASE),
    re.compile(r"\bdoc\s*\(\s*['\"]", re.IGNORECASE),
    re.compile(r"'\s*\)\s*\(", re.IGNORECASE),
]


@registry.register
class LdapInjectionRule(BaseRule):
    """Detects LDAP/XPath injection patterns in LLM output.

    Flags LDAP filter manipulation, null-byte injection, and XPath axis
    expressions that could expose directory contents when passed unsanitised
    to LDAP or XPath processors. Covers OWASP LLM05 (Improper Output Handling).
    """

    rule_id: ClassVar[str] = "OS-011"
    rule_name: ClassVar[str] = "LDAP Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects LDAP injection patterns in LLM output."
    owasp: ClassVar[list[str]] = ["LLM05"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _LDAP_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"LDAP injection pattern detected: '{repr(m.group(0))[:60]}'",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
        return self._allow()


# ── XML / XPath Injection ────────────────────────────────────────────────────

_XPATH_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"'\s*or\s+'[^']*'\s*=\s*'[^']*'", re.IGNORECASE),
    re.compile(r'"\s*or\s+"[^"]*"\s*=\s*"[^"]*"', re.IGNORECASE),
    re.compile(r"'\s*\]\s*\|", re.IGNORECASE),
    re.compile(r"\bstring\s*\(\s*//", re.IGNORECASE),
    re.compile(r"//@\w+", re.IGNORECASE),
    re.compile(r"\bdoc\s*\(\s*['\"]", re.IGNORECASE),
    re.compile(r"\bcount\s*\(\s*//", re.IGNORECASE),
    re.compile(r"position\s*\(\s*\)\s*=", re.IGNORECASE),
    re.compile(r"<!DOCTYPE\s+\w+\s+SYSTEM", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)", re.IGNORECASE),
]


@registry.register
class XmlXpathInjectionRule(BaseRule):
    """Detects XML/XPath injection and XXE patterns in LLM output.

    Covers XPath boolean-based injection (``' or 'a'='a``), XXE attacks using
    ``DOCTYPE``/``ENTITY`` declarations, and XPath axis traversal. Complements
    input-side checks for XML payloads passed through to downstream parsers.
    Addresses OWASP LLM02 (Insecure Output Handling) and LLM05.
    """

    rule_id: ClassVar[str] = "OS-012"
    rule_name: ClassVar[str] = "XML/XPath Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects XML/XPath injection and XXE patterns in LLM output."
    owasp: ClassVar[list[str]] = ["LLM02", "LLM05"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _XPATH_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"XML/XPath injection pattern detected: '{m.group(0)[:60]}'",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_pattern=m.group(0)[:60],
                )
        return self._allow()


@registry.register
class DangerousCodeConstructRule(BaseRule):
    """Detects dangerous code constructs in LLM-generated output.

    Flags Python execution primitives (``eval``, ``exec``, ``__import__``,
    ``subprocess``), JavaScript dynamic execution (``child_process``,
    ``new Function``), and shell download-and-execute patterns. Code containing
    these constructs should be reviewed before execution.
    """

    rule_id: ClassVar[str] = "OS-007"
    rule_name: ClassVar[str] = "Dangerous Code Construct"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = (
        "Detects dangerous code constructs (eval, exec, subprocess) in generated code."
    )
    owasp: ClassVar[list[str]] = ["LLM02", "LLM08"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _CODE_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"Dangerous code construct detected: '{m.group(0)[:60]}'",
                    action=GuardAction.WARN,
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_construct=m.group(0)[:60],
                )
        return self._allow()


# ── Insecure File Path / Path Injection ──────────────────────────────────────

_FILE_PATH_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:file|php|zlib|glob|phar|expect|data)://", re.IGNORECASE),
    re.compile(r"/proc/self/(?:environ|cmdline|fd)", re.IGNORECASE),
    re.compile(r"(?:c:|d:)\\(?:windows|users|program\s*files)", re.IGNORECASE),
    re.compile(r"/etc/(?:shadow|group|sudoers|crontab)", re.IGNORECASE),
    re.compile(r"\\\\[a-zA-Z0-9._-]+\\[a-zA-Z$][a-zA-Z0-9._-]*", re.IGNORECASE),
    re.compile(r"%2e%2e%2f|%2e%2e/|\.\./.*(?:etc|windows|boot)", re.IGNORECASE),
]


@registry.register
class FilePathInjectionRule(BaseRule):
    """Detects insecure file path references and wrapper URI schemes in LLM output.

    Catches wrapper URI schemes (``file://``, ``php://``, ``phar://``), absolute
    OS paths to sensitive system files (``/proc/self/environ``,
    ``/etc/shadow``), Windows drive paths, and UNC paths. Complements the
    input-side ``PathTraversalRule`` by covering output-context leakage.
    Addresses OWASP LLM02 (Insecure Output Handling) and LLM05.
    """

    rule_id: ClassVar[str] = "OS-013"
    rule_name: ClassVar[str] = "Insecure File Path Injection"
    category: ClassVar[RuleCategory] = RuleCategory.OUTPUT_SAFETY
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects insecure file path references and wrapper URI schemes in LLM output."
    )
    owasp: ClassVar[list[str]] = ["LLM02", "LLM05"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in _FILE_PATH_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"Insecure file path pattern detected: '{m.group(0)[:60]}'",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_pattern=m.group(0)[:60],
                )
        return self._allow()
