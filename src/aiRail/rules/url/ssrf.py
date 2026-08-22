"""URL/SSRF protection rules."""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar
from urllib.parse import urlparse

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry

# ── Pre-compiled regexes ──────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"(?:https?|ftp|file|gopher|dict|ldap|sftp|ssh|telnet|smtp|pop3|imap)"
    r"://[^\s\"'<>{}|\\^`\[\]]{1,2000}",
    re.IGNORECASE,
)

_BLOCKED_SCHEMES = frozenset(
    ["file", "gopher", "dict", "ftp", "ldap", "ldaps", "tftp", "netdoc", "jar"]
)

# Private IP ranges
_PRIVATE_NETWORKS_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local (APIPA)
    ipaddress.IPv4Network("127.0.0.0/8"),  # Loopback
    ipaddress.IPv4Network("0.0.0.0/8"),  # "This" network
    ipaddress.IPv4Network("100.64.0.0/10"),  # Shared address space
    ipaddress.IPv4Network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.IPv4Network("198.18.0.0/15"),  # Benchmarking
    ipaddress.IPv4Network("240.0.0.0/4"),  # Reserved
]

_LOOPBACK_V6 = ipaddress.IPv6Address("::1")
_LINK_LOCAL_V6 = ipaddress.IPv6Network("fe80::/10")
_ULA_V6 = ipaddress.IPv6Network("fc00::/7")

# AWS metadata service
_METADATA_HOSTS = frozenset(
    [
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "169.254.170.2",  # AWS ECS metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
    ]
)

_METADATA_PATHS = re.compile(
    r"/(?:latest/meta-data|computeMetadata/v1|metadata/instance)",
    re.IGNORECASE,
)

# Embedded credentials in URL
_EMBEDDED_CRED_RE = re.compile(
    r"https?://[^:@\s]{1,100}:[^@\s]{1,200}@",
    re.IGNORECASE,
)

# Localhost patterns
_LOCALHOST_RE = re.compile(r"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|0:0:0:0:0:0:0:1)\b")


def _is_private_ip(host: str) -> bool:
    """Check if a host is a private/reserved IP address."""
    host = host.strip("[]")  # IPv6 bracket notation

    # Strip port from IPv4 (e.g., "127.0.0.1:8080")
    # Don't strip from IPv6 (colons are part of the address)
    if ":" in host:
        # Try parsing as IPv6 first
        try:
            ipaddress.IPv6Address(host)
            # Valid IPv6 — no port stripping needed
        except ValueError:
            # Might be host:port for IPv4
            parts = host.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host = parts[0]

    try:
        addr_v4 = ipaddress.IPv4Address(host)
        return any(addr_v4 in net for net in _PRIVATE_NETWORKS_V4)
    except ValueError:
        pass

    try:
        addr_v6 = ipaddress.IPv6Address(host)
        return (
            addr_v6 == _LOOPBACK_V6
            or addr_v6.is_loopback
            or addr_v6.is_link_local
            or addr_v6.is_private
            or addr_v6 in _LINK_LOCAL_V6
            or addr_v6 in _ULA_V6
        )
    except ValueError:
        pass

    return False


def _extract_host(url: str) -> str | None:
    """Extract the host from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or parsed.netloc.split(":")[0] or None
    except Exception:
        return None


@registry.register
class SchemeValidationRule(BaseRule):
    """Blocks dangerous URL schemes (file://, gopher://, etc.)."""

    rule_id: ClassVar[str] = "URL-001"
    rule_name: ClassVar[str] = "URL Scheme Validation"
    category: ClassVar[RuleCategory] = RuleCategory.URL_SSRF
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Blocks dangerous URL schemes."

    def __init__(
        self,
        blocked_schemes: frozenset[str] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.blocked_schemes = blocked_schemes if blocked_schemes is not None else _BLOCKED_SCHEMES

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            try:
                scheme = urlparse(url).scheme.lower()
                if scheme in self.blocked_schemes:
                    return self._block(
                        f"Dangerous URL scheme detected: {scheme}://",
                        offset_start=m.start(),
                        offset_end=m.end(),
                        scheme=scheme,
                    )
            except Exception:  # noqa: S112
                continue
        return self._allow()


@registry.register
class PrivateIpRule(BaseRule):
    """Detects URLs pointing to private/reserved IP ranges (SSRF prevention)."""

    rule_id: ClassVar[str] = "URL-002"
    rule_name: ClassVar[str] = "Private IP SSRF"
    category: ClassVar[RuleCategory] = RuleCategory.URL_SSRF
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects URLs targeting private/reserved IP addresses."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            host = _extract_host(url)
            if host is None:
                continue

            # Localhost check
            if _LOCALHOST_RE.fullmatch(host):
                return self._block(
                    f"SSRF: URL targets localhost: {host}",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    host=host,
                )

            if _is_private_ip(host):
                return self._block(
                    f"SSRF: URL targets private IP range: {host}",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    host=host,
                )

        return self._allow()


@registry.register
class MetadataServiceRule(BaseRule):
    """Detects requests to cloud metadata service endpoints."""

    rule_id: ClassVar[str] = "URL-003"
    rule_name: ClassVar[str] = "Metadata Service SSRF"
    category: ClassVar[RuleCategory] = RuleCategory.URL_SSRF
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects requests to cloud metadata service endpoints."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            host = _extract_host(url)
            if host and host in _METADATA_HOSTS:
                return self._block(
                    f"SSRF: URL targets cloud metadata service: {host}",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    host=host,
                )

            # Check for metadata path patterns
            if _METADATA_PATHS.search(url):
                return self._block(
                    "SSRF: URL path matches metadata service pattern",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )

        return self._allow()


@registry.register
class EmbeddedCredentialRule(BaseRule):
    """Detects embedded credentials in URLs (user:pass@host)."""

    rule_id: ClassVar[str] = "URL-004"
    rule_name: ClassVar[str] = "URL Embedded Credentials"
    category: ClassVar[RuleCategory] = RuleCategory.URL_SSRF
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects URLs with embedded credentials."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        m = _EMBEDDED_CRED_RE.search(text)
        if m:
            return self._block(
                "URL with embedded credentials detected",
                offset_start=m.start(),
                offset_end=m.end(),
            )
        return self._allow()


@registry.register
class UrlDomainRule(BaseRule):
    """Validates URLs against domain allowlist/blocklist."""

    rule_id: ClassVar[str] = "URL-005"
    rule_name: ClassVar[str] = "URL Domain Validation"
    category: ClassVar[RuleCategory] = RuleCategory.URL_SSRF
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Validates URL domains against allow/blocklists."

    def __init__(
        self,
        allowlist: list[str] | None = None,
        blocklist: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.allowlist = {d.lower() for d in allowlist} if allowlist else None
        self.blocklist = {d.lower() for d in blocklist} if blocklist else None

    def _domain_allowed(self, host: str) -> bool:
        """Check if host is in allowlist (supports subdomain matching)."""
        if self.allowlist is None:
            return True
        host = host.lower()
        if host in self.allowlist:
            return True
        # Check if it's a subdomain of an allowed domain
        return any(host.endswith(f".{allowed}") for allowed in self.allowlist)

    def _domain_blocked(self, host: str) -> bool:
        """Check if host is in blocklist."""
        if self.blocklist is None:
            return False
        host = host.lower()
        return host in self.blocklist or any(
            host.endswith(f".{blocked}") for blocked in self.blocklist
        )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            host = _extract_host(url)
            if host is None:
                continue

            if self._domain_blocked(host):
                return self._block(
                    f"URL domain '{host}' is in the blocklist",
                    offset_start=m.start(),
                    offset_end=m.end(),
                    host=host,
                )

            if not self._domain_allowed(host):
                return self._block(
                    f"URL domain '{host}' is not in the allowlist",
                    offset_start=m.start(),
                    offset_end=m.end(),
                    host=host,
                )

        return self._allow()
