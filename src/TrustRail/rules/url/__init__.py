"""URL and SSRF protection rules."""

from aiRail.rules.url.ssrf import (
    EmbeddedCredentialRule,
    MetadataServiceRule,
    PrivateIpRule,
    SchemeValidationRule,
    UrlDomainRule,
)

__all__ = [
    "EmbeddedCredentialRule",
    "MetadataServiceRule",
    "PrivateIpRule",
    "SchemeValidationRule",
    "UrlDomainRule",
]
