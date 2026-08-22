"""URL and SSRF protection rules."""

from trustrail.rules.url.ssrf import (
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
