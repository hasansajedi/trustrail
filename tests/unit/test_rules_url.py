"""Unit tests for URL/SSRF rules."""

from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction, GuardStage
from trustrail.rules.url.ssrf import (
    EmbeddedCredentialRule,
    MetadataServiceRule,
    PrivateIpRule,
    SchemeValidationRule,
    UrlDomainRule,
    _is_private_ip,
)


def ctx():
    return GuardContext(stage=GuardStage.USER_INPUT)


class TestPrivateIpDetection:
    def test_rfc1918_10(self):
        assert _is_private_ip("10.0.0.1")

    def test_rfc1918_172(self):
        assert _is_private_ip("172.16.0.1")
        assert _is_private_ip("172.31.255.255")

    def test_rfc1918_192(self):
        assert _is_private_ip("192.168.1.1")

    def test_link_local(self):
        assert _is_private_ip("169.254.169.254")

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1")

    def test_public_ip_not_private(self):
        assert not _is_private_ip("8.8.8.8")
        assert not _is_private_ip("1.1.1.1")

    def test_ipv6_loopback(self):
        assert _is_private_ip("::1")


class TestSchemeValidationRule:
    def setup_method(self):
        self.rule = SchemeValidationRule()

    def test_blocks_file_scheme(self):
        d = self.rule.evaluate("Use file:///etc/passwd", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_gopher(self):
        d = self.rule.evaluate("gopher://evil.com:70/1payload", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_ftp(self):
        d = self.rule.evaluate("ftp://files.example.com/data", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_https(self):
        d = self.rule.evaluate("https://example.com/page", ctx())
        assert d.action == GuardAction.ALLOW

    def test_allows_http(self):
        d = self.rule.evaluate("http://example.com/page", ctx())
        assert d.action == GuardAction.ALLOW


class TestPrivateIpRule:
    def setup_method(self):
        self.rule = PrivateIpRule()

    def test_blocks_aws_metadata(self):
        d = self.rule.evaluate("http://169.254.169.254/latest/meta-data/", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_internal_ip(self):
        d = self.rule.evaluate("http://10.0.0.1/admin", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_localhost(self):
        d = self.rule.evaluate("http://localhost/admin", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_127(self):
        d = self.rule.evaluate("http://127.0.0.1:8080/", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_public_ip(self):
        d = self.rule.evaluate("http://8.8.8.8/dns", ctx())
        assert d.action == GuardAction.ALLOW

    def test_allows_public_domain(self):
        d = self.rule.evaluate("https://example.com/api", ctx())
        assert d.action == GuardAction.ALLOW


class TestMetadataServiceRule:
    def setup_method(self):
        self.rule = MetadataServiceRule()

    def test_blocks_aws_metadata(self):
        d = self.rule.evaluate("http://169.254.169.254/latest/meta-data/", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_gcp_metadata(self):
        d = self.rule.evaluate("http://metadata.google.internal/computeMetadata/v1/", ctx())
        assert d.action == GuardAction.BLOCK

    def test_blocks_metadata_path(self):
        d = self.rule.evaluate(
            "http://internal.example.com/latest/meta-data/iam/security-credentials/", ctx()
        )
        assert d.action == GuardAction.BLOCK

    def test_allows_normal_url(self):
        d = self.rule.evaluate("https://api.example.com/v1/users", ctx())
        assert d.action == GuardAction.ALLOW


class TestEmbeddedCredentialRule:
    def setup_method(self):
        self.rule = EmbeddedCredentialRule()

    def test_detects_user_pass_in_url(self):
        d = self.rule.evaluate("http://user:password@example.com/", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_url_without_credentials(self):
        d = self.rule.evaluate("https://example.com/page", ctx())
        assert d.action == GuardAction.ALLOW


class TestUrlDomainRule:
    def test_blocklist(self):
        rule = UrlDomainRule(blocklist=["evil.com"])
        d = rule.evaluate("https://evil.com/malware", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allowlist_blocks_unknown(self):
        rule = UrlDomainRule(allowlist=["example.com"])
        d = rule.evaluate("https://unknown.com/api", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allowlist_permits_known(self):
        rule = UrlDomainRule(allowlist=["example.com"])
        d = rule.evaluate("https://example.com/api", ctx())
        assert d.action == GuardAction.ALLOW

    def test_allowlist_permits_subdomain(self):
        rule = UrlDomainRule(allowlist=["example.com"])
        d = rule.evaluate("https://api.example.com/v1", ctx())
        assert d.action == GuardAction.ALLOW

    def test_blocklist_blocks_subdomain(self):
        rule = UrlDomainRule(blocklist=["evil.com"])
        d = rule.evaluate("https://sub.evil.com/page", ctx())
        assert d.action == GuardAction.BLOCK
