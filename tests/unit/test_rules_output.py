"""Unit tests for output safety rules."""

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.output.safety import (
    HtmlInjectionRule,
    MarkdownExternalImageRule,
    PathTraversalRule,
    ShellMetacharRule,
    SuspiciousUrlRule,
    UnsafeProtocolRule,
    XmlXpathInjectionRule,
)


def ctx():
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


class TestHtmlInjectionRule:
    def setup_method(self):
        self.rule = HtmlInjectionRule()

    def test_detects_script_tag(self):
        d = self.rule.evaluate("<script>alert('xss')</script>", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_javascript_protocol(self):
        d = self.rule.evaluate('<a href="javascript:void(0)">click</a>', ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_event_handler(self):
        d = self.rule.evaluate('<img src="x" onerror="alert(1)">', ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_iframe(self):
        d = self.rule.evaluate('<iframe src="https://evil.com"></iframe>', ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_safe_html(self):
        d = self.rule.evaluate("The answer is 42.", ctx())
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "OS-001"


class TestPathTraversalRule:
    def setup_method(self):
        self.rule = PathTraversalRule()

    def test_detects_dotdot_slash(self):
        d = self.rule.evaluate("Read file at ../../../etc/passwd", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_etc_passwd(self):
        d = self.rule.evaluate("Contents of /etc/passwd:", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_url_encoded(self):
        d = self.rule.evaluate("path: ..%2F..%2Fetc%2Fpasswd", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_safe_path(self):
        d = self.rule.evaluate("The file is at /home/user/documents/report.pdf", ctx())
        assert d.action == GuardAction.ALLOW


class TestShellMetacharRule:
    def setup_method(self):
        self.rule = ShellMetacharRule()

    def test_detects_command_substitution(self):
        d = self.rule.evaluate("Run: $(rm -rf /)", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_backtick_exec(self):
        d = self.rule.evaluate("Output: `cat /etc/passwd`", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_semicolon_rm(self):
        d = self.rule.evaluate("command; rm -rf /tmp/data", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_safe_text(self):
        d = self.rule.evaluate("Run the program with --flag=value", ctx())
        assert d.action == GuardAction.ALLOW


class TestUnsafeProtocolRule:
    def setup_method(self):
        self.rule = UnsafeProtocolRule()

    def test_detects_file_protocol(self):
        d = self.rule.evaluate("Open file://etc/passwd", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_gopher(self):
        d = self.rule.evaluate("Connect to gopher://evil.com", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_https(self):
        d = self.rule.evaluate("Visit https://example.com", ctx())
        assert d.action == GuardAction.ALLOW


class TestSuspiciousUrlRule:
    def setup_method(self):
        self.rule = SuspiciousUrlRule()

    def test_detects_url_shortener(self):
        d = self.rule.evaluate("Click here: https://bit.ly/3xYZ123", ctx())
        assert d.action == GuardAction.WARN

    def test_detects_raw_ip(self):
        d = self.rule.evaluate("Visit https://1.2.3.4/malware", ctx())
        assert d.action == GuardAction.WARN

    def test_allows_reputable_domain(self):
        d = self.rule.evaluate("Documentation at https://docs.python.org/3/", ctx())
        assert d.action == GuardAction.ALLOW


class TestMarkdownExternalImageRule:
    def setup_method(self):
        self.rule = MarkdownExternalImageRule()

    def test_detects_external_image(self):
        d = self.rule.evaluate("![tracker](https://evil.com/pixel.png)", ctx())
        assert d.action == GuardAction.WARN

    def test_allows_plain_text(self):
        d = self.rule.evaluate("Here is my answer.", ctx())
        assert d.action == GuardAction.ALLOW


class TestXmlXpathInjectionRule:
    def setup_method(self):
        self.rule = XmlXpathInjectionRule()

    def test_detects_xpath_boolean_injection(self):
        d = self.rule.evaluate("' or 'a'='a'", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_xxe_doctype(self):
        d = self.rule.evaluate("<!DOCTYPE foo SYSTEM 'file:///etc/passwd'>", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_xxe_entity(self):
        d = self.rule.evaluate("<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_xpath_axis_traversal(self):
        d = self.rule.evaluate("string(//password)", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_plain_xml(self):
        d = self.rule.evaluate("<user><name>Alice</name></user>", ctx())
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "OS-012"


class TestFilePathInjectionRule:
    def setup_method(self):
        from aiRail.rules.output.safety import FilePathInjectionRule

        self.rule = FilePathInjectionRule()

    def test_detects_file_wrapper(self):
        d = self.rule.evaluate("Read file://etc/passwd", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_php_wrapper(self):
        d = self.rule.evaluate("Include php://input for data", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_proc_self_environ(self):
        d = self.rule.evaluate("Check /proc/self/environ for secrets", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_etc_shadow(self):
        d = self.rule.evaluate("Contents from /etc/shadow", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_windows_drive(self):
        d = self.rule.evaluate("Path: c:\\windows\\system32\\config", ctx())
        assert d.action == GuardAction.BLOCK

    def test_allows_safe_path(self):
        d = self.rule.evaluate("Save to /home/user/documents/report.pdf", ctx())
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "OS-013"
