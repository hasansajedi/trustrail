"""Coverage and privacy regressions for OWASP LLM05 output rules."""

from __future__ import annotations

import pytest

from trustrail import GuardAction, GuardContext, GuardStage
from trustrail.rules.output import (
    DangerousCodeConstructRule,
    FilePathInjectionRule,
    HtmlInjectionRule,
    LdapInjectionRule,
    LogInjectionRule,
    MarkdownExternalImageRule,
    PathTraversalRule,
    ShellMetacharRule,
    SqlInjectionRule,
    SstiDetectionRule,
    SuspiciousUrlRule,
    UnsafeProtocolRule,
    XmlXpathInjectionRule,
)


def _context() -> GuardContext:
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


@pytest.mark.parametrize(
    ("rule", "value"),
    [
        (HtmlInjectionRule(), "<script>private_output_marker</script>"),
        (PathTraversalRule(), "../private_output_marker"),
        (ShellMetacharRule(), "$(private_output_marker)"),
        (SuspiciousUrlRule(), "https://private-output-marker.xyz/path"),
        (UnsafeProtocolRule(), "file://private_output_marker"),
        (
            MarkdownExternalImageRule(),
            "![private_output_marker](https://example.test/pixel)",
        ),
        (DangerousCodeConstructRule(), "eval(private_output_marker)"),
        (SqlInjectionRule(), "x' UNION SELECT private_output_marker"),
        (SstiDetectionRule(), "{{ private_output_marker }}"),
        (LogInjectionRule(), "safe\r\n[ERROR] private_output_marker"),
        (LdapInjectionRule(), "*)(uid=*) private_output_marker"),
        (
            XmlXpathInjectionRule(),
            "<!DOCTYPE private SYSTEM 'file://private_output_marker'>",
        ),
        (FilePathInjectionRule(), "php://private_output_marker"),
    ],
)
def test_output_rule_finding_is_content_free_and_mapped(rule, value: str):
    decision = rule.evaluate(value, _context())

    assert decision.action != GuardAction.ALLOW
    assert decision.finding is not None
    serialized = decision.finding.model_dump_json()
    assert value not in serialized
    assert "private_output_marker" not in serialized
    assert decision.finding.metadata == {}
    assert decision.finding.owasp == ["LLM05:2025"]


def test_html_rule_scans_beyond_old_fifty_thousand_character_boundary():
    value = "a" * 60_000 + "<script>alert(1)</script>"

    decision = HtmlInjectionRule().evaluate(value, _context())

    assert decision.action == GuardAction.BLOCK


def test_sql_detector_allows_benign_explanatory_text():
    decision = SqlInjectionRule().evaluate(
        "Use a prepared statement and bind the user identifier as a parameter.",
        _context(),
    )

    assert decision.action == GuardAction.ALLOW
