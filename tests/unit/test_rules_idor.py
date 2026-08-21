"""Tests for TL-004 IdorDetectionRule."""

import pytest

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.tools.tool_rules import IdorDetectionRule


def _ctx(tool_args: dict) -> GuardContext:
    return GuardContext(
        stage=GuardStage.TOOL_REQUEST,
        metadata={"tool_args": tool_args},
    )


class TestIdorDetectionRule:
    def test_detects_numeric_user_id(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"user_id": "1337"}))
        assert result.action == GuardAction.BLOCK

    def test_detects_integer_user_id(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"user_id": 99999}))
        assert result.action == GuardAction.BLOCK

    def test_detects_numeric_account_id(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"account_id": "10000"}))
        assert result.action == GuardAction.BLOCK

    def test_detects_rest_path_with_id(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"endpoint": "/api/v1/users/99999/profile"}))
        assert result.action == GuardAction.BLOCK

    def test_detects_admin_path(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"path": "/admin/users/list"}))
        assert result.action == GuardAction.BLOCK

    def test_detects_traversal_in_document_id(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"document_id": "../../../admin/secrets"}))
        assert result.action == GuardAction.BLOCK

    def test_allows_safe_string_user_id(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"user_id": "abc-def-123"}))
        assert result.action == GuardAction.ALLOW

    def test_allows_non_sensitive_key_with_number(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"quantity": "5000", "page": "100"}))
        assert result.action == GuardAction.ALLOW

    def test_allows_normal_api_path(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"endpoint": "/api/v1/products/search"}))
        assert result.action == GuardAction.ALLOW

    def test_allows_empty_args(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({}))
        assert result.action == GuardAction.ALLOW

    def test_finding_includes_idor_field(self):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({"user_id": "1337"}))
        assert result.finding is not None
        assert result.finding.metadata.get("idor_field") == "user_id"

    @pytest.mark.parametrize(
        "key",
        ["user_id", "account_id", "customer_id", "owner_id", "record_id", "document_id"],
    )
    def test_detects_numeric_in_all_sensitive_keys(self, key: str):
        rule = IdorDetectionRule()
        result = rule.evaluate("", _ctx({key: "12345"}))
        assert result.action == GuardAction.BLOCK
