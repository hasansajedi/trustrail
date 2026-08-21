"""Tests for RL-006 NestingDepthRule."""

import json

import pytest

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.resource.limits import NestingDepthRule


def _ctx() -> GuardContext:
    return GuardContext(stage=GuardStage.USER_INPUT)


def _make_json_bomb(depth: int) -> str:
    """Build a deeply nested JSON object."""
    payload = '"x"'
    for _ in range(depth):
        payload = '{"a":' + payload + "}"
    return payload


def _make_xml_bomb(depth: int) -> str:
    """Build a deeply nested XML document."""
    inner = "<v>1</v>"
    for _ in range(depth):
        inner = f"<a>{inner}</a>"
    return inner


class TestNestingDepthRule:
    def test_detects_deep_json(self):
        rule = NestingDepthRule(max_json_depth=50)
        payload = _make_json_bomb(150)
        result = rule.evaluate(payload, _ctx())
        assert result.action == GuardAction.BLOCK

    def test_allows_shallow_json(self):
        rule = NestingDepthRule(max_json_depth=50)
        payload = json.dumps({"a": {"b": {"c": 1}}})
        result = rule.evaluate(payload, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_detects_deep_xml(self):
        rule = NestingDepthRule(max_xml_depth=50)
        payload = _make_xml_bomb(150)
        result = rule.evaluate(payload, _ctx())
        assert result.action == GuardAction.BLOCK

    def test_allows_shallow_xml(self):
        rule = NestingDepthRule(max_xml_depth=50)
        payload = "<root><item><name>test</name></item></root>"
        result = rule.evaluate(payload, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_plain_text(self):
        rule = NestingDepthRule()
        result = rule.evaluate("Just a plain sentence with no structure.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_default_threshold_passes_normal_json(self):
        rule = NestingDepthRule()
        data = {"level1": {"level2": {"level3": [1, 2, 3]}}}
        result = rule.evaluate(json.dumps(data), _ctx())
        assert result.action == GuardAction.ALLOW

    def test_finding_includes_depth_info(self):
        rule = NestingDepthRule(max_json_depth=10)
        payload = _make_json_bomb(50)
        result = rule.evaluate(payload, _ctx())
        assert result.finding is not None
        assert result.finding.metadata.get("nesting_depth", 0) > 10

    @pytest.mark.parametrize("depth", [101, 200, 500])
    def test_blocks_at_various_excessive_depths(self, depth: int):
        rule = NestingDepthRule(max_json_depth=100)
        payload = _make_json_bomb(depth)
        result = rule.evaluate(payload, _ctx())
        assert result.action == GuardAction.BLOCK
