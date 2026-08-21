"""Security corpus regression tests for persistent memory writes."""

import json
from pathlib import Path

import pytest

from aiRail import Guard, GuardAction

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "memory_writes.json"


@pytest.mark.parametrize("entry", json.loads(CORPUS_PATH.read_text()))
def test_memory_write_corpus(entry):
    result = Guard.silent().check_memory_write(entry["text"])

    expected = GuardAction(entry["expected_action"])
    assert result.action == expected
    memory_findings = [finding for finding in result.findings if finding.rule_id == "MEM-001"]
    if memory_findings:
        assert memory_findings[0].metadata["classification"] == entry["classification"]
