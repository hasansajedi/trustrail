"""Bypass-oriented security corpus for OWASP LLM07:2025."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustrail import Guard, GuardStage

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "system_prompt_leakage.json"
CASES: list[dict[str, str | bool]] = json.loads(CORPUS_PATH.read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case["id"]))
def test_system_prompt_extraction_corpus(case: dict[str, str | bool]):
    result = Guard.silent().check(
        str(case["text"]),
        GuardStage(str(case["stage"])),
    )

    assert result.is_blocked is case["blocked"]
    if case["blocked"]:
        serialized = " ".join(finding.model_dump_json() for finding in result.findings)
        assert str(case["text"]) not in serialized
