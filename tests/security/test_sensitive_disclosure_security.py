"""Security regression tests for OWASP LLM02 disclosure bypasses."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from trustrail import Guard, GuardStage
from trustrail.audit import LoggingAuditSink
from trustrail.integrations.langchain.handler import AegisRailCallbackHandler
from trustrail.models.enums import GuardAction

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "sensitive_disclosure.json"


def _corpus() -> list[dict[str, object]]:
    return json.loads(CORPUS_PATH.read_text())


@pytest.mark.parametrize("case", _corpus(), ids=lambda case: str(case["name"]))
def test_sensitive_disclosure_corpus(case: dict[str, object]):
    text = str(case["text"]) if "text" in case else "".join(case["text_parts"])
    result = Guard.silent().check(text, GuardStage.FINAL_OUTPUT)
    expected = GuardAction(str(case["expected_action"]))

    assert result.action == expected


def test_audit_log_contains_metadata_but_not_secret(caplog: pytest.LogCaptureFixture):
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
    guard = Guard(audit_sink=LoggingAuditSink(logger_name="test.safe-audit"))

    with caplog.at_level(logging.INFO, logger="test.safe-audit"):
        guard.check(token, GuardStage.FINAL_OUTPUT)

    assert token not in caplog.text
    assert "SD-015" in caplog.text


def test_integration_error_log_uses_exception_type_only(
    caplog: pytest.LogCaptureFixture,
):
    secret = "do-not-log-this-secret"

    class BrokenGuard:
        def check(self, value: str, stage: GuardStage):
            raise RuntimeError(secret)

    handler = AegisRailCallbackHandler(BrokenGuard())  # type: ignore[arg-type]
    with caplog.at_level(logging.WARNING, logger="trustrail.langchain"):
        response = SimpleNamespace(generations=[[SimpleNamespace(text="hello")]])
        handler.on_llm_end(response, run_id=None)  # type: ignore[arg-type]

    assert secret not in caplog.text
    assert "RuntimeError" in caplog.text
