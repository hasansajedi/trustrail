"""LlamaIndex observer for trustrail.

Requires: pip install trustrail[llamaindex]
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from trustrail.exceptions import GuardrailBlockedError
from trustrail.models.enums import GuardStage

if TYPE_CHECKING:
    from trustrail.guard import Guard

logger = logging.getLogger("trustrail.llamaindex")


class AegisRailObserver:
    """LlamaIndex event observer that integrates trustrail guardrails.

    Usage:
        from llama_index.core import Settings
        guard = Guard.balanced()
        observer = AegisRailObserver(guard=guard)
        # Attach to LlamaIndex events via dispatcher

    Requires: pip install trustrail[llamaindex]
    """

    def __init__(self, guard: Guard, raise_on_block: bool = True) -> None:
        self.guard = guard
        self.raise_on_block = raise_on_block

    def on_query(self, query: str, **kwargs: Any) -> str:
        """Check query before retrieval."""
        try:
            result = self.guard.check(query, GuardStage.USER_INPUT)
            if result.is_blocked and self.raise_on_block:
                raise GuardrailBlockedError(
                    "Query blocked by guardrail",
                    stage=GuardStage.USER_INPUT,
                    findings=result.findings,
                )
            return result.output_value
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            logger.warning("trustrail query check error: %s", type(exc).__name__)
            return query

    def on_retrieve(self, nodes: list[Any], **kwargs: Any) -> list[Any]:
        """Check retrieved nodes for indirect injection."""
        safe_nodes = []
        for node in nodes:
            text = getattr(node, "text", "") or getattr(node, "content", "")
            if not text:
                safe_nodes.append(node)
                continue
            try:
                result = self.guard.check(text, GuardStage.RAG_DOCUMENT)
                if not result.is_blocked:
                    safe_text = result.output_value
                    if safe_text == text or self._replace_node_text(node, safe_text):
                        safe_nodes.append(node)
                    else:
                        logger.warning(
                            "RAG document dropped because redacted content could not be applied"
                        )
                else:
                    rule_ids = [finding.rule_id for finding in result.findings]
                    logger.warning("RAG document blocked by rules: %s", rule_ids)
            except Exception as exc:
                logger.warning("trustrail retrieve check error: %s", type(exc).__name__)
                safe_nodes.append(node)
        return safe_nodes

    @staticmethod
    def _replace_node_text(node: Any, safe_text: str) -> bool:
        """Apply redacted text through common LlamaIndex node interfaces."""
        setter = getattr(node, "set_content", None)
        if callable(setter):
            setter(safe_text)
            return True
        for attribute in ("text", "content"):
            if hasattr(node, attribute):
                try:
                    setattr(node, attribute, safe_text)
                except (AttributeError, TypeError, ValueError):
                    continue
                return True
        return False

    def on_llm_response(self, response: str, **kwargs: Any) -> str:
        """Check LLM response before returning."""
        try:
            result = self.guard.check(response, GuardStage.LLM_RESPONSE)
            if result.is_blocked and self.raise_on_block:
                raise GuardrailBlockedError(
                    "LLM response blocked by guardrail",
                    stage=GuardStage.LLM_RESPONSE,
                    findings=result.findings,
                )
            return result.output_value
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            logger.warning("trustrail response check error: %s", type(exc).__name__)
            return response
