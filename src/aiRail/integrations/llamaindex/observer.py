"""LlamaIndex observer for aiRail.

Requires: pip install aiRail[llamaindex]
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aiRail.exceptions import GuardrailBlockedError
from aiRail.models.enums import GuardStage

if TYPE_CHECKING:
    from aiRail.guard import Guard

logger = logging.getLogger("aiRail.llamaindex")


class AegisRailObserver:
    """LlamaIndex event observer that integrates aiRail guardrails.

    Usage:
        from llama_index.core import Settings
        guard = Guard.balanced()
        observer = AegisRailObserver(guard=guard)
        # Attach to LlamaIndex events via dispatcher

    Requires: pip install aiRail[llamaindex]
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
            logger.warning(f"aiRail query check error: {exc}")
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
                    safe_nodes.append(node)
                else:
                    msg = result.findings[0].message if result.findings else "unknown"
                    logger.warning(f"RAG document blocked: {msg}")
            except Exception as exc:
                logger.warning(f"aiRail retrieve check error: {exc}")
                safe_nodes.append(node)
        return safe_nodes

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
            logger.warning(f"aiRail response check error: {exc}")
            return response
