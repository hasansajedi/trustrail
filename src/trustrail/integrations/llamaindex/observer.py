"""Synchronous and awaited LlamaIndex guardrail hooks.

Requires: pip install trustrail[llamaindex]
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal

from trustrail.exceptions import GuardrailBlockedError
from trustrail.models.core import GuardContext, GuardResult
from trustrail.models.enums import FailMode, GuardAction, GuardStage

if TYPE_CHECKING:
    from trustrail.guard import Guard

logger = logging.getLogger("trustrail.llamaindex")

EmptyRetrievalBehavior = Literal["raise", "return_empty"]

_SAFE_ACTIONS = {
    GuardAction.ALLOW,
    GuardAction.WARN,
    GuardAction.REDACT,
    GuardAction.TRANSFORM,
}


def _identifier(value: Any) -> str | None:
    return str(value) if value is not None else None


def _guard_fail_mode(guard: Any) -> FailMode:
    value = getattr(guard, "fail_mode", FailMode.CLOSED)
    try:
        return FailMode(value)
    except ValueError:
        return FailMode.CLOSED


def _framework_context(
    stage: GuardStage,
    *,
    kwargs: Mapping[str, Any],
    boundary_metadata: Mapping[str, Any] | None = None,
) -> GuardContext:
    supplied_metadata = kwargs.get("metadata")
    metadata = dict(supplied_metadata) if isinstance(supplied_metadata, Mapping) else {}
    if boundary_metadata:
        metadata.update(boundary_metadata)

    run_id = _identifier(kwargs.get("run_id"))
    if run_id is not None:
        metadata["run_id"] = run_id
    request_id = (
        _identifier(kwargs.get("request_id")) or _identifier(metadata.get("request_id")) or run_id
    )
    tenant_id = _identifier(kwargs.get("tenant_id")) or _identifier(metadata.get("tenant_id"))
    user_id = _identifier(kwargs.get("user_id")) or _identifier(metadata.get("user_id"))
    session_id = _identifier(kwargs.get("session_id")) or _identifier(metadata.get("session_id"))
    tags_value = kwargs.get("tags")
    tags = [str(tag) for tag in tags_value] if isinstance(tags_value, (list, tuple)) else []

    values: dict[str, Any] = {
        "stage": stage,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "session_id": session_id,
        "metadata": metadata,
        "tags": tags,
    }
    if request_id is not None:
        values["request_id"] = request_id
    return GuardContext(**values)


class TrustRailObserver:
    """Explicit sync and async TrustRail boundaries for LlamaIndex pipelines."""

    def __init__(
        self,
        guard: Guard,
        raise_on_block: bool = True,
        *,
        empty_retrieval: EmptyRetrievalBehavior = "raise",
    ) -> None:
        if empty_retrieval not in ("raise", "return_empty"):
            raise ValueError("empty_retrieval must be 'raise' or 'return_empty'")
        self.guard = guard
        self.raise_on_block = raise_on_block
        self.empty_retrieval = empty_retrieval

    def _decision_value(
        self,
        result: GuardResult,
        *,
        original: str,
        stage: GuardStage,
        message: str,
    ) -> str:
        if result.action not in _SAFE_ACTIONS:
            if self.raise_on_block:
                raise GuardrailBlockedError(
                    message,
                    stage=stage,
                    findings=result.findings,
                    score=result.score.value,
                    action=result.action.value,
                )
            return original
        return result.output_value

    def _guard_error(
        self,
        exc: Exception,
        *,
        stage: GuardStage,
        boundary: str,
    ) -> None:
        if isinstance(exc, GuardrailBlockedError):
            raise exc
        if _guard_fail_mode(self.guard) == FailMode.CLOSED:
            raise GuardrailBlockedError(
                f"LlamaIndex {boundary} guard check failed closed",
                stage=stage,
                provider_error=type(exc).__name__,
            ) from exc
        logger.warning(
            "trustrail %s check error (fail-open): %s",
            boundary,
            type(exc).__name__,
        )

    def on_query(self, query: str, **kwargs: Any) -> str:
        """Check a query before retrieval."""
        context = _framework_context(GuardStage.USER_INPUT, kwargs=kwargs)
        try:
            result = self.guard.check(query, GuardStage.USER_INPUT, context=context)
            return self._decision_value(
                result,
                original=query,
                stage=GuardStage.USER_INPUT,
                message="Query blocked by guardrail",
            )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            self._guard_error(exc, stage=GuardStage.USER_INPUT, boundary="query")
            return query

    async def aon_query(self, query: str, **kwargs: Any) -> str:
        """Await the query decision before retrieval."""
        context = _framework_context(GuardStage.USER_INPUT, kwargs=kwargs)
        try:
            result = await self.guard.acheck(query, GuardStage.USER_INPUT, context=context)
            return self._decision_value(
                result,
                original=query,
                stage=GuardStage.USER_INPUT,
                message="Query blocked by guardrail",
            )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            self._guard_error(exc, stage=GuardStage.USER_INPUT, boundary="query")
            return query

    def on_retrieve(self, nodes: list[Any], **kwargs: Any) -> list[Any]:
        """Check retrieved nodes and enforce configured empty-result behavior."""
        safe_nodes: list[Any] = []
        rejected_count = 0
        for index, node in enumerate(nodes):
            text = self._node_text(node)
            if not text:
                safe_nodes.append(node)
                continue
            context = _framework_context(
                GuardStage.RAG_DOCUMENT,
                kwargs=kwargs,
                boundary_metadata=self._node_metadata(node, index=index),
            )
            try:
                result = self.guard.check(text, GuardStage.RAG_DOCUMENT, context=context)
                if result.action not in _SAFE_ACTIONS:
                    rejected_count += 1
                    self._log_rejected_node(result)
                    continue
                safe_text = result.output_value
                if safe_text != text and not self._replace_node_text(node, safe_text):
                    rejected_count += 1
                    logger.warning(
                        "RAG document blocked because transformed content could not be applied"
                    )
                    continue
                safe_nodes.append(node)
            except GuardrailBlockedError:
                raise
            except Exception as exc:
                if _guard_fail_mode(self.guard) == FailMode.OPEN:
                    logger.warning(
                        "trustrail retrieve check error (fail-open): %s",
                        type(exc).__name__,
                    )
                    safe_nodes.append(node)
                else:
                    rejected_count += 1
                    logger.warning(
                        "trustrail retrieve check error (fail-closed): %s",
                        type(exc).__name__,
                    )
        return self._enforce_retrieval_result(safe_nodes, rejected_count=rejected_count)

    async def aon_retrieve(self, nodes: list[Any], **kwargs: Any) -> list[Any]:
        """Await every retrieved-node decision before synthesis."""
        safe_nodes: list[Any] = []
        rejected_count = 0
        for index, node in enumerate(nodes):
            text = self._node_text(node)
            if not text:
                safe_nodes.append(node)
                continue
            context = _framework_context(
                GuardStage.RAG_DOCUMENT,
                kwargs=kwargs,
                boundary_metadata=self._node_metadata(node, index=index),
            )
            try:
                result = await self.guard.acheck(
                    text,
                    GuardStage.RAG_DOCUMENT,
                    context=context,
                )
                if result.action not in _SAFE_ACTIONS:
                    rejected_count += 1
                    self._log_rejected_node(result)
                    continue
                safe_text = result.output_value
                if safe_text != text and not self._replace_node_text(node, safe_text):
                    rejected_count += 1
                    logger.warning(
                        "RAG document blocked because transformed content could not be applied"
                    )
                    continue
                safe_nodes.append(node)
            except GuardrailBlockedError:
                raise
            except Exception as exc:
                if _guard_fail_mode(self.guard) == FailMode.OPEN:
                    logger.warning(
                        "trustrail retrieve check error (fail-open): %s",
                        type(exc).__name__,
                    )
                    safe_nodes.append(node)
                else:
                    rejected_count += 1
                    logger.warning(
                        "trustrail retrieve check error (fail-closed): %s",
                        type(exc).__name__,
                    )
        return self._enforce_retrieval_result(safe_nodes, rejected_count=rejected_count)

    def on_llm_response(self, response: str, **kwargs: Any) -> str:
        """Check a model response before returning it."""
        context = _framework_context(GuardStage.LLM_RESPONSE, kwargs=kwargs)
        try:
            result = self.guard.check(response, GuardStage.LLM_RESPONSE, context=context)
            return self._decision_value(
                result,
                original=response,
                stage=GuardStage.LLM_RESPONSE,
                message="LLM response blocked by guardrail",
            )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            self._guard_error(exc, stage=GuardStage.LLM_RESPONSE, boundary="response")
            return response

    async def aon_llm_response(self, response: str, **kwargs: Any) -> str:
        """Await the response decision before returning it."""
        context = _framework_context(GuardStage.LLM_RESPONSE, kwargs=kwargs)
        try:
            result = await self.guard.acheck(
                response,
                GuardStage.LLM_RESPONSE,
                context=context,
            )
            return self._decision_value(
                result,
                original=response,
                stage=GuardStage.LLM_RESPONSE,
                message="LLM response blocked by guardrail",
            )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            self._guard_error(exc, stage=GuardStage.LLM_RESPONSE, boundary="response")
            return response

    def _enforce_retrieval_result(
        self,
        safe_nodes: list[Any],
        *,
        rejected_count: int,
    ) -> list[Any]:
        if safe_nodes or rejected_count == 0 or self.empty_retrieval == "return_empty":
            return safe_nodes
        raise GuardrailBlockedError(
            "All retrieved RAG nodes were blocked by guardrail",
            stage=GuardStage.RAG_DOCUMENT,
            rejected_count=rejected_count,
        )

    @staticmethod
    def _node_text(node: Any) -> str:
        text = getattr(node, "text", "") or getattr(node, "content", "")
        return text if isinstance(text, str) else ""

    @staticmethod
    def _node_metadata(node: Any, *, index: int) -> dict[str, Any]:
        node_id = getattr(node, "node_id", None) or getattr(node, "id_", None)
        metadata: dict[str, Any] = {"node_index": index}
        if node_id is not None:
            metadata["node_id"] = str(node_id)
        return metadata

    @staticmethod
    def _log_rejected_node(result: GuardResult) -> None:
        rule_ids = [finding.rule_id for finding in result.findings]
        logger.warning("RAG document blocked by rules: %s", rule_ids)

    @staticmethod
    def _replace_node_text(node: Any, safe_text: str) -> bool:
        """Apply transformed text through common LlamaIndex node interfaces."""
        setter = getattr(node, "set_content", None)
        if callable(setter):
            try:
                setter(safe_text)
            except Exception:
                return False
            else:
                return True
        for attribute in ("text", "content"):
            if hasattr(node, attribute):
                try:
                    setattr(node, attribute, safe_text)
                except Exception as exc:
                    logger.debug(
                        "could not apply RAG transformation through %s: %s",
                        attribute,
                        type(exc).__name__,
                    )
                    continue
                return True
        return False


# Compatibility alias for the pre-TrustRail package naming.
AegisRailObserver = TrustRailObserver
