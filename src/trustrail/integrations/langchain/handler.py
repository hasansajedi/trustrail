"""Awaited LangChain callback handlers for trustrail.

Requires: pip install trustrail[langchain]
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any
from uuid import UUID

from trustrail.exceptions import GuardrailBlockedError
from trustrail.models.core import GuardContext, GuardResult
from trustrail.models.enums import FailMode, GuardAction, GuardStage

if TYPE_CHECKING:
    from trustrail.guard import Guard

    class _LangChainBaseCallbackHandler:
        """Static type for the optional LangChain base handler."""

    class _LangChainAsyncCallbackHandler(_LangChainBaseCallbackHandler):
        """Static type for the optional LangChain async handler."""

else:
    try:
        from langchain_core.callbacks import (
            AsyncCallbackHandler as _LangChainAsyncCallbackHandler,
        )
        from langchain_core.callbacks import BaseCallbackHandler as _LangChainBaseCallbackHandler
    except ImportError:  # pragma: no cover - optional extra is absent in core installs

        class _LangChainBaseCallbackHandler:
            """Minimal import-time fallback for environments without LangChain."""

        class _LangChainAsyncCallbackHandler(_LangChainBaseCallbackHandler):
            """Minimal async fallback for environments without LangChain."""


logger = logging.getLogger("trustrail.langchain")

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
    run_id: UUID | str | None,
    kwargs: Mapping[str, Any],
    boundary_metadata: Mapping[str, Any] | None = None,
) -> GuardContext:
    supplied_metadata = kwargs.get("metadata")
    metadata = dict(supplied_metadata) if isinstance(supplied_metadata, Mapping) else {}
    if boundary_metadata:
        metadata.update(boundary_metadata)
    run_id_value = _identifier(run_id)
    parent_run_id = _identifier(kwargs.get("parent_run_id"))
    if run_id_value is not None:
        metadata["run_id"] = run_id_value
    if parent_run_id is not None:
        metadata["parent_run_id"] = parent_run_id

    request_id = (
        _identifier(kwargs.get("request_id"))
        or _identifier(metadata.get("request_id"))
        or run_id_value
    )
    tenant_id = _identifier(kwargs.get("tenant_id")) or _identifier(metadata.get("tenant_id"))
    user_id = _identifier(kwargs.get("user_id")) or _identifier(metadata.get("user_id"))
    session_id = (
        _identifier(kwargs.get("session_id"))
        or _identifier(metadata.get("session_id"))
        or parent_run_id
    )
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


class _TrustRailHandlerBase:
    # LangChain's callback manager propagates handler errors only when this is
    # true. Blocking decisions must reach the caller before provider execution.
    raise_error = True
    run_inline = True

    def __init__(self, guard: Guard, raise_on_block: bool = True) -> None:
        self.guard = guard
        self.raise_on_block = raise_on_block

    @property
    def ignore_llm(self) -> bool:
        return False

    @property
    def ignore_chat_model(self) -> bool:
        return False

    @property
    def ignore_tool(self) -> bool:
        return False

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
                f"LangChain {boundary} guard check failed closed",
                stage=stage,
                provider_error=type(exc).__name__,
            ) from exc
        logger.warning(
            "trustrail %s check error (fail-open): %s",
            boundary,
            type(exc).__name__,
        )

    @staticmethod
    def _immutable_transform(
        *,
        stage: GuardStage,
        boundary: str,
        result: GuardResult,
        exc: Exception | None = None,
    ) -> None:
        error = GuardrailBlockedError(
            f"LangChain {boundary} required a transformation that could not be applied",
            stage=stage,
            findings=result.findings,
            score=result.score.value,
        )
        if exc is None:
            raise error
        raise error from exc


class TrustRailCallbackHandler(_TrustRailHandlerBase, _LangChainBaseCallbackHandler):
    """Synchronous LangChain handler that enforces checks before returning."""

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Check and transform LLM prompts synchronously before invocation."""
        model_name = serialized.get("name") or serialized.get("id")
        for index, prompt in enumerate(prompts):
            context = _framework_context(
                GuardStage.LLM_REQUEST,
                run_id=run_id,
                kwargs=kwargs,
                boundary_metadata={"model": model_name, "prompt_index": index},
            )
            try:
                result = self.guard.check(prompt, GuardStage.LLM_REQUEST, context=context)
                safe_prompt = self._decision_value(
                    result,
                    original=prompt,
                    stage=GuardStage.LLM_REQUEST,
                    message="LLM input blocked",
                )
                if safe_prompt != prompt:
                    try:
                        prompts[index] = safe_prompt
                    except (AttributeError, TypeError, ValueError) as exc:
                        self._immutable_transform(
                            stage=GuardStage.LLM_REQUEST,
                            boundary="LLM input",
                            result=result,
                            exc=exc,
                        )
            except GuardrailBlockedError:
                raise
            except Exception as exc:
                self._guard_error(exc, stage=GuardStage.LLM_REQUEST, boundary="LLM input")

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        """Check and transform generated text before downstream callbacks."""
        generations = getattr(response, "generations", ())
        for generation_index, generation_list in enumerate(generations):
            for candidate_index, generation in enumerate(generation_list):
                text = getattr(generation, "text", "")
                if not isinstance(text, str) or not text:
                    continue
                context = _framework_context(
                    GuardStage.LLM_RESPONSE,
                    run_id=run_id,
                    kwargs=kwargs,
                    boundary_metadata={
                        "generation_index": generation_index,
                        "candidate_index": candidate_index,
                    },
                )
                try:
                    result = self.guard.check(text, GuardStage.LLM_RESPONSE, context=context)
                    safe_text = self._decision_value(
                        result,
                        original=text,
                        stage=GuardStage.LLM_RESPONSE,
                        message="LLM output blocked",
                    )
                    if safe_text != text:
                        try:
                            generation.text = safe_text
                        except (AttributeError, TypeError, ValueError) as exc:
                            self._immutable_transform(
                                stage=GuardStage.LLM_RESPONSE,
                                boundary="LLM output",
                                result=result,
                                exc=exc,
                            )
                except GuardrailBlockedError:
                    raise
                except Exception as exc:
                    self._guard_error(exc, stage=GuardStage.LLM_RESPONSE, boundary="LLM output")

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Check tool input before invocation."""
        tool_name = str(serialized.get("name", "unknown"))
        context = _framework_context(
            GuardStage.TOOL_REQUEST,
            run_id=run_id,
            kwargs=kwargs,
            boundary_metadata={"tool_name": tool_name},
        )
        try:
            result = self.guard.check(input_str, GuardStage.TOOL_REQUEST, context=context)
            safe_input = self._decision_value(
                result,
                original=input_str,
                stage=GuardStage.TOOL_REQUEST,
                message=f"Tool '{tool_name}' input blocked",
            )
            if safe_input != input_str:
                self._immutable_transform(
                    stage=GuardStage.TOOL_REQUEST,
                    boundary="tool input",
                    result=result,
                )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            self._guard_error(exc, stage=GuardStage.TOOL_REQUEST, boundary="tool input")


class TrustRailAsyncCallbackHandler(_TrustRailHandlerBase, _LangChainAsyncCallbackHandler):
    """Native async LangChain handler that awaits every guard decision."""

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Await and enforce LLM prompt decisions before invocation."""
        model_name = serialized.get("name") or serialized.get("id")
        for index, prompt in enumerate(prompts):
            context = _framework_context(
                GuardStage.LLM_REQUEST,
                run_id=run_id,
                kwargs=kwargs,
                boundary_metadata={"model": model_name, "prompt_index": index},
            )
            try:
                result = await self.guard.acheck(
                    prompt,
                    GuardStage.LLM_REQUEST,
                    context=context,
                )
                safe_prompt = self._decision_value(
                    result,
                    original=prompt,
                    stage=GuardStage.LLM_REQUEST,
                    message="LLM input blocked",
                )
                if safe_prompt != prompt:
                    try:
                        prompts[index] = safe_prompt
                    except (AttributeError, TypeError, ValueError) as exc:
                        self._immutable_transform(
                            stage=GuardStage.LLM_REQUEST,
                            boundary="LLM input",
                            result=result,
                            exc=exc,
                        )
            except GuardrailBlockedError:
                raise
            except Exception as exc:
                self._guard_error(exc, stage=GuardStage.LLM_REQUEST, boundary="LLM input")

    async def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        """Await and enforce generated-text decisions."""
        generations = getattr(response, "generations", ())
        for generation_index, generation_list in enumerate(generations):
            for candidate_index, generation in enumerate(generation_list):
                text = getattr(generation, "text", "")
                if not isinstance(text, str) or not text:
                    continue
                context = _framework_context(
                    GuardStage.LLM_RESPONSE,
                    run_id=run_id,
                    kwargs=kwargs,
                    boundary_metadata={
                        "generation_index": generation_index,
                        "candidate_index": candidate_index,
                    },
                )
                try:
                    result = await self.guard.acheck(
                        text,
                        GuardStage.LLM_RESPONSE,
                        context=context,
                    )
                    safe_text = self._decision_value(
                        result,
                        original=text,
                        stage=GuardStage.LLM_RESPONSE,
                        message="LLM output blocked",
                    )
                    if safe_text != text:
                        try:
                            generation.text = safe_text
                        except (AttributeError, TypeError, ValueError) as exc:
                            self._immutable_transform(
                                stage=GuardStage.LLM_RESPONSE,
                                boundary="LLM output",
                                result=result,
                                exc=exc,
                            )
                except GuardrailBlockedError:
                    raise
                except Exception as exc:
                    self._guard_error(exc, stage=GuardStage.LLM_RESPONSE, boundary="LLM output")

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Await and enforce tool-input decisions before invocation."""
        tool_name = str(serialized.get("name", "unknown"))
        context = _framework_context(
            GuardStage.TOOL_REQUEST,
            run_id=run_id,
            kwargs=kwargs,
            boundary_metadata={"tool_name": tool_name},
        )
        try:
            result = await self.guard.acheck(
                input_str,
                GuardStage.TOOL_REQUEST,
                context=context,
            )
            safe_input = self._decision_value(
                result,
                original=input_str,
                stage=GuardStage.TOOL_REQUEST,
                message=f"Tool '{tool_name}' input blocked",
            )
            if safe_input != input_str:
                self._immutable_transform(
                    stage=GuardStage.TOOL_REQUEST,
                    boundary="tool input",
                    result=result,
                )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            self._guard_error(exc, stage=GuardStage.TOOL_REQUEST, boundary="tool input")


# Compatibility aliases for the pre-TrustRail package naming.
AegisRailCallbackHandler = TrustRailCallbackHandler
AegisRailAsyncCallbackHandler = TrustRailAsyncCallbackHandler
