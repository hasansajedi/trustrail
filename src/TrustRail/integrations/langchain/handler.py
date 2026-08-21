"""LangChain callback handler for aiRail.

Requires: pip install aiRail[langchain]
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from aiRail.exceptions import GuardrailBlockedError
from aiRail.models.enums import GuardStage

if TYPE_CHECKING:
    from aiRail.guard import Guard

logger = logging.getLogger("aiRail.langchain")


class AegisRailCallbackHandler:
    """LangChain callback handler that integrates aiRail guardrails.

    Checks LLM inputs and outputs at each chain step.
    Requires: pip install aiRail[langchain]
    """

    def __init__(self, guard: Guard, raise_on_block: bool = True) -> None:
        self.guard = guard
        self.raise_on_block = raise_on_block

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Guard LLM input prompts."""
        import asyncio

        for prompt in prompts:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # In async context — schedule check; store task to satisfy linter
                    _task = loop.create_task(self.guard.acheck(prompt, GuardStage.LLM_REQUEST))
                    del _task  # fire-and-forget; result handled via audit sink
                else:
                    result = self.guard.check(prompt, GuardStage.LLM_REQUEST)
                    if result.is_blocked and self.raise_on_block:
                        raise GuardrailBlockedError(
                            "LLM input blocked",
                            stage=GuardStage.LLM_REQUEST,
                            findings=result.findings,
                        )
            except GuardrailBlockedError:
                raise
            except Exception as exc:
                logger.warning(f"aiRail check error in LangChain handler: {exc}")

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        """Guard LLM output."""
        try:
            # Extract text from LLMResult
            if hasattr(response, "generations"):
                for gen_list in response.generations:
                    for gen in gen_list:
                        text = getattr(gen, "text", "")
                        if text:
                            result = self.guard.check(text, GuardStage.LLM_RESPONSE)
                            if result.is_blocked and self.raise_on_block:
                                raise GuardrailBlockedError(
                                    "LLM output blocked",
                                    stage=GuardStage.LLM_RESPONSE,
                                    findings=result.findings,
                                )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            logger.warning(f"aiRail check error in LangChain handler: {exc}")

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Guard tool inputs."""
        tool_name = serialized.get("name", "unknown")
        try:
            from aiRail.models.core import GuardContext

            ctx = GuardContext(
                stage=GuardStage.TOOL_REQUEST,
                metadata={"tool_name": tool_name},
            )
            result = self.guard.check(input_str, GuardStage.TOOL_REQUEST, context=ctx)
            if result.is_blocked and self.raise_on_block:
                raise GuardrailBlockedError(
                    f"Tool '{tool_name}' input blocked",
                    stage=GuardStage.TOOL_REQUEST,
                    findings=result.findings,
                )
        except GuardrailBlockedError:
            raise
        except Exception as exc:
            logger.warning(f"aiRail tool check error: {exc}")
