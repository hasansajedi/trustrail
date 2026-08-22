"""Agent session tracking and enforcement."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from trustrail.exceptions import GuardrailBlockedError
from trustrail.models.core import GuardContext, GuardResult, ToolCall
from trustrail.models.enums import GuardStage

if TYPE_CHECKING:
    from trustrail.guard import Guard


@dataclass
class AgentSessionState:
    """Tracks resource usage and limits for an agent session."""

    session_id: str = ""
    step_count: int = 0
    tool_call_count: int = 0
    recursion_depth: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    start_time: float = field(default_factory=time.monotonic)
    max_steps: int = 50
    max_tool_calls: int = 100
    max_depth: int = 10
    max_duration_seconds: float = 300.0
    tool_call_history: list[str] = field(default_factory=list)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def is_within_limits(self) -> bool:
        return (
            self.step_count <= self.max_steps
            and self.tool_call_count <= self.max_tool_calls
            and self.recursion_depth <= self.max_depth
            and self.elapsed_seconds < self.max_duration_seconds
        )

    def check_limits(self) -> str | None:
        """Return error message if any limit exceeded, else None."""
        if self.step_count > self.max_steps:
            return f"Step limit exceeded: {self.step_count}/{self.max_steps}"
        if self.tool_call_count > self.max_tool_calls:
            return f"Tool call limit exceeded: {self.tool_call_count}/{self.max_tool_calls}"
        if self.recursion_depth > self.max_depth:
            return f"Recursion depth exceeded: {self.recursion_depth}/{self.max_depth}"
        if self.elapsed_seconds >= self.max_duration_seconds:
            return f"Duration exceeded: {self.elapsed_seconds:.1f}s/{self.max_duration_seconds}s"
        return None


class AgentSession:
    """Async context manager for agent session tracking.

    Tracks step count, tool calls, recursion depth, and resource budgets.
    """

    def __init__(
        self,
        guard: Guard,
        context: GuardContext,
        max_steps: int = 50,
        max_tool_calls: int = 100,
        max_depth: int = 10,
        max_duration_seconds: float = 300.0,
    ) -> None:
        self._guard = guard
        self._base_context = context
        self.state = AgentSessionState(
            session_id=context.session_id or context.request_id,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            max_depth=max_depth,
            max_duration_seconds=max_duration_seconds,
        )

    async def __aenter__(self) -> AgentSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    def _make_context(self) -> GuardContext:
        """Create a context with current session state."""
        return GuardContext(
            request_id=self._base_context.request_id,
            session_id=self._base_context.session_id,
            user_id=self._base_context.user_id,
            tenant_id=self._base_context.tenant_id,
            stage=GuardStage.AGENT_ACTION,
            trust_level=self._base_context.trust_level,
            metadata={
                **self._base_context.metadata,
                "agent_step_count": self.state.step_count,
                "agent_tool_call_count": self.state.tool_call_count,
                "agent_recursion_depth": self.state.recursion_depth,
            },
            tags=self._base_context.tags,
        )

    async def step(self, content: str) -> GuardResult:
        """Record an agent step and validate it."""
        self.state.step_count += 1
        error = self.state.check_limits()
        if error:
            raise GuardrailBlockedError(error, stage=GuardStage.AGENT_ACTION)

        ctx = self._make_context()
        return await self._guard.acheck(content, GuardStage.AGENT_ACTION, context=ctx)

    async def validate_tool_call(self, tool_call: ToolCall) -> GuardResult:
        """Validate and record a tool call."""
        self.state.tool_call_count += 1
        self.state.tool_call_history.append(tool_call.name)

        error = self.state.check_limits()
        if error:
            raise GuardrailBlockedError(error, stage=GuardStage.TOOL_REQUEST)

        ctx = GuardContext(
            request_id=self._base_context.request_id,
            session_id=self._base_context.session_id,
            stage=GuardStage.TOOL_REQUEST,
            trust_level=self._base_context.trust_level,
            metadata={
                "tool_name": tool_call.name,
                "tool_args": tool_call.arguments,
                "agent_tool_call_count": self.state.tool_call_count,
            },
        )
        return await self._guard.acheck(tool_call.name, GuardStage.TOOL_REQUEST, context=ctx)

    def enter_recursion(self) -> None:
        """Record entering a recursive agent call."""
        self.state.recursion_depth += 1

    def exit_recursion(self) -> None:
        """Record exiting a recursive agent call."""
        self.state.recursion_depth = max(0, self.state.recursion_depth - 1)

    @property
    def summary(self) -> dict[str, Any]:
        """Return a summary of the session state."""
        return {
            "session_id": self.state.session_id,
            "steps": self.state.step_count,
            "tool_calls": self.state.tool_call_count,
            "max_depth_reached": self.state.recursion_depth,
            "elapsed_seconds": round(self.state.elapsed_seconds, 2),
            "within_limits": self.state.is_within_limits,
        }
