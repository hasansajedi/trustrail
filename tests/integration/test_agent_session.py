"""Integration tests for agent session tracking."""

import pytest

from aiRail.exceptions import GuardrailBlockedError
from aiRail.guard import Guard
from aiRail.models.core import GuardContext, ToolCall
from aiRail.models.enums import GuardStage


class TestAgentSession:
    @pytest.mark.asyncio
    async def test_basic_session(self):
        guard = Guard.silent()
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION, session_id="test-session")

        async with guard.agent_session(ctx) as session:
            result = await session.step("Analyzing user request")
            assert result is not None
            assert session.state.step_count == 1

    @pytest.mark.asyncio
    async def test_tool_call_tracking(self):
        guard = Guard.silent()
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION, session_id="test-session")

        async with guard.agent_session(ctx) as session:
            tool = ToolCall(name="search", arguments={"query": "Python docs"})
            await session.validate_tool_call(tool)
            assert session.state.tool_call_count == 1

    @pytest.mark.asyncio
    async def test_step_limit_enforced(self):
        guard = Guard.silent()
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION)

        async with guard.agent_session(ctx, max_steps=2) as session:
            await session.step("Step 1")
            await session.step("Step 2")
            with pytest.raises(GuardrailBlockedError):
                await session.step("Step 3 - should be blocked")

    @pytest.mark.asyncio
    async def test_recursion_tracking(self):
        guard = Guard.silent()
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION)

        async with guard.agent_session(ctx) as session:
            session.enter_recursion()
            assert session.state.recursion_depth == 1
            session.exit_recursion()
            assert session.state.recursion_depth == 0

    @pytest.mark.asyncio
    async def test_session_summary(self):
        guard = Guard.silent()
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION)

        async with guard.agent_session(ctx) as session:
            await session.step("Step 1")
            summary = session.summary
            assert summary["steps"] == 1
            assert "elapsed_seconds" in summary
            assert summary["within_limits"]
