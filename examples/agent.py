"""Agent session tracking example."""

import asyncio

from trustrail import Guard, GuardContext, GuardStage, ToolCall


async def main() -> None:
    guard = Guard.balanced()
    ctx = GuardContext(
        stage=GuardStage.AGENT_ACTION,
        request_id="request-001",
        session_id="agent-session-001",
        user_id="authenticated-user",
        tenant_id="tenant-a",
    )

    async with guard.agent_session(
        ctx,
        max_steps=5,
        max_tool_calls=10,
        max_depth=3,
        max_duration_seconds=30,
    ) as session:
        print("Agent session started\n")

        # Simulate agent steps
        for i in range(3):
            result = await session.step(f"Processing step {i + 1}")
            print(f"Step {i + 1}: {result.action.value}")

        # Simulate tool calls
        tools = [
            ToolCall(name="search", arguments={"query": "Python documentation"}),
            ToolCall(name="calculator", arguments={"expression": "2 + 2"}),
        ]
        for tool in tools:
            result = await session.validate_tool_call(tool)
            print(f"Tool '{tool.name}': {result.action.value}")

        print(f"\nSession summary: {session.summary}")


if __name__ == "__main__":
    asyncio.run(main())
