"""Protect OpenAI-style multipart and tool-call messages without data loss."""

import asyncio
import json

from trustrail import Guard
from trustrail.integrations.openai import protect_openai_messages


async def main() -> None:
    guard = Guard.silent()
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Describe this safe\u200b image."},
                {
                    "type": "image_url",
                    "image_url": {
                        "url": "data:image/png;base64,example-placeholder",
                        "detail": "low",
                    },
                },
            ],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-weather",
                    "type": "function",
                    "function": {"name": "weather", "arguments": '{"city":"Berlin"}'},
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call-weather",
            "content": '{"temperature":18}',
        },
    ]

    safe_messages = await protect_openai_messages(messages, guard)

    assert safe_messages[0]["content"][0]["text"] == "Describe this safe image."
    assert safe_messages[0]["content"][1] == messages[0]["content"][1]
    assert safe_messages[1]["content"] is None
    assert safe_messages[1]["tool_calls"] == messages[1]["tool_calls"]
    assert safe_messages[2]["tool_call_id"] == "call-weather"
    assert messages[0]["content"][0]["text"] == "Describe this safe\u200b image."
    print(json.dumps(safe_messages, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
