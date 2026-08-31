# OpenAI integration

Install the optional dependency:

```bash
python -m pip install "trustrail[openai]"
```

The adapter accepts OpenAI-style message dictionaries, checks each role at the
correct guard stage, and returns dictionaries that can be passed directly to an
OpenAI client.

```python
from trustrail import Guard
from trustrail.integrations.openai import (
    filter_openai_messages,
    protect_openai_messages,
    protect_openai_response,
)

guard = Guard.balanced()
messages = [
    {"role": "system", "content": "You are a concise assistant."},
    {"role": "user", "content": user_input},
]

safe_messages = await protect_openai_messages(messages, guard)
response = await openai_client.responses.create(
    model="your-model",
    input=safe_messages,
)
safe_text = await protect_openai_response(response.output_text, guard)
```

## Vision and tool-calling messages

Multipart content and tool-call conversations retain their original structure.
For example, the image block, parallel tool calls, nullable assistant content,
and tool-call IDs below survive protection unchanged:

```python
messages = [
    {
        "role": "user",
        "content": [
            {"type": "text", "text": "Describe this image."},
            {
                "type": "image_url",
                "image_url": {"url": image_data_url, "detail": "low"},
            },
        ],
    },
    {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_weather",
                "type": "function",
                "function": {
                    "name": "weather",
                    "arguments": '{"city":"Berlin"}',
                },
            },
            {
                "id": "call_time",
                "type": "function",
                "function": {
                    "name": "time",
                    "arguments": '{"zone":"Europe/Berlin"}',
                },
            },
        ],
    },
    {
        "role": "tool",
        "tool_call_id": "call_weather",
        "content": '{"temperature":18}',
    },
]

safe_messages = await protect_openai_messages(messages, guard)
```

String content, `text`, `input_text`, `output_text`, and `refusal` content
parts, plus a top-level string `refusal`, are scanned asynchronously. Any
redaction or transformation is written back to the same textual field.
`image_url`, `input_audio`, `file`, and unknown future content parts are
retained byte-for-byte at the value level but are not interpreted by the text
guard. Validate those payloads with a modality-specific validator before model
submission when they are untrusted. Unsupported parts are never silently
removed.

`protect_openai_messages` is atomic: a blocked or approval-required entry raises
instead of returning a partial conversation. It preserves the ordering and
fields of allowed or transformed entries, including `None`, `tool_calls`,
`tool_call_id`, `refusal`, `name`, and provider extension fields. `tool`
messages are checked at `TOOL_RESPONSE`, while `system`, `developer`, `user`,
and `assistant` use their corresponding explicit boundaries.

Legacy partial filtering is available only through the deliberately named
`filter_openai_messages(messages, guard)` API. Filtering can corrupt tool-call
pairing and prompt semantics, so use it only when dropping entries is an
explicit application policy. `check_openai_messages` returns every individual
message result when the application needs to render its own structured
rejection. All async adapter functions use the guard's async evaluation API.

The adapter does not send data to OpenAI and does not create a client. Configure
API credentials and model access through the official OpenAI SDK.
