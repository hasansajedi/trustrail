# OpenAI integration

Install the optional dependency:

```bash
python -m pip install "trustrail[openai]"
```

The adapter converts OpenAI-style message dictionaries and checks each role at
the correct guard stage.

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

`protect_openai_messages` is atomic: a blocked or approval-required entry raises
instead of returning a partial conversation. It preserves the ordering and
fields of allowed or transformed entries. `tool` messages are checked at
`TOOL_RESPONSE`, while `system`, `developer`, `user`, and `assistant` use their
corresponding explicit boundaries.

Legacy partial filtering is available only through the deliberately named
`filter_openai_messages(messages, guard)` API. Filtering can corrupt tool-call
pairing and prompt semantics, so use it only when dropping entries is an
explicit application policy. `check_openai_messages` returns every individual
result when the application needs to render its own structured rejection.

The adapter does not send data to OpenAI and does not create a client. Configure
API credentials and model access through the official OpenAI SDK.
