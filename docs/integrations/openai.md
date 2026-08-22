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

`protect_openai_messages` filters blocked messages. In conversational products,
you may prefer `check_openai_messages` so you can reject the entire request and
retain the original message ordering rather than silently removing content.

The adapter does not send data to OpenAI and does not create a client. Configure
API credentials and model access through the official OpenAI SDK.
