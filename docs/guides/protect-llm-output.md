# Protect LLM output

Validate model output before rendering it, storing it, or passing it to another
system. Output rules detect sensitive data, unsafe markup, shell metacharacters,
path traversal, and suspicious URLs.

```python
from trustrail import Guard, GuardStage

guard = Guard.balanced()
raw_response = await model.generate(prompt)
result = await guard.acheck(raw_response, GuardStage.LLM_RESPONSE)

if result.is_blocked:
    return "The generated response could not be displayed safely."

response = result.output_value
```

Use `FINAL_OUTPUT` for the last check immediately before data crosses the
application boundary:

```python
response = await guard.aprotect(response, GuardStage.FINAL_OUTPUT)
```

## Decorator boundary

```python
@guard.output(stage=GuardStage.LLM_RESPONSE)
async def answer(prompt: str) -> str:
    return await model.generate(prompt)
```

Guardrails do not replace context-specific escaping. HTML-escape text rendered
into HTML, parameterize SQL, avoid shell execution, and validate URLs at the
network layer even after the output passes trustrail.
