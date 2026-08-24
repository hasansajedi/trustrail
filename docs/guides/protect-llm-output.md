# Protect LLM output

Validate model output before rendering it, storing it, or passing it to another
system. Then apply a destination contract before the value reaches a browser,
interpreter, database, filesystem, or tool.

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

## Apply the destination contract

```python
from trustrail import OutputContext, OutputHandlingPolicy, SafeOutputHandler

handler = SafeOutputHandler(
    OutputHandlingPolicy(
        allowed_url_hosts=frozenset({"docs.example.com"}),
    )
)

safe_html_text = handler.require(response, OutputContext.HTML)
safe_url = handler.require(model_url, OutputContext.URL)
```

`SafeOutputHandler` encodes HTML and JavaScript text, checks Markdown and URLs,
confines paths, validates strict structured output, and rejects raw SQL, shell,
template, code, and tool sinks. For example, bind a SQL value as data:

```python
database.execute(
    "SELECT id FROM documents WHERE title = ?",
    (handler.as_sql_parameter(model_title),),
)
```

For tools, `parse_tool_call()` validates a fixed application-selected name and a
strict Pydantic argument schema. It returns a non-executing plan that still needs
deterministic authorization and approval. See [safe model output handling](../security/output-handling.md)
for every context, examples, assumptions, and residual risk.
