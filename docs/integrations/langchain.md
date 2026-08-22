# LangChain integration

```bash
python -m pip install "trustrail[langchain]"
```

Attach `AegisRailCallbackHandler` through LangChain's callback configuration:

```python
from trustrail import Guard
from trustrail.integrations.langchain import AegisRailCallbackHandler

guard = Guard.balanced()
handler = AegisRailCallbackHandler(guard, raise_on_block=True)

result = chain.invoke(
    {"input": user_input},
    config={"callbacks": [handler]},
)
```

The handler checks LLM prompts, generated text, and tool inputs. A blocked
synchronous callback raises `GuardrailBlockedError` when `raise_on_block=True`.

For an async chain, protect the external boundary explicitly with
`await guard.aprotect(...)`. The callback schedules LLM-start checking when an
event loop is already running, so it should not be the only enforcement point
before a high-impact action.

```python
from trustrail import GuardStage

safe_input = await guard.aprotect(user_input, GuardStage.USER_INPUT)
result = await chain.ainvoke({"input": safe_input}, config={"callbacks": [handler]})
safe_output = await guard.aprotect(str(result), GuardStage.FINAL_OUTPUT)
```
