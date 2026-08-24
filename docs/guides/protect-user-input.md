# Protect user input

Check user-controlled text before adding it to a prompt, retrieval query, memory,
or tool argument.

```python
from trustrail import Guard, GuardContext, GuardStage

guard = Guard.balanced()
context = GuardContext(user_id="user-42", request_id="req-123")

result = guard.check(user_text, GuardStage.USER_INPUT, context=context)
if result.is_blocked:
    reasons = [finding.message for finding in result.findings]
    raise ValueError(f"Unsafe input: {reasons}")

safe_text = result.output_value
```

Use `protect` when exceptions fit the control flow:

```python
from trustrail import GuardrailBlockedError

try:
    safe_text = guard.protect(user_text, GuardStage.USER_INPUT)
except GuardrailBlockedError as exc:
    logger.info("blocked input", extra={"score": exc.score})
    return "I cannot process that request."
```

## Async handlers

```python
safe_text = await guard.aprotect(user_text, GuardStage.USER_INPUT)
```

Do not return rule details or matched substrings to an untrusted caller; detailed
feedback can help an attacker tune bypass attempts. Log rule IDs and request IDs
to a protected audit system instead.

## Composed prompts

Checking user input alone is insufficient when the final request also contains
retrieval results, tool responses, memory, or extracted media. Label and scan
every source together before constructing model messages:

```python
from trustrail import PromptSegment, PromptSource, TrustLevel

safe_segments = guard.protect_prompt_segments(
    [
        PromptSegment(
            source=PromptSource.SYSTEM,
            trust_level=TrustLevel.TRUSTED,
            content=system_prompt,
        ),
        PromptSegment(source=PromptSource.USER, content=user_text),
        PromptSegment(source=PromptSource.RAG, content=retrieved_text),
    ]
)
```

This also detects attacks split across otherwise safe-looking segments. Use the
returned segments downstream so Unicode normalization and other safe
transformations are not discarded.
