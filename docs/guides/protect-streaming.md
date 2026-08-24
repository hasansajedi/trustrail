# Protect streaming output

Create one scanner per response. It retains a bounded overlap so a dangerous
pattern split across chunks can still be detected.

```python
from trustrail import Guard, GuardStage

guard = Guard.balanced()
scanner = guard.stream(GuardStage.STREAM)

async for result in scanner.scan(model.stream(prompt)):
    if result.is_blocked:
        await model.cancel()
        break
    yield result.safe_chunk

final = scanner.finalize()
if final.is_blocked:
    logger.warning("stream blocked", extra={"score": final.score.value})
```

Never emit `result.chunk` directly; emit `safe_chunk` only after checking the
action. A client may already have received earlier safe chunks when a later chunk
blocks, so avoid streaming into irreversible sinks.

Sensitive data contained in one chunk is redacted before emission according to
`sensitive_data_mode`. If a sensitive match spans an already-emitted chunk
boundary, the scanner fails closed because it cannot retract the prefix. Pass
`protected_data=[ProtectedData(...)]` to `Guard.stream()` to apply the same
private-context disclosure check used by `Guard.check()`.

Streaming checks are pattern-oriented. If the complete response has security or
compliance significance, buffer it server-side and perform a final
`GuardStage.FINAL_OUTPUT` check before committing it.
