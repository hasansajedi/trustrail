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
action. `safe_chunk` is suitable for immediate emission only for `ALLOW`, `WARN`,
or `REDACT`; it is empty for `BLOCK` and `REQUIRE_APPROVAL`. A client may already
have received earlier safe chunks when a later chunk blocks, so avoid streaming
into irreversible sinks.

Character and estimated-token limits apply to the cumulative response, not each
overlap window. Splitting an oversized response into small chunks therefore does
not bypass `GuardConfig.max_text_length` or the resource policy's token limit.
Inspect `scanner.total_chars` while streaming or `final.input_length` after
finalization. Because scanner memory is bounded, `final.value` contains only the
retained normalized suffix when the response is larger than the buffer; collect
safe chunks separately if a complete final-output check is required.

Sensitive data contained in one chunk is redacted before emission according to
`sensitive_data_mode`. If a sensitive match spans an already-emitted chunk
boundary, the scanner fails closed because it cannot retract the prefix. Pass
`protected_data=[ProtectedData(...)]` to `Guard.stream()` to apply the same
private-context disclosure check used by `Guard.check()`.

Streaming checks are pattern-oriented. If the complete response has security or
compliance significance, buffer it server-side and perform a final
`GuardStage.FINAL_OUTPUT` check before committing it.

The scanner also inherits the guard's scoring thresholds and failure mode. A
rule failure blocks immediately under the default `FailMode.CLOSED`. With an
explicit `FailMode.OPEN` configuration, streaming continues; use that mode only
when the application has another reliable enforcement boundary.
