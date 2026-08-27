# Streaming

`StreamScanner` checks generated text incrementally and keeps a bounded
look-behind window so patterns split across chunks can still be detected.

```python
from trustrail import FailMode, GuardContext, GuardStage
from trustrail.rules.output import HtmlInjectionRule, ShellMetacharRule
from trustrail.streaming import StreamScanner

scanner = StreamScanner(
    rules=[HtmlInjectionRule(), ShellMetacharRule()],
    context=GuardContext(request_id="req-123", stage=GuardStage.STREAM),
    buffer_size=4096,
    chunk_overlap=256,
    fail_mode=FailMode.CLOSED,
    block_at=80,
    warn_at=40,
)

async for result in scanner.scan(model_stream):
    if result.is_blocked:
        await cancel_generation()
        break
    yield result.safe_chunk
```

## Operational guidance

Do not send a chunk to the client before checking its `StreamResult`. Once a
scanner blocks, later chunks are also blocked and `safe_chunk` is empty.
`safe_chunk` may be emitted after an `ALLOW`, `WARN`, or `REDACT` decision. It is
empty for `BLOCK` and `REQUIRE_APPROVAL`. Previously emitted chunks cannot be
retracted, so do not stream into an irreversible sink when a later decision may
invalidate the complete response.

Choose `chunk_overlap` large enough to cover the longest pattern your rules need
to recognize. Choose `buffer_size` based on memory limits; it is bounded and does
not grow with the response. Character, UTF-8 byte, and estimated-token limit
rules use cumulative counters, so splitting an oversized response into small
chunks does not bypass them. Pattern detectors still receive only the bounded
overlap window. For checks that require the complete semantic response, buffer
safe chunks in the application and perform a final
`Guard.check(..., GuardStage.FINAL_OUTPUT)` after the stream finishes.

`scanner.total_chars` and `scanner.total_bytes` report how much original content
has been scanned. `scanner.finalize().input_length` contains the cumulative
character count. The final result's `value` is only the bounded, normalized
suffix retained by `buffer_size`; it is not necessarily the complete response.

`Guard.stream(...)`, `Guard.check(..., GuardStage.STREAM)`, and the final-output
check strip invisible Unicode tag, variation-selector, zero-width, and
bidirectional-control channels. `StreamResult.safe_chunk` contains the sanitized
chunk. When constructing `StreamScanner` directly, include
`InvisibleUnicodeRule` in its custom rule list or rely on the required final
`Guard` check before rendering.

`Guard.stream()` inherits `fail_mode`, `block_at`, and `warn_at` from its
`GuardConfig`. Under `FailMode.CLOSED`, a rule exception blocks the current chunk
and every later chunk and records a content-free failure finding. Under
`FailMode.OPEN`, evaluation continues without exposing exception details in the
result. Direct `StreamScanner` construction defaults to fail closed and accepts
the same scoring thresholds explicitly. Custom rules normally receive bounded
overlap text. A rule that can evaluate from counters or other bounded state may
override `BaseRule.evaluate_stream()`; it must not retain the growing response.
