# Streaming

`StreamScanner` checks generated text incrementally and keeps a bounded
look-behind window so patterns split across chunks can still be detected.

```python
from trustrail import GuardContext
from trustrail.rules.output import HtmlInjectionRule, ShellMetacharRule
from trustrail.streaming import StreamScanner

scanner = StreamScanner(
    rules=[HtmlInjectionRule(), ShellMetacharRule()],
    context=GuardContext(request_id="req-123"),
    buffer_size=4096,
    chunk_overlap=256,
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

Choose `chunk_overlap` large enough to cover the longest pattern your rules need
to recognize. Choose `buffer_size` based on memory limits; it is bounded and does
not grow with the response. For checks that require the complete semantic
response, perform a final `Guard.check(..., GuardStage.FINAL_OUTPUT)` after the
stream finishes.

`Guard.stream(...)`, `Guard.check(..., GuardStage.STREAM)`, and the final-output
check strip invisible Unicode tag, variation-selector, zero-width, and
bidirectional-control channels. `StreamResult.safe_chunk` contains the sanitized
chunk. When constructing `StreamScanner` directly, include
`InvisibleUnicodeRule` in its custom rule list or rely on the required final
`Guard` check before rendering.

The scanner catches rule exceptions to keep streaming responsive. If your
security requirements demand fail-closed provider behavior, validate the final
output with the main `Guard` engine before committing a side effect.
