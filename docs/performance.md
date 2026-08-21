# Performance

`Guard.check` runs deterministic rules synchronously. `Guard.acheck` moves that
work to a thread so async request handlers do not block the event loop.

```python
result = guard.check(text, GuardStage.USER_INPUT)          # synchronous code
result = await guard.acheck(text, GuardStage.USER_INPUT)  # async applications
```

Use `result.latency_ms` and `result.rules_evaluated` to measure real workloads.
Benchmark benign and adversarial inputs across representative lengths; regex and
normalization costs may differ significantly by content.

## Operational recommendations

- Reuse a configured `Guard` rather than constructing one per request.
- Reject oversized requests before guard evaluation.
- Keep custom rules deterministic, bounded, and free of network calls.
- Use provider protocols for remote checks and set explicit timeouts.
- Create one `StreamScanner` per response; do not share scanner state.
- Measure p50, p95, and p99 latency by stage and input-size bucket.

Do not disable a security category based only on synthetic throughput. Measure
the end-to-end application and document the coverage tradeoff.
