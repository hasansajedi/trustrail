# Migration and upgrades

trustrail follows semantic versioning, but guard decisions can change when rules
improve even if the public API remains compatible.

## Upgrade procedure

1. Pin the target version in a branch.
2. Read the project changelog and release notes.
3. Run unit and integration tests.
4. Replay your labeled benign and adversarial corpus.
5. Compare actions, scores, findings, and latency by rule ID.
6. Review newly blocked benign cases and newly allowed attack cases.
7. Deploy gradually and monitor decision-rate changes.

```bash
python -m pip install --upgrade "trustrail==<target-version>"
python -m pip check
pytest
```

When replacing another guardrail library, run both systems in parallel without
double-blocking. Normalize their outputs into a common evaluation report, define
the acceptance criteria for each boundary, then move enforcement one stage at a
time.

## `protect_messages()` now rejects atomically

`Guard.protect_messages()` no longer removes rejected messages and returns the
remaining entries. A blocked, quarantined, or retry-required entry now raises
`GuardrailBlockedError`; `REQUIRE_APPROVAL` raises `ApprovalRequiredError`.
Allowed transformations preserve role, name, metadata, ordering, and
`tool_call_id` relationships.

Applications that deliberately relied on partial filtering must migrate to the
explicit `Guard.filter_messages()` API and review how removed entries affect
prompt meaning and assistant/tool-call pairing. The OpenAI adapter equivalent is
`filter_openai_messages()`; `protect_openai_messages()` now follows the atomic
behavior.

Message roles are no longer routed through an `else` fallback. The built-in
roles are `system`, `developer`, `user`, `assistant`, and `tool`. Supply a
`role_stages` mapping for any application-specific role. Built-in role mappings
cannot be overridden with a weaker boundary.

## OpenAI adapter preserves structured messages

The OpenAI adapter no longer converts `content=None` to `"None"`, flattens
multipart content, or drops tool calls, refusals, and extension fields.
Unmodified messages now round trip losslessly. Textual multipart fields are
scanned and transformed in place; image, audio, file, and unknown content parts
are retained unchanged and require a separate modality-specific validator when
untrusted. Async adapter functions now use async guard evaluation throughout.

## LangChain and LlamaIndex callbacks now enforce awaited decisions

Async LangChain workloads should replace `AegisRailCallbackHandler` with
`TrustRailAsyncCallbackHandler`; it awaits input decisions instead of scheduling
background checks. Synchronous workloads should use `TrustRailCallbackHandler`.
The old AegisRail names remain compatibility aliases.

LlamaIndex async pipelines should call `aon_query()`, `aon_retrieve()`, and
`aon_llm_response()`. `TrustRailObserver` now raises when every checked RAG node
is rejected unless `empty_retrieval="return_empty"` is configured explicitly.
Unexpected framework guard errors now follow `GuardConfig.fail_mode` in both
integrations.
