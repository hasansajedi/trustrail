# LlamaIndex integration

```bash
python -m pip install "trustrail[llamaindex]"
```

`TrustRailObserver` provides explicit boundaries for a query, retrieved nodes,
and the final model response:

```python
from trustrail import Guard
from trustrail.integrations.llamaindex import TrustRailObserver

observer = TrustRailObserver(Guard.balanced())

safe_query = observer.on_query(
    user_query,
    request_id=request_id,
    tenant_id=tenant_id,
)
nodes = retriever.retrieve(safe_query)
safe_nodes = observer.on_retrieve(
    nodes,
    request_id=request_id,
    tenant_id=tenant_id,
)
response = query_engine.synthesize(safe_query, nodes=safe_nodes)
safe_response = observer.on_llm_response(
    str(response),
    request_id=request_id,
    tenant_id=tenant_id,
)
```

Use the awaited hooks in an async RAG pipeline:

```python
safe_query = await observer.aon_query(user_query, request_id=request_id)
nodes = await retriever.aretrieve(safe_query)
safe_nodes = await observer.aon_retrieve(nodes, request_id=request_id)
response = await query_engine.asynthesize(safe_query, nodes=safe_nodes)
safe_response = await observer.aon_llm_response(str(response), request_id=request_id)
```

Async hooks await every decision and propagate cancellation. Unexpected guard
or provider errors follow `GuardConfig.fail_mode`: closed mode rejects the
unchecked value or node, while open mode logs the exception type and retains the
original.

Retrieved objects must expose `text` or `content`. When a guard transforms a
document, the observer applies it through `set_content()` or a writable text
attribute. An object that cannot accept the safe value is rejected. Nodes
without text pass through unchanged.

If every checked node is blocked, failed closed, or unable to accept a required
transformation, the observer raises `GuardrailBlockedError` by default. Systems
whose retrieval layer explicitly supports an empty context can opt in:

```python
observer = TrustRailObserver(guard, empty_retrieval="return_empty")
```

The observer is an adapter, not automatic global registration. Call its hooks
in the pipeline or connect them to the event API used by the installed
LlamaIndex version. Request, run, session, user, tenant, and node identifiers
are propagated into `GuardContext` for audit correlation.

`AegisRailObserver` remains a compatibility alias. New code should import
`TrustRailObserver`.
