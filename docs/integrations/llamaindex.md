# LlamaIndex integration

```bash
python -m pip install "trustrail[llamaindex]"
```

`AegisRailObserver` exposes explicit hooks for the query, retrieved nodes, and
final model response:

```python
from trustrail import Guard
from trustrail.integrations.llamaindex import AegisRailObserver

observer = AegisRailObserver(Guard.balanced(), raise_on_block=True)

safe_query = observer.on_query(user_query)
nodes = retriever.retrieve(safe_query)
safe_nodes = observer.on_retrieve(nodes)
response = query_engine.synthesize(safe_query, nodes=safe_nodes)
safe_response = observer.on_llm_response(str(response))
```

Retrieved objects must expose either a `text` or `content` attribute. Blocked
nodes are removed while their finding is logged. Nodes without text pass through
unchanged.

The observer is an adapter, not automatic global registration. Call its hooks in
your pipeline or connect them to the event/dispatcher API used by your installed
LlamaIndex version. Always preserve source metadata separately for audit and
provenance decisions.
