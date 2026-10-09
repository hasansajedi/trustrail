# Runnable examples

The repository contains offline examples that use local stand-ins and do not
make model-provider calls. Clone the repository and run an example from its root:

```bash
uv run python examples/basic_input.py
uv run python examples/mcp_oauth.py
```

The complete annotated index lives in
[`examples/README.md`](https://github.com/hasansajedi/trustrail/blob/main/examples/README.md).
Use the [feature catalog](features.md) to find the security guide and API for
each example.

## Recommended paths

### First guardrail

1. [`basic_input.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/basic_input.py)
2. [`configuration_and_audit.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/configuration_and_audit.py)
3. [`conversation.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/conversation.py)
4. [`output_handling.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/output_handling.py)

### RAG and persistent data

- [`rag_example.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/rag_example.py)
- [`secure_vector_workflow.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/secure_vector_workflow.py)
- [`data_poisoning.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/data_poisoning.py)
- [`persistent_memory.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/persistent_memory.py)
- [`memory_taint.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/memory_taint.py)
- [`tenant_isolation.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/tenant_isolation.py)

### Agents, tools, and high-impact actions

- [`agent.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/agent.py)
- [`goal_integrity.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/goal_integrity.py)
- [`delegated_identity.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/delegated_identity.py)
- [`tool_authorization.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/tool_authorization.py)
- [`semantic_tool_authorization.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/semantic_tool_authorization.py)
- [`high_impact_approval.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/high_impact_approval.py)
- [`credential_brokering.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/credential_brokering.py)
- [`isolated_code_execution.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/isolated_code_execution.py)
- [`cascading_failures.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/cascading_failures.py)

### MCP authorization

[`mcp_oauth.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/mcp_oauth.py)
shows an end-to-end resource-server flow:

1. configure a pinned issuer, audience, resource, server, scopes, tools, and
   argument resource pointers;
2. validate a dedicated `tools/list` token and filter discovery;
3. validate a new request-bound `tools/call` token;
4. authorize the exact tool and account argument; and
5. acquire a workload-owned downstream credential without forwarding the
   caller's bearer token.

Read [MCP OAuth authorization](security/mcp-oauth.md) before adapting the local
token issuer or credential provider to production.

## Framework and provider integrations

Framework examples depend on application objects and therefore live in their
integration guides:

- [OpenAI](integrations/openai.md)
- [FastAPI](integrations/fastapi.md)
- [LangChain](integrations/langchain.md)
- [LlamaIndex](integrations/llamaindex.md)
- [external safety providers](integrations/external-safety-providers.md)
- [OpenTelemetry](observability.md)
- [Redis-backed state](guides/rate-limiting.md)

## What examples intentionally omit

The local implementations of approval verifiers, vaults, replay stores, and
audit sinks are suitable for learning and tests. Production systems need
authenticated external services, protected keys, durable shared atomic state,
rate limiting, transport security, downstream authorization, and monitoring.
Never derive tenant, user, ownership, scope, approval, or policy facts from
prompt text or model output.
