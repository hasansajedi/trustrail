# API reference

The primary public imports are available directly from `trustrail`:

```python
from trustrail import Guard, GuardAction, GuardContext, GuardStage
```

Start with [`Guard`](guard.md), then use the model and enum reference when you
need to construct contextual checks or inspect structured results. The
[feature catalog](../features.md) maps every implemented control to its primary
runtime API, typed models, security guide, and runnable example.

## API groups

| Group | Main modules and entry points | Reference |
| --- | --- | --- |
| Guard engine | `Guard`, configuration, policies, rules, protocols | [Guard](guard.md) · [rules](rules.md) · [policies](../policies.md) |
| Content boundaries | prompt injection, sensitive data, RAG, output handling, streaming | [Models](models.md) · [streaming](advanced.md#streaming) |
| Agent security | tool authorization, identity, goals, approvals, privileges, credentials, workflows, code execution | [Advanced APIs](advanced.md) · [models](models.md) |
| Data and model security | memory, labels, lifecycle, tenant isolation, vector, poisoning, training data, supply chain | [Advanced APIs](advanced.md) · [models](models.md) |
| MCP security | tool definitions, onboarding, OAuth, signed messages, server isolation | [MCP models](models.md#mcp-tool-definition-integrity) |
| Testing and operations | audit sinks, red-team runner, campaign runner, state backends, integrations | [Advanced APIs](advanced.md#adaptive-red-team-regression) |

Core guard, authorization, security-control, and model names are exported from
`trustrail`. Integration, streaming, state-backend, observability, and testing
utilities are imported from their documented subpackages. Internal helpers and
underscored names are not compatibility promises. Prefer root imports when an
API is available there:

```python
from trustrail import MCPOAuthPolicy, MCPOAuthResourceServer, ToolAuthorizer
```

## Public package

::: trustrail
    options:
      members: true
      show_root_heading: false
      show_root_toc_entry: false
