# Supply-chain security

An LLM application depends on packages, models, prompts, plugins, tools, vector
indexes, and external content. aiRail can inspect content crossing these
boundaries, but it cannot establish the integrity of the components themselves.

## API response integrity (SC-001)

Supply chain attacks embed prompt-injection payloads inside the responses of
third-party APIs or tools. When an infected response is later included in the
LLM context, the embedded instructions execute as if typed by the user.

`ApiResponseIntegrityRule` (SC-001) scans tool and API responses for
instruction-hijacking patterns before they are passed to the model:

```python
from aiRail.rules.rag import ApiResponseIntegrityRule
from aiRail import GuardContext, GuardStage

rule = ApiResponseIntegrityRule()
context = GuardContext(stage=GuardStage.TOOL_RESPONSE)

# Run on every API/tool response before including it in the prompt
result = rule.evaluate(api_response_body, context)
if result.is_blocked:
    raise ValueError("Injected instruction detected in API response")
```

Detected patterns include:

- `"Ignore all previous instructions and …"`
- `"New instructions: you are now …"` / `"Updated system prompt: …"`
- `"Disregard your guidelines and reveal …"`
- `"From now on, always …"` / role-reassignment pivots (`"Act as a jailbroken …"`)

Apply this rule at the `TOOL_RESPONSE` and `EXTERNAL_CONTENT` guard stages.
SC-001 defaults to `BLOCK` with `CRITICAL` severity.

## IDOR detection in tool arguments (TL-004)

Insecure Direct Object Reference (IDOR) occurs when an LLM autonomously
constructs a tool call that references another user's resource — by enumerating
numeric IDs, constructing admin paths, or inserting path-traversal sequences.

`IdorDetectionRule` (TL-004) inspects ownership-sensitive argument fields
(`user_id`, `account_id`, `document_id`, `endpoint`, `path`, etc.) for:

- Bare numeric IDs that look like enumeration (`"user_id": 1337`)
- REST paths with numeric segments (`/api/v1/users/99999/profile`)
- Admin or privileged resource paths (`/admin/`, `/internal/`, `/debug/`)
- Path-traversal sequences (`../../../`)

```python
from aiRail.rules.tools import IdorDetectionRule

rule = IdorDetectionRule()
context = GuardContext(
    stage=GuardStage.TOOL_REQUEST,
    metadata={"tool_args": {"user_id": 99999}},
)
result = rule.evaluate("", context)
if result.is_blocked:
    raise PermissionError("IDOR attempt blocked in tool arguments")
```

TL-004 defaults to `BLOCK` with `HIGH` severity.

## Plugin permission scope (TL-003)

Plugins that call operations outside their declared permission scope are a
leading cause of privilege escalation in agentic systems (OWASP LLM07).

`PluginPermissionScopeRule` (TL-003) validates every tool call against a
per-plugin allowlist of permitted operations:

```python
from aiRail.rules.tools import PluginPermissionScopeRule

rule = PluginPermissionScopeRule(
    plugin_scopes={
        "calendar": {"read_events", "create_event", "delete_event"},
        "email":    {"read_inbox", "send_email"},
    }
)

context = GuardContext(
    stage=GuardStage.TOOL_REQUEST,
    metadata={
        "plugin_name": "email",
        "tool_name":   "delete_database",   # out of scope → blocked
    },
)
result = rule.evaluate("", context)
```

Or using the `validate_tool_call` helper directly:

```python
result = rule.validate_tool_call(tool_call, context, plugin_name="email")
```

Plugins not present in `plugin_scopes` are allowed through (the rule only
enforces scopes it knows about). TL-003 defaults to `BLOCK` with `HIGH`
severity.

## Recommended controls

- Pin dependencies and review lockfile changes.
- Run dependency and secret scanning in CI.
- Verify model, prompt, and dataset provenance.
- Restrict who can modify release and publishing workflows.
- Use short-lived credentials and least-privilege service accounts.
- Sign or attest release artifacts where supported.
- Treat tool/plugin output as `TOOL_RESPONSE` and retrieved data as
  `EXTERNAL_CONTENT` or `RAG_DOCUMENT`.
- Rebuild indexes after a compromised source or pipeline is remediated.
- Apply SC-001 at every `TOOL_RESPONSE` boundary, not just on first use.

For aiRail itself, install from PyPI with an exact version in production and
test upgrades against your attack and benign corpora. Trusted Publishing proves
which workflow uploaded an artifact; it does not prove the artifact is free of
vulnerabilities.
