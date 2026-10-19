# MCP resource and prompt integrity

MCP resources, resource templates, prompts, subscriptions, and completion
metadata are untrusted context and control-plane inputs. Pinning tools does not
prevent another primitive from changing after review or injecting instructions
into model context. `MCPPrimitiveGuard` applies one fail-closed lifecycle to all
of these surfaces.

## Workflow

1. Build typed definitions with an application-assigned authenticated
   `server_id`, trusted `provenance_id`, required authorization scopes, size and
   MIME limits, and an optional closed JSON content schema.
2. Call `require_discovery()` and show the exact definitions through a trusted
   review UI.
3. Call `require_approval()` with the unchanged discovery snapshot and persist
   the signed approval outside model and MCP-server control.
4. Fetch the live definition and call `require_use()` immediately before use.
5. Call `validate_resource_content()`, `validate_prompt_render()`, or
   `validate_completion()` before adding returned data to model context or an
   application sink. Pass the approved `MCPSubscriptionIdentity` for an update.

The [runnable example](https://github.com/hasansajedi/trustrail/blob/main/examples/mcp_primitives.py)
shows all four runtime boundaries. A minimal resource boundary is:

```python
import os

from trustrail import MCPPrimitiveGuard, MCPResourceContent, MCPResourceDefinition

resource = MCPResourceDefinition(
    # Both IDs come from authenticated application configuration—not server data.
    server_id="knowledge-production",
    name="handbook",
    description="The reviewed employee handbook.",
    provenance_id="knowledge-store-v3",
    required_scopes=frozenset({"knowledge:read"}),
    uri="https://knowledge.example/resources/handbook",
    mimeType="application/json",
    max_size=64_000,
    contentSchema={
        "type": "object",
        "properties": {"leave_days": {"type": "integer"}},
        "required": ["leave_days"],
        "additionalProperties": False,
    },
)
guard = MCPPrimitiveGuard(os.environ["TRUSTRAIL_MCP_PIN_KEY"].encode())
discovery = guard.require_discovery((resource,))
approval = guard.require_approval(
    (resource,), discovery, approved_by="knowledge-owner"
)

# Construct this only from the authenticated response and authorization layer.
content = MCPResourceContent(
    server_id="knowledge-production",
    uri=resource.uri,
    mimeType="application/json",
    data='{"leave_days":25}',
    provenance_id="knowledge-store-v3",
    granted_scopes=frozenset({"knowledge:read"}),
)
decision = guard.validate_resource_content(resource, content, approval)
if not decision.is_allowed:
    raise RuntimeError("resource must not enter model context")
```

## Configuration

Defaults permit only `https://` and same-server `mcp://` resource URIs,
`https://` icons, and JSON or common text media types. Narrow them for each
deployment:

```python
from trustrail import MCPPrimitiveGuard, MCPPrimitivePolicy

policy = MCPPrimitivePolicy(
    max_primitives=100,
    max_nodes_per_primitive=2_000,
    max_total_string_chars=50_000,
    max_depth=24,
    allowed_uri_schemes=frozenset({"https"}),
    allowed_icon_schemes=frozenset({"https"}),
    allowed_mime_types=frozenset({"application/json", "text/plain"}),
    reject_cross_server_references=True,
    require_closed_content_schemas=True,
)
guard = MCPPrimitiveGuard(signing_key, policy)
```

Template variables must have an explicit `MCPResourceTemplateArgument` with a
regular expression and length ceiling. Prompt arguments are closed: required
arguments must be present and undeclared arguments are rejected. Completion
contracts name the exact prompt or template argument, allowed context keys, and
suggestion bounds. Subscription updates must match an approved subscription,
resource URI, server, provenance, and scope set.

## What is bound and checked

Canonical digests cover every definition field, including annotations and their
extension metadata, icons, URI/template variables, MIME type, schema,
provenance, scopes, and runtime bounds. Signed snapshots bind lifecycle phase,
time, reviewer, primitive set, and per-field digests. Adding, removing, or
changing any primitive requires a new review; findings expose only hashed
identities, safe field paths, and digests.

Definition and live-content checks include model-directed instructions,
compatibility-normalized and invisible Unicode, confusable/shadow names,
cross-server references, credentials/fragments/loopback or private literal IPs
in URIs, malformed templates and MIME types, and configured nesting/size limits.
Runtime checks additionally bind the authenticated server and URI/name,
provenance, authorization scopes, byte/character limits, media type, JSON schema,
template arguments, prompt arguments/messages, subscription identity, and
completion context and suggestions.

## Assumptions, limitations, and residual risk

- The host authenticates the MCP connection and assigns `server_id`,
  `provenance_id`, and granted scopes from trusted state. Server-returned claims
  are not evidence of identity or authorization by themselves.
- The HMAC key, snapshots, approval identity, and review UI remain outside model
  and server control. Use at least 32 random bytes, separate keys per
  environment, protected storage, and explicit rotation that invalidates old
  approvals.
- Complete mediation remains an application responsibility. Validate the exact
  bytes immediately before use and never forward content after a denied result.
- URI checks reject dangerous syntax and literal local addresses but do not
  resolve DNS, follow redirects, validate TLS, or prevent DNS rebinding. Enforce
  DNS/IP/redirect policy and egress controls in the HTTP or MCP gateway.
- The built-in JSON validator intentionally supports a security-oriented subset
  (`type`, `properties`, `required`, `additionalProperties`, `items`, and
  `maxLength`), not full JSON Schema. Perform independent strict validation when
  the application relies on other keywords.
- Static instruction and confusable checks are defense in depth. Novel,
  multilingual, encoded, multimodal, or domain-specific poisoning can evade
  patterns, and benign instructional prompts may need application-specific
  review. Pair this control with content isolation, least privilege, output
  checks, monitoring, and adversarial tests.
- Binary bytes are UTF-8 decoded for the default text/JSON policy. Supporting
  images, audio, PDFs, archives, or custom schemes requires a separate bounded
  parser/scanner and a deliberately expanded policy.
- A valid pin proves definition integrity, not that a remote implementation or
  fetched content is truthful. Use authenticated message integrity, server
  onboarding, runtime authorization, sandboxing, and independent provenance.

Combine this boundary with [tool-definition integrity](mcp-tool-integrity.md),
[message integrity](mcp-message-integrity.md), [OAuth authorization](mcp-oauth.md),
and [server isolation](mcp-server-isolation.md).
