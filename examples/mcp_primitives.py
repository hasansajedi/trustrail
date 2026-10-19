"""Pin and validate MCP resources, prompts, subscriptions, and completions."""

from trustrail import (
    MCPCompletionDefinition,
    MCPCompletionMetadata,
    MCPPrimitiveGuard,
    MCPPrimitivePolicy,
    MCPPromptArgument,
    MCPPromptDefinition,
    MCPPromptMessage,
    MCPPromptRender,
    MCPResourceContent,
    MCPResourceDefinition,
    MCPSubscriptionIdentity,
)


def main() -> None:
    resource = MCPResourceDefinition(
        server_id="knowledge.example",
        name="handbook",
        description="The reviewed employee handbook.",
        provenance_id="knowledge-production",
        required_scopes=frozenset({"knowledge:read"}),
        uri="https://knowledge.example/resources/handbook",
        mimeType="application/json",
        max_size=4_096,
        contentSchema={
            "type": "object",
            "properties": {"leave_days": {"type": "integer"}},
            "required": ["leave_days"],
            "additionalProperties": False,
        },
    )
    prompt = MCPPromptDefinition(
        server_id="knowledge.example",
        name="answer-policy-question",
        description="Answer a question using the reviewed handbook.",
        provenance_id="knowledge-production",
        required_scopes=frozenset({"prompts:read"}),
        arguments=(
            MCPPromptArgument(
                name="question", description="The user's policy question.", required=True
            ),
        ),
    )
    subscription = MCPSubscriptionIdentity(
        server_id="knowledge.example",
        name="handbook-updates",
        description="Approved updates to the employee handbook.",
        provenance_id="knowledge-production",
        required_scopes=frozenset({"knowledge:read"}),
        subscription_id="handbook-subscription",
        event_type="resource_updated",
        resource_uri=resource.uri,
    )
    completion = MCPCompletionDefinition(
        server_id="knowledge.example",
        name="question-completion",
        description="Reviewed suggestions for a policy question.",
        provenance_id="knowledge-production",
        required_scopes=frozenset({"prompts:read"}),
        reference_kind="prompt",
        reference_name=prompt.name,
        argument_name="question",
        max_values=5,
    )
    definitions = (resource, prompt, subscription, completion)
    policy = MCPPrimitivePolicy(
        allowed_uri_schemes=frozenset({"https"}),
        allowed_mime_types=frozenset({"application/json"}),
        max_total_string_chars=50_000,
    )
    guard = MCPPrimitiveGuard(b"replace-with-a-secret-key-of-32-bytes", policy)

    # Persist both snapshots in protected application storage. In production,
    # approval happens only after a trusted UI presents the exact definitions.
    discovery = guard.require_discovery(definitions)
    approval = guard.require_approval(definitions, discovery, approved_by="knowledge-owner")

    content = MCPResourceContent(
        server_id="knowledge.example",
        uri=resource.uri,
        mimeType="application/json",
        data='{"leave_days":25}',
        provenance_id="knowledge-production",
        granted_scopes=frozenset({"knowledge:read"}),
        subscription_id=subscription.subscription_id,
    )
    render = MCPPromptRender(
        server_id="knowledge.example",
        prompt_name=prompt.name,
        arguments={"question": "How much annual leave is provided?"},
        messages=(MCPPromptMessage(role="user", content="Answer the leave question."),),
        provenance_id="knowledge-production",
        granted_scopes=frozenset({"prompts:read"}),
    )
    suggestions = MCPCompletionMetadata(
        server_id="knowledge.example",
        reference_kind="prompt",
        reference_name=prompt.name,
        argument_name="question",
        values=("How much annual leave is provided?",),
        total=1,
        has_more=False,
        provenance_id="knowledge-production",
        granted_scopes=frozenset({"prompts:read"}),
    )

    guard.validate_resource_content(
        resource, content, approval, subscription=subscription
    ).model_dump_json()
    guard.validate_prompt_render(prompt, render, approval).model_dump_json()
    guard.validate_completion(completion, suggestions, approval).model_dump_json()
    print("All MCP context primitives verified")


if __name__ == "__main__":
    main()
