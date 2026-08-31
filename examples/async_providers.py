"""Run moderation and RAG grounding providers through Guard.acheck()."""

from __future__ import annotations

import asyncio

from trustrail import (
    Document,
    FailMode,
    Guard,
    GuardConfig,
    GuardStage,
    ProviderRegistration,
)
from trustrail.testing import FakeGroundingVerifier, FakeModerationProvider


async def main() -> None:
    moderation = FakeModerationProvider(trigger_keywords=["REMOTE_POLICY_TRIGGER"])
    grounding = FakeGroundingVerifier(always_grounded=False)
    guard = Guard(
        GuardConfig(
            audit_enabled=False,
            provider_timeout_seconds=2.0,
            max_async_concurrency=4,
        ),
        content_safety_providers=[
            ProviderRegistration(
                provider_id="primary-moderation",
                provider=moderation,
                timeout_seconds=1.0,
                fail_mode=FailMode.CLOSED,
            )
        ],
        grounding_verifiers=[
            ProviderRegistration(
                provider_id="rag-grounding",
                provider=grounding,
                timeout_seconds=1.5,
                fail_mode=FailMode.CLOSED,
            )
        ],
    )

    moderation_result = await guard.acheck(
        "REMOTE_POLICY_TRIGGER",
        GuardStage.FINAL_OUTPUT,
    )
    print("Moderation:", moderation_result.action.value)

    documents = [
        Document(
            content="The support plan includes email assistance.",
            source="reviewed-support-policy",
        )
    ]
    grounding_result = await guard.acheck(
        "This answer contains a made up benefit.",
        GuardStage.LLM_RESPONSE,
        documents=documents,
    )
    print("Grounding:", grounding_result.action.value)


if __name__ == "__main__":
    asyncio.run(main())
