"""Redact and approve a persistent-memory write before storing it."""

import asyncio

from trustrail import Guard, GuardContext, GuardStage
from trustrail.audit import MemoryAuditSink


class ReviewQueue:
    """Demo approval provider; production approval must be out of band."""

    async def request_approval(
        self,
        value: str,
        context: GuardContext | None = None,
        reason: str = "",
    ) -> bool:
        print(f"Reviewing {value!r}: {reason}")
        # A real provider binds the decision to an authenticated reviewer and
        # the exact request instead of automatically approving it.
        return True


async def main() -> None:
    audit_sink = MemoryAuditSink()
    guard = Guard(audit_sink=audit_sink, approval_provider=ReviewQueue())
    context = GuardContext(
        request_id="request-42",
        session_id="session-7",
        user_id="authenticated-user",
        tenant_id="tenant-a",
        stage=GuardStage.MEMORY_WRITE,
    )

    safe_value = await guard.authorize_memory_write(
        "My notification email is alice@example.com.",
        persistent=True,
        context=context,
    )

    # Store only safe_value after approval; never store the original proposal.
    memory_store: dict[str, str] = {}
    memory_store["notification-preference"] = safe_value
    print(memory_store)
    print([event.memory_approval_outcome for event in audit_sink.events])


if __name__ == "__main__":
    asyncio.run(main())
