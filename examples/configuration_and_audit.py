"""Configure redaction and inspect privacy-preserving audit events."""

import asyncio

from trustrail import Guard, GuardConfig, GuardContext, GuardStage, SensitiveDataMode
from trustrail.audit import MemoryAuditSink


async def main() -> None:
    audit_sink = MemoryAuditSink(max_events=100)
    guard = Guard(
        config=GuardConfig(
            sensitive_data_mode=SensitiveDataMode.REDACT,
            audit_enabled=True,
            audit_include_metadata=True,
        ),
        audit_sink=audit_sink,
    )
    context = GuardContext(
        request_id="request-42",
        session_id="session-7",
        user_id="authenticated-user",
        tenant_id="tenant-a",
        tags=["example"],
    )

    safe_value = await guard.aprotect(
        "Contact alice@example.com about the report.",
        GuardStage.USER_INPUT,
        context=context,
    )
    event = audit_sink.events[-1]

    print(f"Safe downstream value: {safe_value}")
    print(f"Audit action: {event.action.value}")
    print(f"Audit finding IDs: {event.finding_ids}")
    assert "alice@example.com" not in safe_value
    assert "alice@example.com" not in event.model_dump_json()


if __name__ == "__main__":
    asyncio.run(main())
