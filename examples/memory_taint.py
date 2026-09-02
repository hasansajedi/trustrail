"""Preserve provenance and taint state across persistent-memory operations."""

from datetime import UTC, datetime

from trustrail import (
    MemoryContentKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryScope,
    MemorySourceKind,
    MemoryTaintAuditBuffer,
    MemoryTaintManager,
    MemoryTaintPolicy,
    MemoryTransformationKind,
    MemoryWriteRequest,
    TrustLevel,
)


def main() -> None:
    now = datetime(2026, 9, 2, tzinfo=UTC)
    content = "The workspace uses Python 3.12."
    audit = MemoryTaintAuditBuffer()
    manager = MemoryTaintManager(
        MemoryTaintPolicy(
            trusted_writer_ids=frozenset({"memory-service"}),
            allowed_purpose_ids=frozenset({"assistant-memory"}),
        ),
        audit_sink=audit,
    )
    provenance = MemoryProvenance(
        source_id="workspace-manifest",
        source_kind=MemorySourceKind.TOOL,
        trust_level=TrustLevel.TRUSTED,
        writer_id="memory-service",
        tenant_id="tenant-a",
        purpose_id="assistant-memory",
        observed_at=now,
    )
    record = MemoryRecord.create(
        content=content,
        memory_id="workspace-runtime",
        tenant_id="tenant-a",
        owner_user_id="user-42",
        writer_id="memory-service",
        purpose_id="assistant-memory",
        content_kind=MemoryContentKind.FACT,
        scope=MemoryScope.USER,
        transformation=MemoryTransformationKind.DIRECT,
        provenance=(provenance,),
        created_at=now,
    )
    request = MemoryWriteRequest.create(
        request_id="write-workspace-runtime",
        actor_id="memory-service",
        actor_user_id="user-42",
        tenant_id="tenant-a",
        purpose_id="assistant-memory",
        record=record,
    )

    # The application owns content storage. The manager stores only security metadata.
    lease = manager.require_write(request, content, now=now)
    backend = {record.memory_id: content}
    manager.commit_write(lease, backend[record.memory_id], now=now)

    read = MemoryReadRequest(
        request_id="read-workspace-runtime",
        reader_id="assistant-service",
        reader_user_id="user-42",
        tenant_id="tenant-a",
        purpose_id="assistant-memory",
        memory_ids=(record.memory_id,),
    )
    safe_records = manager.require_retrieval(read, backend, now=now)

    print(safe_records[0].memory_id)
    print([event.kind for event in audit.events])


if __name__ == "__main__":
    main()
