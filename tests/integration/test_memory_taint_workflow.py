"""Integration coverage for persistent-memory lineage and incident response."""

from datetime import UTC, datetime

from trustrail import (
    GuardAction,
    MemoryContentKind,
    MemoryDependency,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRebuildPlan,
    MemoryRecord,
    MemoryScope,
    MemorySourceKind,
    MemoryTaintManager,
    MemoryTaintPolicy,
    MemoryTaintStatus,
    MemoryTransformationKind,
    MemoryWriteRequest,
    TrustLevel,
)

NOW = datetime(2026, 9, 2, 12, tzinfo=UTC)


def test_storage_retrieval_and_lineage_wide_quarantine_workflow() -> None:
    rebuilds: list[MemoryRebuildPlan] = []

    class RebuildQueue:
        def request_rebuild(self, plan: MemoryRebuildPlan) -> None:
            rebuilds.append(plan)

    manager = MemoryTaintManager(
        MemoryTaintPolicy(
            trusted_writer_ids=frozenset({"memory-service"}),
            allowed_purpose_ids=frozenset({"assistant-memory"}),
        ),
        rebuild_hook=RebuildQueue(),
    )
    backend: dict[str, str] = {}
    source_content = "The account uses monthly billing."
    provenance = (
        MemoryProvenance(
            source_id="account-database-row-42",
            source_kind=MemorySourceKind.TOOL,
            trust_level=TrustLevel.TRUSTED,
            writer_id="memory-service",
            tenant_id="tenant-a",
            purpose_id="assistant-memory",
            observed_at=NOW,
        ),
    )
    source = MemoryRecord.create(
        content=source_content,
        memory_id="account-fact",
        tenant_id="tenant-a",
        owner_user_id="user-1",
        writer_id="memory-service",
        purpose_id="assistant-memory",
        content_kind=MemoryContentKind.FACT,
        scope=MemoryScope.USER,
        transformation=MemoryTransformationKind.DIRECT,
        provenance=provenance,
        created_at=NOW,
    )

    def persist(record: MemoryRecord, content: str) -> MemoryRecord:
        request = MemoryWriteRequest.create(
            request_id=f"write-{record.memory_id}",
            actor_id="memory-service",
            actor_user_id="user-1",
            tenant_id="tenant-a",
            purpose_id="assistant-memory",
            record=record,
        )
        lease = manager.require_write(request, content, now=NOW)
        backend[record.memory_id] = content
        committed = manager.commit_write(lease, backend[record.memory_id], now=NOW)
        assert committed.record is not None
        return committed.record

    committed_source = persist(source, source_content)
    summary_content = "Billing cadence: monthly."
    summary = MemoryRecord.create(
        content=summary_content,
        memory_id="account-summary",
        tenant_id="tenant-a",
        owner_user_id="user-1",
        writer_id="memory-service",
        purpose_id="assistant-memory",
        content_kind=MemoryContentKind.SUMMARY,
        scope=MemoryScope.USER,
        transformation=MemoryTransformationKind.SUMMARY,
        provenance=provenance,
        dependencies=(
            MemoryDependency(
                memory_id=committed_source.memory_id,
                record_digest=committed_source.record_digest,
            ),
        ),
        created_at=NOW,
    )
    committed_summary = persist(summary, summary_content)

    read_request = MemoryReadRequest(
        request_id="read-account-memory",
        reader_id="assistant-service",
        reader_user_id="user-1",
        tenant_id="tenant-a",
        purpose_id="assistant-memory",
        memory_ids=(committed_source.memory_id, committed_summary.memory_id),
    )
    allowed = manager.authorize_retrieval(read_request, backend, now=NOW)
    assert allowed.action == GuardAction.ALLOW

    backend[committed_source.memory_id] = "Attacker replaced the stored bytes."
    denied = manager.authorize_retrieval(read_request, backend, now=NOW)
    incident = manager.quarantine(
        committed_source.memory_id,
        reason_code="storage-integrity-incident",
        now=NOW,
    )

    assert denied.action == GuardAction.BLOCK
    assert [record.taint_status for record in manager.records] == [
        MemoryTaintStatus.QUARANTINED,
        MemoryTaintStatus.QUARANTINED,
    ]
    assert incident.rebuild_plan is not None
    assert incident.rebuild_plan.affected_memory_ids == (
        "account-fact",
        "account-summary",
    )
    assert incident.rebuild_plan.authoritative_source_ids == ("account-database-row-42",)
    assert rebuilds == [incident.rebuild_plan]
