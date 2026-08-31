"""Framework integration enforcement, fail-mode, and async lifecycle tests."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from trustrail import GuardAction, GuardrailBlockedError, GuardStage
from trustrail.integrations.langchain import (
    AegisRailAsyncCallbackHandler,
    AegisRailCallbackHandler,
    TrustRailAsyncCallbackHandler,
    TrustRailCallbackHandler,
)
from trustrail.integrations.llamaindex import AegisRailObserver, TrustRailObserver
from trustrail.models.core import GuardContext, GuardResult
from trustrail.models.enums import FailMode


class StaticGuard:
    def __init__(
        self,
        *,
        action: GuardAction = GuardAction.ALLOW,
        transformed_value: str | None = None,
        fail_mode: FailMode = FailMode.CLOSED,
    ) -> None:
        self.action = action
        self.transformed_value = transformed_value
        self.fail_mode = fail_mode
        self.contexts: list[GuardContext] = []

    def _result(self, value: str, stage: GuardStage, context: GuardContext) -> GuardResult:
        self.contexts.append(context)
        return GuardResult(
            action=self.action,
            value=value,
            transformed_value=self.transformed_value,
            stage=stage,
            context=context,
        )

    def check(
        self,
        value: str,
        stage: GuardStage,
        *,
        context: GuardContext,
    ) -> GuardResult:
        return self._result(value, stage, context)

    async def acheck(
        self,
        value: str,
        stage: GuardStage,
        *,
        context: GuardContext,
    ) -> GuardResult:
        await asyncio.sleep(0)
        return self._result(value, stage, context)


class FailingGuard:
    def __init__(self, fail_mode: FailMode) -> None:
        self.fail_mode = fail_mode

    def check(self, value: str, stage: GuardStage, **kwargs: Any) -> GuardResult:
        del value, stage, kwargs
        raise RuntimeError("provider-secret-must-not-be-logged")

    async def acheck(self, value: str, stage: GuardStage, **kwargs: Any) -> GuardResult:
        del value, stage, kwargs
        await asyncio.sleep(0)
        raise RuntimeError("provider-secret-must-not-be-logged")


class Node:
    def __init__(self, text: str, node_id: str = "node-1") -> None:
        self.text = text
        self.node_id = node_id


def test_trustrail_names_export_with_compatibility_aliases() -> None:
    assert AegisRailCallbackHandler is TrustRailCallbackHandler
    assert AegisRailAsyncCallbackHandler is TrustRailAsyncCallbackHandler
    assert AegisRailObserver is TrustRailObserver


def test_sync_blocked_prompt_and_tool_never_reach_provider() -> None:
    guard = StaticGuard(action=GuardAction.BLOCK)
    handler = TrustRailCallbackHandler(guard)  # type: ignore[arg-type]
    provider_calls = 0
    tool_calls = 0

    with pytest.raises(GuardrailBlockedError):
        handler.on_llm_start({}, ["blocked prompt"], run_id=uuid4())
        provider_calls += 1

    with pytest.raises(GuardrailBlockedError):
        handler.on_tool_start({"name": "dangerous"}, "blocked input", run_id=uuid4())
        tool_calls += 1

    assert provider_calls == 0
    assert tool_calls == 0


@pytest.mark.asyncio
async def test_async_handler_awaits_blocking_decision_before_model_invocation() -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    class PausingGuard:
        fail_mode = FailMode.CLOSED

        async def acheck(
            self,
            value: str,
            stage: GuardStage,
            *,
            context: GuardContext,
        ) -> GuardResult:
            del context
            started.set()
            await release.wait()
            return GuardResult(action=GuardAction.BLOCK, value=value, stage=stage)

    handler = TrustRailAsyncCallbackHandler(PausingGuard())  # type: ignore[arg-type]
    task = asyncio.create_task(handler.on_llm_start({}, ["blocked"], run_id=uuid4()))
    await asyncio.wait_for(started.wait(), timeout=1)

    assert not task.done()
    release.set()
    with pytest.raises(GuardrailBlockedError):
        await task


@pytest.mark.asyncio
async def test_async_handler_propagates_cancellation_without_orphaning_check() -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class CancellableGuard:
        fail_mode = FailMode.CLOSED

        async def acheck(
            self,
            value: str,
            stage: GuardStage,
            *,
            context: GuardContext,
        ) -> GuardResult:
            del context
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return GuardResult(value=value, stage=stage)

    handler = TrustRailAsyncCallbackHandler(CancellableGuard())  # type: ignore[arg-type]
    task = asyncio.create_task(handler.on_llm_start({}, ["prompt"], run_id=uuid4()))
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()


def test_langchain_applies_mutable_transformations_and_blocks_immutable_inputs() -> None:
    guard = StaticGuard(transformed_value="safe value")
    handler = TrustRailCallbackHandler(guard)  # type: ignore[arg-type]
    prompts = ["unsafe value"]
    generation = SimpleNamespace(text="unsafe value")

    handler.on_llm_start({}, prompts, run_id=uuid4())
    handler.on_llm_end(SimpleNamespace(generations=[[generation]]), run_id=uuid4())

    assert prompts == ["safe value"]
    assert generation.text == "safe value"
    with pytest.raises(GuardrailBlockedError, match="could not be applied"):
        handler.on_tool_start({"name": "tool"}, "unsafe value", run_id=uuid4())


@pytest.mark.parametrize("fail_mode", [FailMode.OPEN, FailMode.CLOSED])
def test_langchain_sync_provider_errors_honor_fail_mode(fail_mode: FailMode) -> None:
    handler = TrustRailCallbackHandler(FailingGuard(fail_mode))  # type: ignore[arg-type]

    if fail_mode == FailMode.CLOSED:
        with pytest.raises(GuardrailBlockedError, match="failed closed"):
            handler.on_llm_start({}, ["prompt"], run_id=uuid4())
    else:
        handler.on_llm_start({}, ["prompt"], run_id=uuid4())


@pytest.mark.parametrize("fail_mode", [FailMode.OPEN, FailMode.CLOSED])
@pytest.mark.asyncio
async def test_langchain_async_provider_errors_honor_fail_mode(fail_mode: FailMode) -> None:
    handler = TrustRailAsyncCallbackHandler(FailingGuard(fail_mode))  # type: ignore[arg-type]

    if fail_mode == FailMode.CLOSED:
        with pytest.raises(GuardrailBlockedError, match="failed closed"):
            await handler.on_llm_start({}, ["prompt"], run_id=uuid4())
    else:
        await handler.on_llm_start({}, ["prompt"], run_id=uuid4())


@pytest.mark.asyncio
async def test_langchain_propagates_run_request_and_tenant_context() -> None:
    guard = StaticGuard()
    handler = TrustRailAsyncCallbackHandler(guard)  # type: ignore[arg-type]
    run_id = uuid4()
    parent_run_id = uuid4()

    await handler.on_llm_start(
        {"name": "fake-model"},
        ["prompt"],
        run_id=run_id,
        parent_run_id=parent_run_id,
        metadata={"request_id": "request-1", "tenant_id": "tenant-1"},
        tags=["integration"],
    )

    context = guard.contexts[0]
    assert context.request_id == "request-1"
    assert context.session_id == str(parent_run_id)
    assert context.tenant_id == "tenant-1"
    assert context.metadata["run_id"] == str(run_id)
    assert context.tags == ["integration"]


def test_blocked_llamaindex_query_never_reaches_retriever() -> None:
    observer = TrustRailObserver(StaticGuard(action=GuardAction.BLOCK))  # type: ignore[arg-type]
    retriever_calls = 0

    with pytest.raises(GuardrailBlockedError):
        observer.on_query("blocked query", request_id="request-1")
        retriever_calls += 1

    assert retriever_calls == 0


@pytest.mark.asyncio
async def test_async_blocked_llamaindex_query_never_reaches_retriever() -> None:
    observer = TrustRailObserver(StaticGuard(action=GuardAction.BLOCK))  # type: ignore[arg-type]
    retriever_calls = 0

    with pytest.raises(GuardrailBlockedError):
        await observer.aon_query("blocked query", request_id="request-1")
        retriever_calls += 1

    assert retriever_calls == 0


def test_llamaindex_transforms_nodes_and_propagates_context() -> None:
    guard = StaticGuard(transformed_value="safe document")
    observer = TrustRailObserver(guard)  # type: ignore[arg-type]
    node = Node("unsafe document", node_id="node-42")

    safe_nodes = observer.on_retrieve(
        [node],
        run_id="run-1",
        request_id="request-1",
        tenant_id="tenant-1",
    )

    assert safe_nodes == [node]
    assert node.text == "safe document"
    context = guard.contexts[0]
    assert context.request_id == "request-1"
    assert context.tenant_id == "tenant-1"
    assert context.metadata["run_id"] == "run-1"
    assert context.metadata["node_id"] == "node-42"


def test_llamaindex_all_blocked_nodes_behavior_is_explicit() -> None:
    guard = StaticGuard(action=GuardAction.BLOCK)
    nodes = [Node("blocked one"), Node("blocked two")]

    with pytest.raises(GuardrailBlockedError, match="All retrieved RAG nodes"):
        TrustRailObserver(guard).on_retrieve(nodes)  # type: ignore[arg-type]

    assert (
        TrustRailObserver(  # type: ignore[arg-type]
            guard,
            empty_retrieval="return_empty",
        ).on_retrieve(nodes)
        == []
    )


@pytest.mark.parametrize("fail_mode", [FailMode.OPEN, FailMode.CLOSED])
def test_llamaindex_sync_provider_errors_honor_fail_mode(fail_mode: FailMode) -> None:
    observer = TrustRailObserver(FailingGuard(fail_mode))  # type: ignore[arg-type]

    if fail_mode == FailMode.CLOSED:
        with pytest.raises(GuardrailBlockedError, match="failed closed"):
            observer.on_query("query")
        with pytest.raises(GuardrailBlockedError, match="All retrieved RAG nodes"):
            observer.on_retrieve([Node("document")])
    else:
        assert observer.on_query("query") == "query"
        node = Node("document")
        assert observer.on_retrieve([node]) == [node]


@pytest.mark.parametrize("fail_mode", [FailMode.OPEN, FailMode.CLOSED])
@pytest.mark.asyncio
async def test_llamaindex_async_provider_errors_honor_fail_mode(fail_mode: FailMode) -> None:
    observer = TrustRailObserver(FailingGuard(fail_mode))  # type: ignore[arg-type]

    if fail_mode == FailMode.CLOSED:
        with pytest.raises(GuardrailBlockedError, match="failed closed"):
            await observer.aon_query("query")
        with pytest.raises(GuardrailBlockedError, match="All retrieved RAG nodes"):
            await observer.aon_retrieve([Node("document")])
    else:
        assert await observer.aon_query("query") == "query"
        node = Node("document")
        assert await observer.aon_retrieve([node]) == [node]


@pytest.mark.asyncio
async def test_llamaindex_async_retrieval_propagates_cancellation() -> None:
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class CancellableGuard:
        fail_mode = FailMode.CLOSED

        async def acheck(
            self,
            value: str,
            stage: GuardStage,
            *,
            context: GuardContext,
        ) -> GuardResult:
            del context
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return GuardResult(value=value, stage=stage)

    observer = TrustRailObserver(CancellableGuard())  # type: ignore[arg-type]
    task = asyncio.create_task(observer.aon_retrieve([Node("document")]))
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()


def test_llamaindex_immutable_transformed_node_is_blocked() -> None:
    class ImmutableNode:
        @property
        def text(self) -> str:
            return "unsafe document"

    observer = TrustRailObserver(  # type: ignore[arg-type]
        StaticGuard(transformed_value="safe document")
    )

    with pytest.raises(GuardrailBlockedError, match="All retrieved RAG nodes"):
        observer.on_retrieve([ImmutableNode()])


def test_real_guard_exposes_read_only_fail_mode() -> None:
    from trustrail import Guard, GuardConfig

    guard = Guard(GuardConfig(fail_mode=FailMode.OPEN, audit_enabled=False))

    assert guard.fail_mode == FailMode.OPEN
