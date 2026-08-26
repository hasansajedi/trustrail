"""Atomic resource budgets and bounded decompression for OWASP LLM10:2025."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
import zlib
from collections import OrderedDict, deque
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from typing import TypeVar

from trustrail.exceptions import ResourceBudgetError
from trustrail.models.enums import GuardAction
from trustrail.models.resource import (
    CompressedPayloadRequest,
    CompressionFormat,
    ConsumptionBudgetPolicy,
    DecompressionResult,
    ResourceBudgetResult,
    ResourceCompletionRequest,
    ResourceLease,
    ResourceLimitCode,
    ResourceLimitFinding,
    ResourceOperationKind,
    ResourceReservationRequest,
    ResourceUsageSignal,
)

_OPEN_XML_TAG_RE = re.compile(r"<(?!/|!|\?)[A-Za-z_:][^<>]{0,255}(?<!/)>")
_CLOSE_XML_TAG_RE = re.compile(r"</[A-Za-z_:][^<>]{0,255}>")
_WindowKey = TypeVar("_WindowKey", bound=Hashable)


def measure_structured_nesting(value: str) -> int:
    """Measure JSON-like and XML nesting without parsing or recursion."""
    json_depth = 0
    max_json_depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            json_depth += 1
            max_json_depth = max(max_json_depth, json_depth)
        elif character in "}]":
            json_depth = max(0, json_depth - 1)

    xml_depth = 0
    max_xml_depth = 0
    position = 0
    while position < len(value):
        opening = _OPEN_XML_TAG_RE.search(value, position)
        closing = _CLOSE_XML_TAG_RE.search(value, position)
        if opening is not None and (closing is None or opening.start() < closing.start()):
            xml_depth += 1
            max_xml_depth = max(max_xml_depth, xml_depth)
            position = opening.end()
        elif closing is not None:
            xml_depth = max(0, xml_depth - 1)
            position = closing.end()
        else:
            break
    return max(max_json_depth, max_xml_depth)


@dataclass
class _SessionState:
    first_seen: float
    tokens_reserved: int = 0
    tool_actions: int = 0
    operation_attempts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class _LeaseState:
    lease: ResourceLease
    principal_id: str
    tenant_id: str
    expires_at: float


class ResourceBudgetManager:
    """Atomically reserve model and agent capacity across trusted identities."""

    def __init__(
        self,
        policy: ConsumptionBudgetPolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._clock = clock
        self._lock = asyncio.Lock()
        self._sessions: dict[tuple[str, str], _SessionState] = {}
        self._principal_windows: dict[tuple[str, str], deque[float]] = {}
        self._tenant_windows: dict[str, deque[float]] = {}
        self._principal_active: dict[tuple[str, str], int] = {}
        self._tenant_active: dict[str, int] = {}
        self._leases: dict[str, _LeaseState] = {}
        self._seen_reservations: OrderedDict[str, float] = OrderedDict()

    @property
    def policy(self) -> ConsumptionBudgetPolicy:
        """Return a defensive copy of the active policy."""
        return self._policy.model_copy(deep=True)

    async def reserve(self, request: ResourceReservationRequest) -> ResourceBudgetResult:
        """Atomically reserve capacity before a model call or agent action."""
        findings = self._request_findings(request)
        if findings:
            return self._blocked(request.identity.request_id, findings)

        now = self._clock()
        identity = request.identity
        session_key = (identity.tenant_id, identity.session_id)
        principal_key = (identity.tenant_id, identity.principal_id)
        reserved_tokens = request.input_tokens + request.requested_output_tokens

        async with self._lock:
            self._purge_expired(now)
            if request.reservation_id in self._seen_reservations:
                return self._blocked(
                    identity.request_id,
                    [
                        self._finding(
                            ResourceLimitCode.RESERVATION_REPLAYED, "Reservation ID reused"
                        )
                    ],
                )
            session = self._sessions.get(session_key)
            if session is None:
                if len(self._sessions) >= self._policy.max_tracked_sessions:
                    return self._blocked(
                        identity.request_id,
                        [
                            self._finding(
                                ResourceLimitCode.TRACKING_CAPACITY_EXCEEDED,
                                "Resource session tracking capacity exhausted",
                                observed=len(self._sessions),
                                limit=self._policy.max_tracked_sessions,
                            )
                        ],
                    )
                session = _SessionState(first_seen=now)

            principal_window = self._window(self._principal_windows, principal_key, now)
            tenant_window = self._window(self._tenant_windows, identity.tenant_id, now)
            principal_active = self._principal_active.get(principal_key, 0)
            tenant_active = self._tenant_active.get(identity.tenant_id, 0)
            attempts = session.operation_attempts.get(identity.operation_id, 0)
            next_tool_actions = session.tool_actions + (
                1 if request.kind == ResourceOperationKind.TOOL else 0
            )

            state_findings: list[ResourceLimitFinding] = []
            elapsed = now - session.first_seen
            if elapsed >= self._policy.max_session_duration_seconds:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.SESSION_DURATION_EXCEEDED,
                        "Session duration budget exhausted",
                        observed=elapsed,
                        limit=self._policy.max_session_duration_seconds,
                    )
                )
            if session.tokens_reserved + reserved_tokens > self._policy.max_session_tokens:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.SESSION_TOKEN_BUDGET_EXCEEDED,
                        "Session token budget exhausted",
                        observed=session.tokens_reserved + reserved_tokens,
                        limit=self._policy.max_session_tokens,
                    )
                )
            if attempts > self._policy.max_retries_per_operation:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.RETRY_LIMIT_EXCEEDED,
                        "Operation retry budget exhausted",
                        observed=max(0, attempts - 1),
                        limit=self._policy.max_retries_per_operation,
                    )
                )
            if next_tool_actions > self._policy.max_tool_actions_per_session:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.TOOL_LOOP_LIMIT_EXCEEDED,
                        "Agent tool-action budget exhausted",
                        observed=next_tool_actions,
                        limit=self._policy.max_tool_actions_per_session,
                    )
                )
            if len(principal_window) >= self._policy.max_requests_per_principal_window:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.PRINCIPAL_RATE_EXCEEDED,
                        "Principal request window exhausted",
                        observed=len(principal_window) + 1,
                        limit=self._policy.max_requests_per_principal_window,
                    )
                )
            if len(tenant_window) >= self._policy.max_requests_per_tenant_window:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.TENANT_RATE_EXCEEDED,
                        "Tenant request window exhausted",
                        observed=len(tenant_window) + 1,
                        limit=self._policy.max_requests_per_tenant_window,
                    )
                )
            if principal_active >= self._policy.max_concurrent_operations_per_principal:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.PRINCIPAL_CONCURRENCY_EXCEEDED,
                        "Principal concurrency budget exhausted",
                        observed=principal_active + 1,
                        limit=self._policy.max_concurrent_operations_per_principal,
                    )
                )
            if tenant_active >= self._policy.max_concurrent_operations_per_tenant:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.TENANT_CONCURRENCY_EXCEEDED,
                        "Tenant concurrency budget exhausted",
                        observed=tenant_active + 1,
                        limit=self._policy.max_concurrent_operations_per_tenant,
                    )
                )
            if len(self._seen_reservations) >= self._policy.max_tracked_reservations:
                state_findings.append(
                    self._finding(
                        ResourceLimitCode.TRACKING_CAPACITY_EXCEEDED,
                        "Reservation replay tracking capacity exhausted",
                        observed=len(self._seen_reservations),
                        limit=self._policy.max_tracked_reservations,
                    )
                )
            if state_findings:
                return self._blocked(identity.request_id, state_findings)

            lease = ResourceLease(
                lease_id=str(uuid.uuid4()),
                reservation_id=request.reservation_id,
                request_id=identity.request_id,
                session_id=identity.session_id,
                reserved_tokens=reserved_tokens,
                requested_output_tokens=request.requested_output_tokens,
                timeout_seconds=self._policy.lease_timeout_seconds,
            )
            self._sessions[session_key] = session
            session.tokens_reserved += reserved_tokens
            session.tool_actions = next_tool_actions
            session.operation_attempts[identity.operation_id] = attempts + 1
            principal_window.append(now)
            tenant_window.append(now)
            self._principal_active[principal_key] = principal_active + 1
            self._tenant_active[identity.tenant_id] = tenant_active + 1
            self._seen_reservations[request.reservation_id] = (
                now + self._policy.max_session_duration_seconds
            )
            self._leases[lease.lease_id] = _LeaseState(
                lease=lease,
                principal_id=identity.principal_id,
                tenant_id=identity.tenant_id,
                expires_at=now + self._policy.lease_timeout_seconds,
            )
            signal = ResourceUsageSignal(
                session_tokens_reserved=session.tokens_reserved,
                session_tool_actions=session.tool_actions,
                principal_window_requests=len(principal_window),
                tenant_window_requests=len(tenant_window),
                principal_active_operations=principal_active + 1,
                tenant_active_operations=tenant_active + 1,
            )
            return ResourceBudgetResult(
                request_id=identity.request_id,
                action=GuardAction.ALLOW,
                lease=lease,
                signal=signal,
            )

    async def require_reservation(self, request: ResourceReservationRequest) -> ResourceLease:
        """Return an active lease or raise before resource-intensive work."""
        result = await self.reserve(request)
        if not result.is_allowed or result.lease is None:
            raise ResourceBudgetError(result=result)
        return result.lease

    async def complete(self, request: ResourceCompletionRequest) -> ResourceBudgetResult:
        """Validate actual output and release its active concurrency lease."""
        now = self._clock()
        async with self._lock:
            lease_state = self._leases.get(request.lease_id)
            if lease_state is None:
                return self._blocked(
                    request.lease_id,
                    [self._finding(ResourceLimitCode.LEASE_UNKNOWN, "Resource lease is unknown")],
                )
            if now >= lease_state.expires_at:
                self._release_lease(request.lease_id)
                return self._blocked(
                    lease_state.lease.request_id,
                    [self._finding(ResourceLimitCode.LEASE_EXPIRED, "Resource lease expired")],
                )
            self._release_lease(request.lease_id)

        findings = self._output_findings(request, lease_state.lease)
        if findings:
            return self._blocked(lease_state.lease.request_id, findings)
        return ResourceBudgetResult(
            request_id=lease_state.lease.request_id,
            action=GuardAction.ALLOW,
            approved_output=request.output_text,
        )

    async def require_completion(self, request: ResourceCompletionRequest) -> str:
        """Return bounded model output or raise before downstream consumption."""
        result = await self.complete(request)
        if not result.is_allowed or result.approved_output is None:
            raise ResourceBudgetError(result=result)
        return result.approved_output

    async def cancel(self, lease_id: str) -> bool:
        """Release a lease after cancellation or provider failure."""
        async with self._lock:
            return self._release_lease(lease_id)

    def _request_findings(
        self,
        request: ResourceReservationRequest,
    ) -> list[ResourceLimitFinding]:
        text = request.input_text
        checks = (
            (
                len(text),
                self._policy.max_input_chars,
                ResourceLimitCode.INPUT_CHARS_EXCEEDED,
                "Input character limit exceeded",
            ),
            (
                len(text.encode("utf-8")),
                self._policy.max_input_bytes,
                ResourceLimitCode.INPUT_BYTES_EXCEEDED,
                "Input byte limit exceeded",
            ),
            (
                request.input_tokens,
                self._policy.max_input_tokens,
                ResourceLimitCode.INPUT_TOKENS_EXCEEDED,
                "Input token limit exceeded",
            ),
            (
                request.requested_output_tokens,
                self._policy.max_output_tokens,
                ResourceLimitCode.OUTPUT_TOKENS_EXCEEDED,
                "Requested output token limit exceeded",
            ),
            (
                measure_structured_nesting(text),
                self._policy.max_nesting_depth,
                ResourceLimitCode.NESTING_DEPTH_EXCEEDED,
                "Structured input nesting limit exceeded",
            ),
        )
        return [
            self._finding(code, message, observed=observed, limit=limit)
            for observed, limit, code, message in checks
            if observed > limit
        ]

    def _output_findings(
        self,
        request: ResourceCompletionRequest,
        lease: ResourceLease,
    ) -> list[ResourceLimitFinding]:
        checks = (
            (
                len(request.output_text),
                self._policy.max_output_chars,
                ResourceLimitCode.OUTPUT_CHARS_EXCEEDED,
                "Output character limit exceeded",
            ),
            (
                len(request.output_text.encode("utf-8")),
                self._policy.max_output_bytes,
                ResourceLimitCode.OUTPUT_BYTES_EXCEEDED,
                "Output byte limit exceeded",
            ),
            (
                request.output_tokens,
                min(self._policy.max_output_tokens, lease.requested_output_tokens),
                ResourceLimitCode.OUTPUT_TOKENS_EXCEEDED,
                "Actual output exceeds the operation's reserved token limit",
            ),
        )
        return [
            self._finding(code, message, observed=observed, limit=limit)
            for observed, limit, code, message in checks
            if observed > limit
        ]

    def _window(
        self,
        windows: dict[_WindowKey, deque[float]],
        key: _WindowKey,
        now: float,
    ) -> deque[float]:
        window = windows.setdefault(key, deque())
        cutoff = now - self._policy.request_window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        return window

    def _purge_expired(self, now: float) -> None:
        for lease_id, state in tuple(self._leases.items()):
            if now >= state.expires_at:
                self._release_lease(lease_id)
        while self._seen_reservations:
            reservation_id, expires_at = next(iter(self._seen_reservations.items()))
            if now < expires_at:
                break
            self._seen_reservations.pop(reservation_id)
        cutoff = now - self._policy.request_window_seconds
        self._purge_windows(self._principal_windows, cutoff)
        self._purge_windows(self._tenant_windows, cutoff)
        active_sessions = {
            (state.tenant_id, state.lease.session_id) for state in self._leases.values()
        }
        retention = self._policy.max_session_duration_seconds + self._policy.lease_timeout_seconds
        for session_key, session in tuple(self._sessions.items()):
            if session_key not in active_sessions and now - session.first_seen >= retention:
                self._sessions.pop(session_key, None)

    @staticmethod
    def _purge_windows(
        windows: dict[_WindowKey, deque[float]],
        cutoff: float,
    ) -> None:
        for key, window in tuple(windows.items()):
            while window and window[0] <= cutoff:
                window.popleft()
            if not window:
                windows.pop(key, None)

    def _release_lease(self, lease_id: str) -> bool:
        state = self._leases.pop(lease_id, None)
        if state is None:
            return False
        principal_key = (state.tenant_id, state.principal_id)
        principal_count = max(0, self._principal_active.get(principal_key, 0) - 1)
        tenant_count = max(0, self._tenant_active.get(state.tenant_id, 0) - 1)
        if principal_count:
            self._principal_active[principal_key] = principal_count
        else:
            self._principal_active.pop(principal_key, None)
        if tenant_count:
            self._tenant_active[state.tenant_id] = tenant_count
        else:
            self._tenant_active.pop(state.tenant_id, None)
        return True

    @staticmethod
    def _finding(
        code: ResourceLimitCode,
        message: str,
        *,
        observed: int | float | None = None,
        limit: int | float | None = None,
    ) -> ResourceLimitFinding:
        return ResourceLimitFinding(
            code=code,
            message=message,
            observed=observed,
            limit=limit,
        )

    @staticmethod
    def _blocked(
        request_id: str,
        findings: list[ResourceLimitFinding],
    ) -> ResourceBudgetResult:
        return ResourceBudgetResult(
            request_id=request_id,
            action=GuardAction.BLOCK,
            findings=tuple(findings),
        )


class BoundedDecompressor:
    """Decode gzip or zlib data incrementally within byte and ratio caps."""

    _CHUNK_BYTES = 64 * 1024

    def __init__(self, policy: ConsumptionBudgetPolicy) -> None:
        self._policy = policy.model_copy(deep=True)

    def decompress(self, request: CompressedPayloadRequest) -> DecompressionResult:
        """Return decompressed bytes only when every expansion bound passes."""
        payload = request.payload
        compressed_bytes = len(payload)
        if compressed_bytes > self._policy.max_compressed_bytes:
            return self._blocked(
                request,
                ResourceLimitCode.COMPRESSED_BYTES_EXCEEDED,
                "Compressed payload byte limit exceeded",
                observed=compressed_bytes,
                limit=self._policy.max_compressed_bytes,
            )
        window_bits = (
            zlib.MAX_WBITS | 16 if request.format == CompressionFormat.GZIP else zlib.MAX_WBITS
        )
        decoder = zlib.decompressobj(window_bits)
        output = bytearray()
        try:
            for offset in range(0, compressed_bytes, self._CHUNK_BYTES):
                pending = payload[offset : offset + self._CHUNK_BYTES]
                while pending:
                    remaining = self._policy.max_decompressed_bytes + 1 - len(output)
                    if remaining <= 0:
                        return self._too_large(request, compressed_bytes, len(output))
                    before = len(pending)
                    output.extend(decoder.decompress(pending, remaining))
                    if len(output) > self._policy.max_decompressed_bytes:
                        return self._too_large(request, compressed_bytes, len(output))
                    if (
                        len(output) / max(1, compressed_bytes)
                        > self._policy.max_decompression_ratio
                    ):
                        return self._ratio_exceeded(request, compressed_bytes, len(output))
                    pending = decoder.unconsumed_tail
                    if pending and len(pending) == before:
                        break
            remaining = self._policy.max_decompressed_bytes + 1 - len(output)
            if remaining <= 0:
                return self._too_large(request, compressed_bytes, len(output))
            output.extend(decoder.flush(remaining))
        except zlib.error:
            return self._blocked(
                request,
                ResourceLimitCode.INVALID_COMPRESSED_PAYLOAD,
                "Compressed payload is invalid or truncated",
            )

        if len(output) > self._policy.max_decompressed_bytes:
            return self._too_large(request, compressed_bytes, len(output))
        if len(output) / max(1, compressed_bytes) > self._policy.max_decompression_ratio:
            return self._ratio_exceeded(request, compressed_bytes, len(output))
        if not decoder.eof:
            return self._blocked(
                request,
                ResourceLimitCode.INVALID_COMPRESSED_PAYLOAD,
                "Compressed payload is invalid or truncated",
            )
        if decoder.unused_data:
            return self._blocked(
                request,
                ResourceLimitCode.CONCATENATED_COMPRESSED_STREAM,
                "Trailing or concatenated compressed stream rejected",
            )
        ratio = len(output) / max(1, compressed_bytes)
        if ratio > self._policy.max_decompression_ratio:
            return self._blocked(
                request,
                ResourceLimitCode.DECOMPRESSION_RATIO_EXCEEDED,
                "Decompression expansion ratio limit exceeded",
                observed=ratio,
                limit=self._policy.max_decompression_ratio,
                decompressed_bytes=len(output),
            )
        return DecompressionResult(
            request_id=request.request_id,
            action=GuardAction.ALLOW,
            compressed_bytes=compressed_bytes,
            decompressed_bytes=len(output),
            expansion_ratio=ratio,
            decompressed_payload=bytes(output),
        )

    def require(self, request: CompressedPayloadRequest) -> bytes:
        """Return bounded bytes or raise before parsing or buffering downstream."""
        result = self.decompress(request)
        if not result.is_allowed or result.decompressed_payload is None:
            raise ResourceBudgetError(result=result)
        return result.decompressed_payload

    def _too_large(
        self,
        request: CompressedPayloadRequest,
        compressed_bytes: int,
        decompressed_bytes: int,
    ) -> DecompressionResult:
        return self._blocked(
            request,
            ResourceLimitCode.DECOMPRESSED_BYTES_EXCEEDED,
            "Decompressed payload byte limit exceeded",
            observed=decompressed_bytes,
            limit=self._policy.max_decompressed_bytes,
            decompressed_bytes=decompressed_bytes,
            compressed_bytes=compressed_bytes,
        )

    def _ratio_exceeded(
        self,
        request: CompressedPayloadRequest,
        compressed_bytes: int,
        decompressed_bytes: int,
    ) -> DecompressionResult:
        return self._blocked(
            request,
            ResourceLimitCode.DECOMPRESSION_RATIO_EXCEEDED,
            "Decompression expansion ratio limit exceeded",
            observed=decompressed_bytes / max(1, compressed_bytes),
            limit=self._policy.max_decompression_ratio,
            decompressed_bytes=decompressed_bytes,
            compressed_bytes=compressed_bytes,
        )

    @staticmethod
    def _blocked(
        request: CompressedPayloadRequest,
        code: ResourceLimitCode,
        message: str,
        *,
        observed: int | float | None = None,
        limit: int | float | None = None,
        compressed_bytes: int | None = None,
        decompressed_bytes: int = 0,
    ) -> DecompressionResult:
        compressed = len(request.payload) if compressed_bytes is None else compressed_bytes
        return DecompressionResult(
            request_id=request.request_id,
            action=GuardAction.BLOCK,
            findings=(
                ResourceLimitFinding(
                    code=code,
                    message=message,
                    observed=observed,
                    limit=limit,
                ),
            ),
            compressed_bytes=compressed,
            decompressed_bytes=decompressed_bytes,
            expansion_ratio=decompressed_bytes / max(1, compressed),
        )
