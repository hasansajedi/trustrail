"""Privacy-safe, atomic detection of cross-turn jailbreak campaigns."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import unicodedata
from collections import Counter, OrderedDict
from datetime import UTC, datetime, timedelta
from typing import Protocol

from trustrail.models.enums import Severity
from trustrail.models.jailbreak_campaign import (
    CampaignAction,
    CampaignCode,
    CampaignEncodingKind,
    CampaignFinding,
    CampaignFragmentProgress,
    CampaignSignal,
    CampaignSignalKind,
    CampaignTurnFeatures,
    JailbreakCampaignEvent,
    JailbreakCampaignPolicy,
    JailbreakCampaignResult,
    JailbreakCampaignState,
)

_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?[0-9A-Fa-f]{24,}(?![0-9A-Fa-f])")
_ESCAPED_UNICODE_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){2,}")
_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f]")
_EXAMPLE_RE = re.compile(
    r"\b(?:for\s+example|hypothetical(?:ly)?|example\s*\d+|demonstrate|few[- ]shot|"
    r"scenario\s*\d+|sample\s*\d+)\b",
    re.IGNORECASE,
)
_BOUNDARY_RE = re.compile(
    r"\b(?:system\s+prompt|developer\s+message|what\s+are\s+your\s+rules|"
    r"which\s+(?:requests?|topics?|words?)\s+(?:are\s+)?forbidden|policy\s+boundary|"
    r"are\s+you\s+allowed\s+to|why\s+(?:can(?:not|'t)|won't)\s+you|"
    r"what\s+would\s+you\s+refuse)\b",
    re.IGNORECASE,
)
_EROSION_RE = re.compile(
    r"\b(?:just\s+this\s+once|make\s+an\s+exception|temporarily\s+(?:relax|disable)|"
    r"slightly\s+relax|ignore\s+(?:one|a\s+single)\s+rule|safe\s+fictional|"
    r"educational\s+purposes?\s+only|no\s+one\s+will\s+know|harmless\s+exception)\b",
    re.IGNORECASE,
)
_RETRY_RE = re.compile(
    r"\b(?:try\s+again|answer\s+anyway|you\s+refused|another\s+way|"
    r"be\s+less\s+cautious|do\s+it\s+now|continue\s+despite|still\s+refusing|"
    r"rephrase\s+the\s+request)\b",
    re.IGNORECASE,
)


class CampaignStateStore(Protocol):
    """Optimistic atomic storage for privacy-safe campaign state."""

    def read(self, scope_ref: str, *, now: datetime) -> JailbreakCampaignState | None:
        """Return a defensive snapshot, excluding expired state."""
        ...

    def compare_and_set(
        self,
        scope_ref: str,
        *,
        expected_version: int | None,
        state: JailbreakCampaignState,
        now: datetime,
    ) -> bool:
        """Atomically write only when the current version matches."""
        ...

    def clear(self, scope_ref: str) -> None:
        """Atomically remove state after an application-enforced context reset."""
        ...


class CampaignStateCapacityError(RuntimeError):
    """Raised when bounded state cannot safely admit another live session."""


class MemoryCampaignStateStore:
    """Thread-safe, expiring, capacity-bounded process-local CAS store."""

    def __init__(self, *, max_sessions: int = 10_000) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        self._max_sessions = max_sessions
        self._states: OrderedDict[str, JailbreakCampaignState] = OrderedDict()
        self._lock = threading.Lock()

    def read(self, scope_ref: str, *, now: datetime) -> JailbreakCampaignState | None:
        _require_aware(now)
        with self._lock:
            self._purge(now)
            state = self._states.get(scope_ref)
            if state is None:
                return None
            self._states.move_to_end(scope_ref)
            return state.model_copy(deep=True)

    def compare_and_set(
        self,
        scope_ref: str,
        *,
        expected_version: int | None,
        state: JailbreakCampaignState,
        now: datetime,
    ) -> bool:
        _require_aware(now)
        if state.scope_ref != scope_ref or state.expires_at <= now:
            raise ValueError("campaign state scope or expiry is invalid")
        with self._lock:
            self._purge(now)
            current = self._states.get(scope_ref)
            current_version = None if current is None else current.version
            if current_version != expected_version:
                return False
            if current is None and len(self._states) >= self._max_sessions:
                raise CampaignStateCapacityError("campaign state capacity exhausted")
            expected_next = 1 if expected_version is None else expected_version + 1
            if state.version != expected_next:
                raise ValueError("campaign state version is not the next CAS version")
            self._states[scope_ref] = state.model_copy(deep=True)
            self._states.move_to_end(scope_ref)
            return True

    def clear(self, scope_ref: str) -> None:
        with self._lock:
            self._states.pop(scope_ref, None)

    def _purge(self, now: datetime) -> None:
        expired = [key for key, state in self._states.items() if state.expires_at <= now]
        for key in expired:
            del self._states[key]


class JailbreakCampaignDetector:
    """Score ordered conversation trajectories without retaining raw prompts."""

    def __init__(
        self,
        policy: JailbreakCampaignPolicy,
        privacy_key: bytes,
        *,
        state_store: CampaignStateStore | None = None,
    ) -> None:
        if len(privacy_key) < 32:
            raise ValueError("privacy_key must contain at least 32 bytes")
        self._policy = policy.model_copy(deep=True)
        self._key = bytes(privacy_key)
        self._store = (
            MemoryCampaignStateStore(max_sessions=policy.max_tracked_sessions)
            if state_store is None
            else state_store
        )
        self._fragments = tuple(_compact(item) for item in policy.protected_fragments)
        self._fragment_refs = tuple(
            self._reference("fragment", fragment) for fragment in self._fragments
        )

    @property
    def policy(self) -> JailbreakCampaignPolicy:
        return self._policy.model_copy(deep=True)

    def assess(
        self,
        event: JailbreakCampaignEvent,
        *,
        now: datetime | None = None,
    ) -> JailbreakCampaignResult:
        """Atomically append one ordered turn and return the committed decision."""
        current = _current_time(now)
        scope_ref = self._scope_reference(event)
        event_ref = self._reference("event", f"{scope_ref}\x00{event.event_id}")
        invalid = self._event_finding(event, current)
        if invalid is not None:
            code, action, message = invalid
            return self._rejected(
                action,
                code,
                message,
                scope_ref=scope_ref,
                event_ref=event_ref,
                next_sequence=self._policy.initial_sequence,
            )

        features = self._features(event, event_ref, scope_ref)
        for _ in range(self._policy.max_atomic_retries):
            try:
                state = self._store.read(scope_ref, now=current)
            except CampaignStateCapacityError:
                return self._state_failure(
                    scope_ref,
                    event_ref,
                    CampaignCode.TRACKING_CAPACITY_EXCEEDED,
                )
            except Exception:
                return self._state_failure(scope_ref, event_ref, CampaignCode.STATE_UNAVAILABLE)

            context_failure = self._state_finding(state, event, scope_ref)
            if context_failure is not None:
                code, action, message, next_sequence = context_failure
                return self._rejected(
                    action,
                    code,
                    message,
                    scope_ref=scope_ref,
                    event_ref=event_ref,
                    next_sequence=next_sequence,
                    state_version=None if state is None else state.version,
                )

            expected_version = None if state is None else state.version
            next_state, signals = self._next_state(state, event, features, current, scope_ref)
            try:
                committed = self._store.compare_and_set(
                    scope_ref,
                    expected_version=expected_version,
                    state=next_state,
                    now=current,
                )
            except CampaignStateCapacityError:
                return self._state_failure(
                    scope_ref,
                    event_ref,
                    CampaignCode.TRACKING_CAPACITY_EXCEEDED,
                )
            except Exception:
                return self._state_failure(scope_ref, event_ref, CampaignCode.STATE_UNAVAILABLE)
            if committed:
                return self._result(next_state, features.event_ref, signals)

        return self._state_failure(
            scope_ref,
            event_ref,
            CampaignCode.ATOMIC_UPDATE_EXHAUSTED,
        )

    def reset_session(self, tenant_id: str, user_id: str, session_id: str) -> None:
        """Clear state after the application has actually discarded model context."""
        scope_ref = self._reference("scope", f"{tenant_id}\x00{user_id}\x00{session_id}")
        self._store.clear(scope_ref)

    def _event_finding(
        self,
        event: JailbreakCampaignEvent,
        now: datetime,
    ) -> tuple[CampaignCode, CampaignAction, str] | None:
        if len(event.content) > self._policy.max_event_chars:
            return (
                CampaignCode.EVENT_TOO_LARGE,
                CampaignAction.BLOCK,
                "Campaign event exceeds the configured processing bound",
            )
        if event.occurred_at > now + timedelta(
            seconds=self._policy.max_future_skew_seconds
        ) or now - event.occurred_at > timedelta(seconds=self._policy.max_event_age_seconds):
            return (
                CampaignCode.EVENT_STALE,
                CampaignAction.CHALLENGE,
                "Campaign event is stale or future-dated",
            )
        return None

    def _state_finding(
        self,
        state: JailbreakCampaignState | None,
        event: JailbreakCampaignEvent,
        scope_ref: str,
    ) -> tuple[CampaignCode, CampaignAction, str, int] | None:
        expected = self._policy.initial_sequence if state is None else state.next_sequence
        if state is not None:
            if state.policy_version != self._policy.policy_version:
                return (
                    CampaignCode.POLICY_CHANGED,
                    CampaignAction.CONTEXT_RESET,
                    "Campaign policy changed and requires a fresh context",
                    expected,
                )
            expected_refs = (
                self._reference("tenant", event.tenant_id),
                self._reference("user", f"{event.tenant_id}\x00{event.user_id}"),
                self._reference(
                    "session",
                    f"{event.tenant_id}\x00{event.user_id}\x00{event.session_id}",
                ),
            )
            if (
                state.scope_ref != scope_ref
                or (state.tenant_ref, state.user_ref, state.session_ref) != expected_refs
                or tuple(item.fragment_ref for item in state.fragment_progress)
                != self._fragment_refs
                or any(
                    item.matched_chars >= len(fragment)
                    for item, fragment in zip(state.fragment_progress, self._fragments, strict=True)
                )
                or len(state.turns) > self._policy.max_turns
            ):
                return (
                    CampaignCode.STATE_INVALID,
                    CampaignAction.BLOCK,
                    "Campaign state is inconsistent with the authenticated scope",
                    expected,
                )
            if state.turns and event.occurred_at < state.turns[-1].occurred_at:
                return (
                    CampaignCode.TIMESTAMP_REGRESSION,
                    CampaignAction.CONTEXT_RESET,
                    "Campaign event time regressed relative to the ordered trajectory",
                    expected,
                )
        if event.sequence < expected:
            return (
                CampaignCode.SEQUENCE_REPLAY,
                CampaignAction.BLOCK,
                "Campaign event sequence was already consumed",
                expected,
            )
        if event.sequence > expected:
            return (
                CampaignCode.SEQUENCE_GAP,
                CampaignAction.CONTEXT_RESET,
                "Campaign event sequence contains a gap",
                expected,
            )
        return None

    def _features(
        self,
        event: JailbreakCampaignEvent,
        event_ref: str,
        scope_ref: str,
    ) -> CampaignTurnFeatures:
        normalized = unicodedata.normalize("NFKC", event.content).casefold()
        encodings = {CampaignEncodingKind.PLAIN}
        if _looks_base64(event.content):
            encodings.add(CampaignEncodingKind.BASE64)
        if _HEX_RE.search(event.content):
            encodings.add(CampaignEncodingKind.HEX)
        if _ESCAPED_UNICODE_RE.search(event.content):
            encodings.add(CampaignEncodingKind.ESCAPED_UNICODE)
        if _INVISIBLE_RE.search(event.content):
            encodings.add(CampaignEncodingKind.INVISIBLE_UNICODE)
        return CampaignTurnFeatures(
            sequence=event.sequence,
            event_ref=event_ref,
            content_ref=self._reference("content", f"{scope_ref}\x00{normalized}"),
            occurred_at=event.occurred_at,
            char_count=len(event.content),
            token_count=len(_TOKEN_RE.findall(normalized)),
            example_markers=len(_EXAMPLE_RE.findall(normalized)),
            boundary_probes=len(_BOUNDARY_RE.findall(normalized)),
            policy_erosion_markers=len(_EROSION_RE.findall(normalized)),
            retry_markers=len(_RETRY_RE.findall(normalized)),
            encodings=frozenset(encodings),
        )

    def _next_state(
        self,
        state: JailbreakCampaignState | None,
        event: JailbreakCampaignEvent,
        features: CampaignTurnFeatures,
        now: datetime,
        scope_ref: str,
    ) -> tuple[JailbreakCampaignState, tuple[CampaignSignal, ...]]:
        previous_turns = () if state is None else state.turns
        turns = (*previous_turns, features)[-self._policy.max_turns :]
        previous_progress = (
            (0,) * len(self._fragments)
            if state is None
            else tuple(item.matched_chars for item in state.fragment_progress)
        )
        compact = _compact(event.content)
        progress_values: list[int] = []
        fragment_completed = False
        for pattern, matched in zip(self._fragments, previous_progress, strict=True):
            next_progress, crossed = _fragment_progress(pattern, matched, compact)
            progress_values.append(next_progress)
            fragment_completed = fragment_completed or crossed

        signals = self._signals(turns, features, fragment_completed)
        score = min(100, sum(item.score for item in signals))
        action = self._action(score, signals)
        if state is not None:
            if state.last_action == CampaignAction.BLOCK:
                action = CampaignAction.BLOCK
                score = max(score, state.risk_score)
            elif (
                state.last_action == CampaignAction.CONTEXT_RESET and action != CampaignAction.BLOCK
            ):
                action = CampaignAction.CONTEXT_RESET
                score = max(score, state.risk_score)
        version = 1 if state is None else state.version + 1
        started_at = now if state is None else state.started_at
        next_state = JailbreakCampaignState(
            scope_ref=scope_ref,
            tenant_ref=self._reference("tenant", event.tenant_id),
            user_ref=self._reference("user", f"{event.tenant_id}\x00{event.user_id}"),
            session_ref=self._reference(
                "session",
                f"{event.tenant_id}\x00{event.user_id}\x00{event.session_id}",
            ),
            policy_version=self._policy.policy_version,
            version=version,
            next_sequence=event.sequence + 1,
            started_at=started_at,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=self._policy.session_ttl_seconds),
            turns=turns,
            fragment_progress=tuple(
                CampaignFragmentProgress(fragment_ref=reference, matched_chars=matched)
                for reference, matched in zip(self._fragment_refs, progress_values, strict=True)
            ),
            risk_score=score,
            last_action=action,
        )
        return next_state, signals

    def _signals(
        self,
        turns: tuple[CampaignTurnFeatures, ...],
        current: CampaignTurnFeatures,
        fragment_completed: bool,
    ) -> tuple[CampaignSignal, ...]:
        signals: list[CampaignSignal] = []
        repetitions = max(Counter(turn.content_ref for turn in turns).values())
        risk_markers = (
            current.example_markers
            + current.boundary_probes
            + current.policy_erosion_markers
            + current.retry_markers
            + len(current.encodings - {CampaignEncodingKind.PLAIN})
        )
        if repetitions >= self._policy.repetition_turns and risk_markers:
            signals.append(
                self._signal(
                    CampaignSignalKind.REPETITION,
                    self._policy.repetition_weight,
                    repetitions,
                    self._policy.repetition_turns,
                )
            )
        examples = sum(turn.example_markers for turn in turns)
        if examples >= self._policy.example_markers:
            signals.append(
                self._signal(
                    CampaignSignalKind.EXAMPLE_ACCUMULATION,
                    self._policy.example_weight,
                    examples,
                    self._policy.example_markers,
                )
            )
        probes = sum(turn.boundary_probes for turn in turns)
        if probes >= self._policy.boundary_probes:
            signals.append(
                self._signal(
                    CampaignSignalKind.POLICY_BOUNDARY_PROBING,
                    self._policy.boundary_weight,
                    probes,
                    self._policy.boundary_probes,
                )
            )
        if fragment_completed:
            signals.append(
                self._signal(
                    CampaignSignalKind.FRAGMENT_RECONSTRUCTION,
                    self._policy.fragment_weight,
                    1,
                    1,
                )
            )
        encoding_kinds: set[CampaignEncodingKind] = set().union(*(turn.encodings for turn in turns))
        if len(encoding_kinds) >= self._policy.encoding_kinds:
            signals.append(
                self._signal(
                    CampaignSignalKind.ENCODING_SHIFT,
                    self._policy.encoding_weight,
                    len(encoding_kinds),
                    self._policy.encoding_kinds,
                )
            )
        retries = sum(turn.retry_markers for turn in turns)
        if retries >= self._policy.retry_markers:
            signals.append(
                self._signal(
                    CampaignSignalKind.RETRY_ESCALATION,
                    self._policy.retry_weight,
                    retries,
                    self._policy.retry_markers,
                )
            )
        erosion = sum(turn.policy_erosion_markers for turn in turns)
        if erosion >= self._policy.policy_erosion_markers:
            signals.append(
                self._signal(
                    CampaignSignalKind.POLICY_EROSION,
                    self._policy.erosion_weight,
                    erosion,
                    self._policy.policy_erosion_markers,
                )
            )
        return tuple(signals)

    def _action(
        self,
        score: int,
        signals: tuple[CampaignSignal, ...],
    ) -> CampaignAction:
        kinds = {signal.kind for signal in signals}
        if kinds & self._policy.critical_signals:
            return CampaignAction.BLOCK
        thresholds = self._policy.thresholds
        if score >= thresholds.block:
            return CampaignAction.BLOCK
        if score >= thresholds.context_reset:
            return CampaignAction.CONTEXT_RESET
        if score >= thresholds.throttle:
            return CampaignAction.THROTTLE
        if score >= thresholds.challenge:
            return CampaignAction.CHALLENGE
        if score >= thresholds.warn:
            return CampaignAction.WARN
        return CampaignAction.ALLOW

    def _result(
        self,
        state: JailbreakCampaignState,
        event_ref: str,
        signals: tuple[CampaignSignal, ...],
    ) -> JailbreakCampaignResult:
        findings: tuple[CampaignFinding, ...] = ()
        if state.last_action != CampaignAction.ALLOW:
            findings = (
                CampaignFinding(
                    code=CampaignCode.CAMPAIGN_RISK,
                    severity=_severity(state.last_action),
                    message="Ordered conversation trajectory exceeded a campaign threshold",
                ),
            )
        return JailbreakCampaignResult(
            action=state.last_action,
            score=state.risk_score,
            scope_ref=state.scope_ref,
            event_ref=event_ref,
            state_version=state.version,
            next_sequence=state.next_sequence,
            signals=signals,
            findings=findings,
            retry_after_seconds=(
                self._policy.throttle_seconds
                if state.last_action == CampaignAction.THROTTLE
                else None
            ),
        )

    def _state_failure(
        self,
        scope_ref: str,
        event_ref: str,
        code: CampaignCode,
    ) -> JailbreakCampaignResult:
        return self._rejected(
            CampaignAction.BLOCK,
            code,
            "Campaign state could not be updated safely",
            scope_ref=scope_ref,
            event_ref=event_ref,
            next_sequence=self._policy.initial_sequence,
        )

    @staticmethod
    def _rejected(
        action: CampaignAction,
        code: CampaignCode,
        message: str,
        *,
        scope_ref: str,
        event_ref: str,
        next_sequence: int,
        state_version: int | None = None,
    ) -> JailbreakCampaignResult:
        return JailbreakCampaignResult(
            action=action,
            score=100 if action == CampaignAction.BLOCK else 0,
            scope_ref=scope_ref,
            event_ref=event_ref,
            state_version=state_version,
            next_sequence=next_sequence,
            findings=(
                CampaignFinding(
                    code=code,
                    severity=_severity(action),
                    message=message,
                ),
            ),
        )

    @staticmethod
    def _signal(
        kind: CampaignSignalKind,
        score: int,
        observed: int,
        threshold: int,
    ) -> CampaignSignal:
        return CampaignSignal(
            kind=kind,
            score=score,
            observed=observed,
            threshold=threshold,
        )

    def _scope_reference(self, event: JailbreakCampaignEvent) -> str:
        return self._reference(
            "scope", f"{event.tenant_id}\x00{event.user_id}\x00{event.session_id}"
        )

    def _reference(self, domain: str, value: str) -> str:
        digest = hmac.new(
            self._key,
            f"trustrail.campaign.{domain}.v1\x00{value}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"


def _compact(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _fragment_progress(pattern: str, matched: int, current: str) -> tuple[int, bool]:
    combined = pattern[:matched] + current
    crossed = False
    position = combined.find(pattern)
    while position >= 0:
        if position < matched < position + len(pattern):
            crossed = True
            break
        position = combined.find(pattern, position + 1)
    maximum = min(len(pattern) - 1, len(combined))
    next_progress = next(
        (size for size in range(maximum, 0, -1) if combined.endswith(pattern[:size])),
        0,
    )
    return next_progress, crossed


def _looks_base64(value: str) -> bool:
    for match in _BASE64_RE.finditer(value):
        candidate = match.group(0).rstrip("=")
        if (
            any(character.islower() for character in candidate)
            and any(character.isupper() for character in candidate)
            and any(character.isdigit() for character in candidate)
        ):
            return True
    return False


def _current_time(value: datetime | None) -> datetime:
    current = value or datetime.now(tz=UTC)
    _require_aware(current)
    return current


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must be timezone-aware")


def _severity(action: CampaignAction) -> Severity:
    return {
        CampaignAction.ALLOW: Severity.INFO,
        CampaignAction.WARN: Severity.LOW,
        CampaignAction.CHALLENGE: Severity.MEDIUM,
        CampaignAction.THROTTLE: Severity.HIGH,
        CampaignAction.CONTEXT_RESET: Severity.HIGH,
        CampaignAction.BLOCK: Severity.CRITICAL,
    }[action]
