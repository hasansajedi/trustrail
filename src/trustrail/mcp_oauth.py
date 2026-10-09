"""Fail-closed OAuth resource-server controls for MCP requests."""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import threading
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Never, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, JsonValue, ValidationError

from trustrail.credentials import CredentialMaterial
from trustrail.exceptions import MCPOAuthAuthorizationError, MCPOAuthDownstreamCredentialError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.mcp import MCPToolDefinition
from trustrail.models.mcp_oauth import (
    AuthorizedMCPOAuthRequest,
    MCPOAuthAuditEvent,
    MCPOAuthAuthorizationResult,
    MCPOAuthCode,
    MCPOAuthDownstreamMode,
    MCPOAuthDownstreamRequest,
    MCPOAuthFinding,
    MCPOAuthOperation,
    MCPOAuthPolicy,
    MCPOAuthReplayStatus,
    MCPOAuthRequestContext,
    MCPOAuthTokenClaims,
    MCPOAuthToolPolicy,
    MCPOAuthTrustedKey,
    oauth_reference,
    utcnow,
)


class MCPOAuthReplayStore(Protocol):
    """Atomically reserve a request-bound token identifier until expiry."""

    def claim(
        self,
        replay_id: str,
        *,
        expires_at: datetime,
        now: datetime,
    ) -> MCPOAuthReplayStatus: ...


class MCPOAuthAuditSink(Protocol):
    """Persist content-free MCP OAuth authorization events."""

    def emit(self, event: MCPOAuthAuditEvent) -> None: ...


class MCPOAuthDownstreamCredentialProvider(Protocol):
    """Resolve credentials inside trusted infrastructure, outside model context."""

    def exchange(
        self,
        request: MCPOAuthDownstreamRequest,
        subject_token: CredentialMaterial,
    ) -> CredentialMaterial: ...

    def workload_credential(
        self,
        request: MCPOAuthDownstreamRequest,
    ) -> CredentialMaterial: ...


class MemoryMCPOAuthReplayStore:
    """Capacity-bounded process-local atomic token replay state."""

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._max_entries = max_entries
        self._entries: dict[str, datetime] = {}
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def claim(
        self,
        replay_id: str,
        *,
        expires_at: datetime,
        now: datetime,
    ) -> MCPOAuthReplayStatus:
        if expires_at.tzinfo is None or now.tzinfo is None:
            raise ValueError("replay timestamps must be timezone-aware")
        if expires_at <= now:
            raise ValueError("replay expiration must be in the future")
        with self._lock:
            expired = [key for key, expiration in self._entries.items() if expiration <= now]
            for key in expired:
                del self._entries[key]
            if replay_id in self._entries:
                return MCPOAuthReplayStatus.REPLAYED
            if len(self._entries) >= self._max_entries:
                return MCPOAuthReplayStatus.FULL
            self._entries[replay_id] = expires_at
            return MCPOAuthReplayStatus.STORED

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


class MemoryMCPOAuthAuditSink:
    """Bounded in-memory content-free audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[MCPOAuthAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: MCPOAuthAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[MCPOAuthAuditEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class _JWTHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    typ: Literal["at+jwt"]
    alg: str
    kid: str


@dataclass(frozen=True)
class _ParsedToken:
    header: _JWTHeader
    claims: MCPOAuthTokenClaims
    signing_input: bytes
    signature: bytes
    token_ref: str


@dataclass(frozen=True)
class _ValidatedToken:
    parsed: _ParsedToken
    authorization: AuthorizedMCPOAuthRequest


class _TokenParseError(ValueError):
    def __init__(self, code: MCPOAuthCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _decode_segment(segment: str, *, maximum_bytes: int) -> bytes:
    if (
        not segment
        or "=" in segment
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in segment
        )
    ):
        raise ValueError("invalid base64url segment")
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if len(decoded) > maximum_bytes:
        raise ValueError("decoded segment exceeds configured size")
    return decoded


def _parse_json_object(segment: str, *, maximum_bytes: int) -> dict[str, Any]:
    raw = _decode_segment(segment, maximum_bytes=maximum_bytes)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("JWT segment must contain a JSON object")
    return value


def _parse_token(token: str, policy: MCPOAuthPolicy) -> _ParsedToken:
    if len(token.encode()) > policy.max_token_bytes:
        raise _TokenParseError(MCPOAuthCode.TOKEN_TOO_LARGE, "Access token exceeds policy size")
    parts = token.split(".")
    if len(parts) != 3:
        raise _TokenParseError(MCPOAuthCode.TOKEN_MALFORMED, "Access token is not compact JWS")
    try:
        header_data = _parse_json_object(parts[0], maximum_bytes=4_096)
        header = _JWTHeader.model_validate(header_data)
    except (ValueError, ValidationError, UnicodeDecodeError, binascii.Error) as exc:
        raise _TokenParseError(
            MCPOAuthCode.HEADER_INVALID,
            "Access token protected header is invalid",
        ) from exc
    if header.alg not in {algorithm.value for algorithm in policy.allowed_algorithms}:
        raise _TokenParseError(
            MCPOAuthCode.ALGORITHM_NOT_ALLOWED,
            "Access token signature algorithm is not allowed",
        )
    try:
        claims_data = _parse_json_object(parts[1], maximum_bytes=policy.max_token_bytes)
        claims = MCPOAuthTokenClaims.model_validate(claims_data)
        signature = _decode_segment(parts[2], maximum_bytes=128)
    except (ValueError, ValidationError, UnicodeDecodeError, binascii.Error) as exc:
        raise _TokenParseError(
            MCPOAuthCode.TOKEN_MALFORMED,
            "Access token claims or signature are malformed",
        ) from exc
    if len(signature) != 64:
        raise _TokenParseError(
            MCPOAuthCode.TOKEN_MALFORMED,
            "Access token signature length is invalid",
        )
    return _ParsedToken(
        header=header,
        claims=claims,
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature=signature,
        token_ref=oauth_reference(token),
    )


def _pointer_value(arguments: Mapping[str, JsonValue], pointer: str) -> JsonValue:
    current: JsonValue = dict(arguments)
    for raw_segment in pointer.split("/")[1:]:
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or segment not in current:
            raise KeyError(pointer)
        current = current[segment]
    return current


def _contains_caller_token(value: JsonValue, token: str) -> bool:
    if isinstance(value, str):
        return value == token or value.casefold() == f"bearer {token}".casefold()
    if isinstance(value, list):
        return any(_contains_caller_token(item, token) for item in value)
    if isinstance(value, dict):
        return any(_contains_caller_token(item, token) for item in value.values())
    return False


class MCPOAuthResourceServer:
    """Validate and authorize every OAuth-protected MCP list and call request."""

    def __init__(
        self,
        policy: MCPOAuthPolicy,
        trusted_keys: Iterable[MCPOAuthTrustedKey],
        *,
        replay_store: MCPOAuthReplayStore | None = None,
        audit_sink: MCPOAuthAuditSink | None = None,
    ) -> None:
        keys = tuple(key.model_copy(deep=True) for key in trusted_keys)
        by_id = {key.key_id: key for key in keys}
        if not keys:
            raise ValueError("at least one trusted OAuth key is required")
        if len(by_id) != len(keys):
            raise ValueError("trusted OAuth keys must have unique key IDs")
        if any(key.issuer != policy.issuer for key in keys):
            raise ValueError("every trusted OAuth key must belong to the policy issuer")
        self._policy = policy.model_copy(deep=True)
        self._trusted_keys = by_id
        self._replay_store = replay_store or MemoryMCPOAuthReplayStore()
        self._audit_sink = audit_sink

    @property
    def policy(self) -> MCPOAuthPolicy:
        return self._policy.model_copy(deep=True)

    def authorize_tools_list(
        self,
        token: str | None,
        context: MCPOAuthRequestContext,
        definitions: Iterable[MCPToolDefinition],
        *,
        now: datetime | None = None,
    ) -> MCPOAuthAuthorizationResult:
        """Verify a request token and expose only effectively authorized tools."""
        current_time = now or utcnow()
        if context.operation != MCPOAuthOperation.TOOLS_LIST:
            return self._blocked(
                context,
                MCPOAuthCode.OPERATION_MISMATCH,
                "Request context is not a tools/list operation",
                current_time,
                token=token,
            )
        validated = self._validate(token, context, current_time)
        if isinstance(validated, MCPOAuthAuthorizationResult):
            return validated
        replay_failure = self._claim(validated, context, current_time)
        if replay_failure is not None:
            return replay_failure
        claims = validated.parsed.claims
        if self._policy.tools_list_scope not in claims.scopes:
            return self._blocked(
                context,
                MCPOAuthCode.SCOPE_MISSING,
                "Access token does not authorize MCP tool discovery",
                current_time,
                token=token,
                key_id=validated.parsed.header.kid,
            )
        visible: list[MCPToolDefinition] = []
        for definition in definitions:
            tool_policy = self._policy.tool_policy_for(definition.name)
            if definition.server_id != context.server_id or tool_policy is None:
                continue
            if not tool_policy.required_scopes.issubset(claims.scopes):
                continue
            if tool_policy.allowed_resource_ids and not (
                tool_policy.allowed_resource_ids & claims.resource_ids
            ):
                continue
            visible.append(definition.model_copy(deep=True))
        return self._allowed(
            context,
            validated.authorization,
            current_time,
            token=token,
            key_id=validated.parsed.header.kid,
            visible_tools=tuple(visible),
        )

    def require_tools_list(
        self,
        token: str | None,
        context: MCPOAuthRequestContext,
        definitions: Iterable[MCPToolDefinition],
        *,
        now: datetime | None = None,
    ) -> tuple[MCPToolDefinition, ...]:
        """Return authorized tool definitions or raise before model exposure."""
        result = self.authorize_tools_list(token, context, definitions, now=now)
        if not result.is_allowed:
            raise MCPOAuthAuthorizationError(result)
        return tuple(tool.model_copy(deep=True) for tool in result.visible_tools)

    def authorize_tool_call(
        self,
        token: str | None,
        context: MCPOAuthRequestContext,
        definition: MCPToolDefinition,
        arguments: Mapping[str, JsonValue],
        *,
        now: datetime | None = None,
    ) -> MCPOAuthAuthorizationResult:
        """Authorize exact tool identity, scopes, and argument-level resources."""
        current_time = now or utcnow()
        if context.operation != MCPOAuthOperation.TOOLS_CALL:
            return self._blocked(
                context,
                MCPOAuthCode.OPERATION_MISMATCH,
                "Request context is not a tools/call operation",
                current_time,
                token=token,
                tool_name=definition.name,
            )
        validated = self._validate(token, context, current_time)
        if isinstance(validated, MCPOAuthAuthorizationResult):
            return validated
        replay_failure = self._claim(validated, context, current_time)
        if replay_failure is not None:
            return replay_failure
        if definition.server_id != context.server_id:
            return self._blocked(
                context,
                MCPOAuthCode.SERVER_MISMATCH,
                "Tool identity belongs to a different MCP server",
                current_time,
                token=token,
                key_id=validated.parsed.header.kid,
                tool_name=definition.name,
            )
        tool_policy = self._policy.tool_policy_for(definition.name)
        if tool_policy is None:
            return self._blocked(
                context,
                MCPOAuthCode.TOOL_NOT_AUTHORIZED,
                "Tool identity is not present in OAuth authorization policy",
                current_time,
                token=token,
                key_id=validated.parsed.header.kid,
                tool_name=definition.name,
            )
        claims = validated.parsed.claims
        if not tool_policy.required_scopes.issubset(claims.scopes):
            return self._blocked(
                context,
                MCPOAuthCode.SCOPE_MISSING,
                "Access token does not contain every scope required by the tool",
                current_time,
                token=token,
                key_id=validated.parsed.header.kid,
                tool_name=definition.name,
            )
        if token is not None and _contains_caller_token(dict(arguments), token):
            return self._blocked(
                context,
                MCPOAuthCode.TOKEN_PASSTHROUGH,
                "Caller access token must not be forwarded in tool arguments",
                current_time,
                token=token,
                key_id=validated.parsed.header.kid,
                tool_name=definition.name,
            )
        resource_ids_or_error = self._argument_resources(
            context,
            token,
            validated,
            tool_policy,
            arguments,
            definition.name,
            current_time,
        )
        if isinstance(resource_ids_or_error, MCPOAuthAuthorizationResult):
            return resource_ids_or_error
        authorization = validated.authorization.model_copy(
            update={
                "tool_name": definition.name,
                "argument_resource_ids": resource_ids_or_error,
            },
            deep=True,
        )
        return self._allowed(
            context,
            authorization,
            current_time,
            token=token,
            key_id=validated.parsed.header.kid,
            tool_name=definition.name,
            resource_ids=resource_ids_or_error,
        )

    def require_tool_call(
        self,
        token: str | None,
        context: MCPOAuthRequestContext,
        definition: MCPToolDefinition,
        arguments: Mapping[str, JsonValue],
        *,
        now: datetime | None = None,
    ) -> AuthorizedMCPOAuthRequest:
        """Return immutable call authority or raise before tool dispatch."""
        result = self.authorize_tool_call(token, context, definition, arguments, now=now)
        if not result.is_allowed or result.authorization is None:
            raise MCPOAuthAuthorizationError(result)
        return result.authorization.model_copy(deep=True)

    def _validate(
        self,
        token: str | None,
        context: MCPOAuthRequestContext,
        current_time: datetime,
    ) -> _ValidatedToken | MCPOAuthAuthorizationResult:
        if token is None or not token:
            return self._blocked(
                context,
                MCPOAuthCode.TOKEN_MISSING,
                "MCP request is missing its access token",
                current_time,
            )
        try:
            parsed = _parse_token(token, self._policy)
        except _TokenParseError as exc:
            return self._blocked(context, exc.code, str(exc), current_time, token=token)
        trusted_key = self._trusted_keys.get(parsed.header.kid)
        if trusted_key is None or trusted_key.algorithm.value != parsed.header.alg:
            return self._blocked(
                context,
                MCPOAuthCode.KEY_NOT_TRUSTED,
                "Access token key is not pinned for the configured issuer and algorithm",
                current_time,
                token=token,
                key_id=parsed.header.kid,
            )
        if (
            trusted_key.revoked
            or (trusted_key.active_from is not None and current_time < trusted_key.active_from)
            or (trusted_key.expires_at is not None and current_time >= trusted_key.expires_at)
        ):
            return self._blocked(
                context,
                MCPOAuthCode.KEY_NOT_ACTIVE,
                "Access token signing key is not active",
                current_time,
                token=token,
                key_id=parsed.header.kid,
            )
        try:
            Ed25519PublicKey.from_public_bytes(trusted_key.public_key).verify(
                parsed.signature,
                parsed.signing_input,
            )
        except (InvalidSignature, ValueError):
            return self._blocked(
                context,
                MCPOAuthCode.SIGNATURE_INVALID,
                "Access token signature is invalid",
                current_time,
                token=token,
                key_id=parsed.header.kid,
            )
        claims = parsed.claims
        checks: Sequence[tuple[bool, MCPOAuthCode, str]] = (
            (
                claims.issuer == self._policy.issuer == trusted_key.issuer,
                MCPOAuthCode.ISSUER_MISMATCH,
                "Access token issuer does not match the pinned resource-server issuer",
            ),
            (
                claims.audiences == frozenset({self._policy.audience}),
                MCPOAuthCode.AUDIENCE_MISMATCH,
                "Access token audience is not exclusively bound to this MCP service",
            ),
            (
                claims.resources == frozenset({self._policy.resource}),
                MCPOAuthCode.RESOURCE_MISMATCH,
                "Access token resource indicator is not exclusively bound to this MCP service",
            ),
            (
                claims.client_id == context.client_id,
                MCPOAuthCode.CLIENT_MISMATCH,
                "Access token client does not match the authenticated client",
            ),
            (
                claims.subject_id == context.subject_id,
                MCPOAuthCode.SUBJECT_MISMATCH,
                "Access token subject does not match the authenticated subject",
            ),
            (
                claims.user_id == context.user_id,
                MCPOAuthCode.USER_MISMATCH,
                "Access token user does not match the authenticated user",
            ),
            (
                claims.tenant_id == context.tenant_id,
                MCPOAuthCode.TENANT_MISMATCH,
                "Access token tenant does not match the authenticated tenant",
            ),
            (
                claims.server_id == context.server_id == self._policy.server_id,
                MCPOAuthCode.SERVER_MISMATCH,
                "Access token server does not match the authenticated MCP server",
            ),
            (
                claims.request_id == context.request_id,
                MCPOAuthCode.REQUEST_MISMATCH,
                "Access token is not bound to this MCP request",
            ),
            (
                claims.scopes.issubset(self._policy.allowed_scopes),
                MCPOAuthCode.SCOPE_EXCESSIVE,
                "Access token contains scopes outside resource-server policy",
            ),
            (
                claims.resource_ids.issubset(self._policy.allowed_resource_ids),
                MCPOAuthCode.RESOURCE_EXCESSIVE,
                "Access token contains resource identifiers outside tool policy",
            ),
        )
        for passed, code, message in checks:
            if not passed:
                return self._blocked(
                    context,
                    code,
                    message,
                    current_time,
                    token=token,
                    key_id=parsed.header.kid,
                )
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        issued_at = datetime.fromtimestamp(claims.issued_at, tz=UTC)
        not_before = datetime.fromtimestamp(claims.not_before, tz=UTC)
        expires_at = datetime.fromtimestamp(claims.expires_at, tz=UTC)
        time_checks: Sequence[tuple[bool, MCPOAuthCode, str]] = (
            (
                issued_at <= current_time + skew and not_before <= current_time + skew,
                MCPOAuthCode.TOKEN_NOT_YET_VALID,
                "Access token is not yet valid",
            ),
            (
                expires_at > current_time - skew,
                MCPOAuthCode.TOKEN_EXPIRED,
                "Access token has expired",
            ),
            (
                expires_at - issued_at <= timedelta(seconds=self._policy.max_token_ttl_seconds),
                MCPOAuthCode.TOKEN_TTL_EXCEEDED,
                "Access token lifetime exceeds resource-server policy",
            ),
            (
                current_time - issued_at
                <= timedelta(seconds=self._policy.max_token_age_seconds) + skew,
                MCPOAuthCode.TOKEN_TOO_OLD,
                "Access token is older than resource-server policy permits",
            ),
        )
        for passed, code, message in time_checks:
            if not passed:
                return self._blocked(
                    context,
                    code,
                    message,
                    current_time,
                    token=token,
                    key_id=parsed.header.kid,
                )
        authorization = AuthorizedMCPOAuthRequest(
            operation=context.operation,
            server_id=context.server_id,
            tenant_id=context.tenant_id,
            user_id=context.user_id,
            subject_id=context.subject_id,
            client_id=context.client_id,
            request_id=context.request_id,
            scopes=claims.scopes,
            resource_ids=claims.resource_ids,
            token_ref=parsed.token_ref,
            token_id_ref=oauth_reference(f"{claims.issuer}\0{claims.token_id}"),
            expires_at=expires_at,
        )
        return _ValidatedToken(parsed=parsed, authorization=authorization)

    def _argument_resources(
        self,
        context: MCPOAuthRequestContext,
        token: str | None,
        validated: _ValidatedToken,
        tool_policy: MCPOAuthToolPolicy,
        arguments: Mapping[str, JsonValue],
        tool_name: str,
        current_time: datetime,
    ) -> frozenset[str] | MCPOAuthAuthorizationResult:
        resources: set[str] = set()
        for pointer in tool_policy.resource_argument_pointers:
            try:
                value = _pointer_value(arguments, pointer)
            except KeyError:
                return self._blocked(
                    context,
                    MCPOAuthCode.ARGUMENT_RESOURCE_MISSING,
                    "Required tool resource argument is missing",
                    current_time,
                    token=token,
                    key_id=validated.parsed.header.kid,
                    tool_name=tool_name,
                )
            if not isinstance(value, str) or not value or len(value) > 1_024:
                return self._blocked(
                    context,
                    MCPOAuthCode.ARGUMENT_RESOURCE_INVALID,
                    "Tool resource argument must be one bounded string identifier",
                    current_time,
                    token=token,
                    key_id=validated.parsed.header.kid,
                    tool_name=tool_name,
                )
            resources.add(value)
        if not resources.issubset(tool_policy.allowed_resource_ids) or not resources.issubset(
            validated.parsed.claims.resource_ids
        ):
            return self._blocked(
                context,
                MCPOAuthCode.RESOURCE_NOT_AUTHORIZED,
                "Tool argument resource is outside token or tool authorization",
                current_time,
                token=token,
                key_id=validated.parsed.header.kid,
                tool_name=tool_name,
                resource_ids=resources,
            )
        return frozenset(resources)

    def _claim(
        self,
        validated: _ValidatedToken,
        context: MCPOAuthRequestContext,
        current_time: datetime,
    ) -> MCPOAuthAuthorizationResult | None:
        replay_id = validated.authorization.token_id_ref
        try:
            status = self._replay_store.claim(
                replay_id,
                expires_at=validated.authorization.expires_at
                + timedelta(seconds=self._policy.clock_skew_seconds),
                now=current_time,
            )
        except Exception:
            return self._blocked(
                context,
                MCPOAuthCode.REPLAY_STORE_ERROR,
                "Token replay state is unavailable",
                current_time,
                token_ref=validated.authorization.token_ref,
                key_id=validated.parsed.header.kid,
            )
        if status == MCPOAuthReplayStatus.REPLAYED:
            return self._blocked(
                context,
                MCPOAuthCode.TOKEN_REPLAYED,
                "Access token has already been consumed",
                current_time,
                token_ref=validated.authorization.token_ref,
                key_id=validated.parsed.header.kid,
            )
        if status == MCPOAuthReplayStatus.FULL:
            return self._blocked(
                context,
                MCPOAuthCode.REPLAY_STORE_FULL,
                "Token replay state is at capacity",
                current_time,
                token_ref=validated.authorization.token_ref,
                key_id=validated.parsed.header.kid,
            )
        return None

    def _allowed(
        self,
        context: MCPOAuthRequestContext,
        authorization: AuthorizedMCPOAuthRequest,
        current_time: datetime,
        *,
        token: str | None,
        key_id: str,
        tool_name: str | None = None,
        resource_ids: Iterable[str] = (),
        visible_tools: tuple[MCPToolDefinition, ...] = (),
    ) -> MCPOAuthAuthorizationResult:
        event = self._audit_event(
            context,
            GuardAction.ALLOW,
            MCPOAuthCode.ALLOWED,
            current_time,
            token=token,
            key_id=key_id,
            tool_name=tool_name,
            resource_ids=resource_ids,
        )
        self._emit(event)
        return MCPOAuthAuthorizationResult(
            action=GuardAction.ALLOW,
            audit_event=event,
            authorization=authorization,
            visible_tools=visible_tools,
        )

    def _blocked(
        self,
        context: MCPOAuthRequestContext,
        code: MCPOAuthCode,
        message: str,
        current_time: datetime,
        *,
        token: str | None = None,
        token_ref: str | None = None,
        key_id: str | None = None,
        tool_name: str | None = None,
        resource_ids: Iterable[str] = (),
    ) -> MCPOAuthAuthorizationResult:
        event = self._audit_event(
            context,
            GuardAction.BLOCK,
            code,
            current_time,
            token=token,
            token_ref=token_ref,
            key_id=key_id,
            tool_name=tool_name,
            resource_ids=resource_ids,
        )
        self._emit(event)
        return MCPOAuthAuthorizationResult(
            action=GuardAction.BLOCK,
            findings=(MCPOAuthFinding(code=code, severity=Severity.HIGH, message=message),),
            audit_event=event,
        )

    def _audit_event(
        self,
        context: MCPOAuthRequestContext,
        action: Literal[GuardAction.ALLOW, GuardAction.BLOCK],
        code: MCPOAuthCode,
        current_time: datetime,
        *,
        token: str | None = None,
        token_ref: str | None = None,
        key_id: str | None = None,
        tool_name: str | None = None,
        resource_ids: Iterable[str] = (),
    ) -> MCPOAuthAuditEvent:
        return MCPOAuthAuditEvent(
            occurred_at=current_time,
            action=action,
            operation=context.operation,
            code=code,
            token_ref=token_ref or (oauth_reference(token) if token else None),
            key_ref=oauth_reference(key_id) if key_id else None,
            issuer_ref=oauth_reference(self._policy.issuer),
            server_ref=oauth_reference(context.server_id),
            tenant_ref=oauth_reference(context.tenant_id),
            user_ref=oauth_reference(context.user_id),
            subject_ref=oauth_reference(context.subject_id),
            client_ref=oauth_reference(context.client_id),
            request_ref=oauth_reference(context.request_id),
            tool_ref=oauth_reference(tool_name) if tool_name else None,
            resource_refs=tuple(sorted(oauth_reference(item) for item in resource_ids)),
        )

    def _emit(self, event: MCPOAuthAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


class MCPOAuthDownstreamBroker:
    """Issue exchanged or workload credentials and reject bearer passthrough."""

    def __init__(
        self,
        provider: MCPOAuthDownstreamCredentialProvider,
        *,
        audit_sink: MCPOAuthAuditSink | None = None,
    ) -> None:
        self._provider = provider
        self._audit_sink = audit_sink

    def acquire(
        self,
        request: MCPOAuthDownstreamRequest,
        *,
        subject_token: CredentialMaterial | None = None,
        now: datetime | None = None,
    ) -> CredentialMaterial:
        """Return a non-passthrough downstream credential or raise content-safely."""
        current_time = now or utcnow()
        authorization = request.authorization
        if (
            authorization.operation != MCPOAuthOperation.TOOLS_CALL
            or authorization.tool_name is None
        ):
            self._raise(
                request,
                MCPOAuthCode.TOOL_NOT_AUTHORIZED,
                "Downstream credentials require an authorized tools/call request",
                current_time,
            )
        if (
            authorization.argument_resource_ids
            and request.resource_id not in authorization.argument_resource_ids
        ) or (
            not authorization.argument_resource_ids
            and request.resource_id is not None
            and request.resource_id not in authorization.resource_ids
        ):
            self._raise(
                request,
                MCPOAuthCode.RESOURCE_NOT_AUTHORIZED,
                "Downstream resource does not match verified caller authority",
                current_time,
            )
        if current_time >= authorization.expires_at:
            self._raise(
                request,
                MCPOAuthCode.TOKEN_EXPIRED,
                "MCP authorization expired before downstream credential issuance",
                current_time,
            )
        if not request.scopes.issubset(authorization.scopes):
            self._raise(
                request,
                MCPOAuthCode.DOWNSTREAM_SCOPE_INVALID,
                "Downstream scopes exceed the verified caller authority",
                current_time,
            )
        try:
            if request.mode == MCPOAuthDownstreamMode.TOKEN_EXCHANGE:
                if subject_token is None or (
                    oauth_reference(subject_token.reveal()) != authorization.token_ref
                ):
                    self._raise(
                        request,
                        MCPOAuthCode.REQUEST_MISMATCH,
                        "Token exchange requires the exact verified subject token",
                        current_time,
                    )
                credential = self._provider.exchange(request, subject_token)
            else:
                if subject_token is not None:
                    self._raise(
                        request,
                        MCPOAuthCode.TOKEN_PASSTHROUGH,
                        "Workload credential flow must not receive a caller token",
                        current_time,
                    )
                credential = self._provider.workload_credential(request)
        except MCPOAuthDownstreamCredentialError:
            raise
        except Exception as exc:
            self._raise(
                request,
                MCPOAuthCode.DOWNSTREAM_CREDENTIAL_UNAVAILABLE,
                "Downstream credential provider is unavailable",
                current_time,
                cause=exc,
            )
        if oauth_reference(credential.reveal()) == authorization.token_ref:
            credential.close()
            self._raise(
                request,
                MCPOAuthCode.TOKEN_PASSTHROUGH,
                "Credential provider returned the caller bearer token",
                current_time,
            )
        self._emit(self._event(request, GuardAction.ALLOW, MCPOAuthCode.ALLOWED, current_time))
        return credential

    def _raise(
        self,
        request: MCPOAuthDownstreamRequest,
        code: MCPOAuthCode,
        message: str,
        current_time: datetime,
        *,
        cause: Exception | None = None,
    ) -> Never:
        event = self._event(request, GuardAction.BLOCK, code, current_time)
        self._emit(event)
        error = MCPOAuthDownstreamCredentialError(code=code, audit_event=event, message=message)
        if cause is None:
            raise error
        raise error from cause

    def _event(
        self,
        request: MCPOAuthDownstreamRequest,
        action: Literal[GuardAction.ALLOW, GuardAction.BLOCK],
        code: MCPOAuthCode,
        current_time: datetime,
    ) -> MCPOAuthAuditEvent:
        authorization = request.authorization
        return MCPOAuthAuditEvent(
            occurred_at=current_time,
            action=action,
            operation=MCPOAuthOperation.DOWNSTREAM_CREDENTIAL,
            code=code,
            token_ref=authorization.token_ref,
            server_ref=oauth_reference(authorization.server_id),
            tenant_ref=oauth_reference(authorization.tenant_id),
            user_ref=oauth_reference(authorization.user_id),
            subject_ref=oauth_reference(authorization.subject_id),
            client_ref=oauth_reference(authorization.client_id),
            request_ref=oauth_reference(authorization.request_id),
            tool_ref=(
                oauth_reference(authorization.tool_name) if authorization.tool_name else None
            ),
            resource_refs=tuple(
                oauth_reference(item)
                for item in (request.resource, request.resource_id)
                if item is not None
            ),
        )

    def _emit(self, event: MCPOAuthAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


__all__ = [
    "MCPOAuthAuditSink",
    "MCPOAuthDownstreamBroker",
    "MCPOAuthDownstreamCredentialProvider",
    "MCPOAuthReplayStore",
    "MCPOAuthResourceServer",
    "MemoryMCPOAuthAuditSink",
    "MemoryMCPOAuthReplayStore",
]
