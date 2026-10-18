"""Strict structured-output validation and downstream-use binding."""

from __future__ import annotations

import json
import math
import threading
import unicodedata
from collections import deque
from typing import Any, Generic, NoReturn, Protocol, cast

from pydantic import ValidationError

from trustrail.exceptions import StructuredOutputError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.structured_output import (
    AuthorizedStructuredOutput,
    StructuredOutputAuditEvent,
    StructuredOutputBinding,
    StructuredOutputCode,
    StructuredOutputContract,
    StructuredOutputDecision,
    StructuredOutputFinding,
    StructuredOutputPhase,
    StructuredOutputUse,
    TStructured,
    ValidatedStructuredOutput,
    canonical_structured_output_json,
    structured_output_digest,
    structured_output_reference,
)

_CONTROL_CHARACTERS = frozenset(chr(value) for value in (*range(0x20), 0x7F))


class StructuredOutputAuditSink(Protocol):
    """Persist content-free structured-output lifecycle evidence."""

    def emit(self, event: StructuredOutputAuditEvent) -> None: ...


class MemoryStructuredOutputAuditSink:
    """Bounded, process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[StructuredOutputAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: StructuredOutputAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[StructuredOutputAuditEvent]:
        """Return a snapshot of emitted events."""
        with self._lock:
            return list(self._events)


class _ParseFailureError(Exception):
    def __init__(self, code: StructuredOutputCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message


class _DuplicateKeyError(ValueError):
    pass


class _NumberError(ValueError):
    pass


def _schema_nodes(value: object) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    stack = [value]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        node = cast(dict[str, Any], current)
        nodes.append(node)

        for keyword in ("$defs", "definitions", "properties", "patternProperties"):
            mapping = node.get(keyword)
            if isinstance(mapping, dict):
                stack.extend(mapping.values())
        for keyword in (
            "additionalProperties",
            "contains",
            "else",
            "if",
            "items",
            "not",
            "propertyNames",
            "then",
        ):
            child = node.get(keyword)
            if isinstance(child, dict):
                stack.append(child)
        for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
            children = node.get(keyword)
            if isinstance(children, list):
                stack.extend(children)
    return nodes


def _resolve_local_ref(schema: dict[str, Any], candidate: object) -> dict[str, Any] | None:
    if not isinstance(candidate, dict):
        return None
    reference = candidate.get("$ref")
    if reference is None:
        return cast(dict[str, Any], candidate)
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    resolved: object = schema
    for encoded_part in reference[2:].split("/"):
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(resolved, dict) or part not in resolved:
            return None
        resolved = resolved[part]
    return cast(dict[str, Any], resolved) if isinstance(resolved, dict) else None


def _is_nullable_union(branches: object) -> bool:
    if not isinstance(branches, list) or len(branches) != 2:
        return False
    null_branches = 0
    for branch in branches:
        if not isinstance(branch, dict):
            continue
        branch_type = branch.get("type")
        if isinstance(branch_type, str) and branch_type == "null":
            null_branches += 1
    return null_branches == 1


def _validate_discriminated_union(
    root: dict[str, Any],
    node: dict[str, Any],
    branches: object,
) -> bool:
    discriminator = node.get("discriminator")
    if not isinstance(branches, list) or len(branches) < 2 or not isinstance(discriminator, dict):
        return False
    property_name = discriminator.get("propertyName")
    if not isinstance(property_name, str) or not property_name:
        return False
    for branch in branches:
        resolved = _resolve_local_ref(root, branch)
        if resolved is None:
            return False
        properties = resolved.get("properties")
        required = resolved.get("required")
        if not isinstance(properties, dict) or property_name not in properties:
            return False
        if not isinstance(required, list) or property_name not in required:
            return False
        tag_schema = properties[property_name]
        if not isinstance(tag_schema, dict) or "const" not in tag_schema:
            return False
    return True


def _validate_contract_schema(contract: StructuredOutputContract[Any]) -> dict[str, Any]:
    """Reject schemas whose generated JSON Schema is permissive or ambiguous."""
    try:
        schema = cast(dict[str, Any], contract.model.model_json_schema(mode="validation"))
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("structured-output model cannot produce a validation schema") from exc

    policy = contract.policy
    for node in _schema_nodes(schema):
        node_type = node.get("type")
        if isinstance(node_type, list):
            non_null = [item for item in node_type if item != "null"]
            if len(node_type) != 2 or len(non_null) != 1:
                raise ValueError("structured-output unions must be explicit and unambiguous")

        if node_type == "object":
            properties = node.get("properties", {})
            if not isinstance(properties, dict):
                raise ValueError("structured-output object properties must be explicit")
            if len(properties) > policy.max_object_properties:
                raise ValueError("structured-output schema exceeds the object property limit")
            if policy.require_closed_objects and node.get("additionalProperties") is not False:
                raise ValueError("every structured-output object must set extra='forbid'")

        if node_type == "array":
            maximum = node.get("maxItems")
            if policy.require_bounded_arrays and (
                isinstance(maximum, bool) or not isinstance(maximum, int)
            ):
                raise ValueError("every structured-output array must declare max_length")
            if isinstance(maximum, int) and maximum > policy.max_array_items:
                raise ValueError("structured-output array exceeds the policy item limit")

        for keyword in ("anyOf", "oneOf"):
            if keyword not in node or _is_nullable_union(node[keyword]):
                continue
            if policy.require_discriminated_unions and (
                keyword != "oneOf" or not _validate_discriminated_union(schema, node, node[keyword])
            ):
                raise ValueError(
                    "non-null structured-output unions require an explicit discriminator"
                )
    return schema


def _schema_digest(contract: StructuredOutputContract[Any], schema: dict[str, Any]) -> str:
    identity = {
        "allowed_uses": sorted(item.value for item in contract.allowed_uses),
        "policy": contract.policy.model_dump(mode="json"),
        "schema": schema,
        "schema_id": contract.schema_id,
        "schema_version": contract.schema_version,
    }
    return structured_output_digest(canonical_structured_output_json(identity))


class StructuredOutputValidator(Generic[TStructured]):
    """Validate a strict schema once, then gate every downstream use by exact binding."""

    def __init__(
        self,
        contract: StructuredOutputContract[TStructured],
        *,
        audit_sink: StructuredOutputAuditSink | None = None,
    ) -> None:
        self._contract = contract
        self._schema = _validate_contract_schema(contract)
        self._schema_digest = _schema_digest(contract, self._schema)
        self._audit_sink = audit_sink

    @property
    def contract(self) -> StructuredOutputContract[TStructured]:
        """Return the immutable application-owned contract."""
        return self._contract

    @property
    def schema_digest(self) -> str:
        """Return the identity digest for the schema, policy, version, and allowed uses."""
        return self._schema_digest

    def validate_json(
        self,
        value: str | bytes,
        *,
        _attempt: int | None = None,
    ) -> ValidatedStructuredOutput[TStructured]:
        """Parse exactly one JSON value and validate the complete object without coercion."""
        phase = (
            StructuredOutputPhase.REPAIR
            if _attempt is not None
            else StructuredOutputPhase.VALIDATION
        )
        self._ensure_schema_current(phase)
        try:
            parsed = self._parse_json(value)
        except _ParseFailureError as exc:
            self._raise(
                phase,
                exc.code,
                Severity.HIGH,
                exc.safe_message,
                attempt=_attempt,
            )

        try:
            model = self._contract.model.model_validate(parsed, strict=True)
        except ValidationError as exc:
            error_types = {str(error.get("type", "")) for error in exc.errors()}
            if any(error_type == "extra_forbidden" for error_type in error_types):
                code = StructuredOutputCode.UNDECLARED_FIELD
                message = "Structured output contains an undeclared field"
            elif any(
                error_type.endswith("_type")
                or error_type.endswith("_parsing")
                or "coerc" in error_type
                for error_type in error_types
            ):
                code = StructuredOutputCode.IMPLICIT_COERCION
                message = "Structured output would require an implicit type coercion"
            else:
                code = StructuredOutputCode.SCHEMA_MISMATCH
                message = "Structured output does not match the complete application schema"
            self._raise(phase, code, Severity.HIGH, message, attempt=_attempt)

        canonical_input = canonical_structured_output_json(parsed)
        canonical_model = canonical_structured_output_json(model.model_dump(mode="json"))
        if canonical_input != canonical_model:
            self._raise(
                phase,
                StructuredOutputCode.SCHEMA_PARSER_DISAGREEMENT,
                Severity.HIGH,
                "Parser and schema validator disagree on the exact structured value",
                attempt=_attempt,
            )

        object_digest = structured_output_digest(canonical_input)
        validated = ValidatedStructuredOutput(
            schema_id=self._contract.schema_id,
            schema_version=self._contract.schema_version,
            schema_digest=self._schema_digest,
            object_digest=object_digest,
            _canonical_json=canonical_input,
            _value=model.model_copy(deep=True),
        )
        self._emit(
            phase=phase,
            code=StructuredOutputCode.VALIDATED,
            action=GuardAction.ALLOW,
            object_digest=object_digest,
            attempt=_attempt,
        )
        return validated

    def validate_typed(self, value: TStructured) -> ValidatedStructuredOutput[TStructured]:
        """Reparse and strictly revalidate a typed output, including constructed models."""
        if type(value) is not self._contract.model:
            self._raise(
                StructuredOutputPhase.VALIDATION,
                StructuredOutputCode.TYPED_OUTPUT_MISMATCH,
                Severity.HIGH,
                "Typed output does not use the application contract model",
            )
        try:
            serialized = value.model_dump_json(warnings="error")
        except (TypeError, ValueError) as exc:
            try:
                self._raise(
                    StructuredOutputPhase.VALIDATION,
                    StructuredOutputCode.TYPED_OUTPUT_MISMATCH,
                    Severity.HIGH,
                    "Typed output cannot be represented by the JSON contract",
                )
            except StructuredOutputError as structured_exc:
                raise structured_exc from exc
        return self.validate_json(serialized)

    def bind(
        self,
        validated: ValidatedStructuredOutput[TStructured],
        *,
        use: StructuredOutputUse,
        context_id: str,
    ) -> StructuredOutputBinding:
        """Bind the exact validated object to one declared downstream operation."""
        self._ensure_schema_current(StructuredOutputPhase.BINDING)
        self._verify_validated(validated, phase=StructuredOutputPhase.BINDING)
        if use not in self._contract.allowed_uses:
            self._raise(
                StructuredOutputPhase.BINDING,
                StructuredOutputCode.USE_NOT_ALLOWED,
                Severity.CRITICAL,
                "Structured-output contract does not permit the requested use",
                object_digest=validated.object_digest,
                use=use,
            )
        context_reference = self._context_reference(context_id, phase=StructuredOutputPhase.BINDING)
        binding = StructuredOutputBinding(
            schema_id=self._contract.schema_id,
            schema_version=self._contract.schema_version,
            schema_digest=self._schema_digest,
            object_digest=validated.object_digest,
            use=use,
            context_reference=context_reference,
        )
        self._emit(
            phase=StructuredOutputPhase.BINDING,
            code=StructuredOutputCode.BOUND,
            action=GuardAction.ALLOW,
            object_digest=validated.object_digest,
            use=use,
            context_reference=context_reference,
        )
        return binding

    def authorize(
        self,
        validated: ValidatedStructuredOutput[TStructured],
        binding: StructuredOutputBinding,
        *,
        use: StructuredOutputUse,
        context_id: str,
    ) -> AuthorizedStructuredOutput[TStructured]:
        """Verify an exact binding and release a defensive value copy to that boundary."""
        self._ensure_schema_current(StructuredOutputPhase.USE)
        verified = self._verify_validated(validated, phase=StructuredOutputPhase.USE)
        expected_context = self._context_reference(context_id, phase=StructuredOutputPhase.USE)
        expected = (
            binding.format_version == 1
            and binding.schema_id == self._contract.schema_id
            and binding.schema_version == self._contract.schema_version
            and binding.schema_digest == self._schema_digest
            and binding.object_digest == validated.object_digest
            and binding.use == use
            and binding.context_reference == expected_context
        )
        if not expected:
            self._raise(
                StructuredOutputPhase.USE,
                StructuredOutputCode.BINDING_MISMATCH,
                Severity.CRITICAL,
                "Structured-output binding does not match the exact downstream operation",
                object_digest=validated.object_digest,
                use=use,
                context_reference=expected_context,
            )
        if use not in self._contract.allowed_uses:
            self._raise(
                StructuredOutputPhase.USE,
                StructuredOutputCode.USE_NOT_ALLOWED,
                Severity.CRITICAL,
                "Structured-output contract does not permit the requested use",
                object_digest=validated.object_digest,
                use=use,
                context_reference=expected_context,
            )
        self._emit(
            phase=StructuredOutputPhase.USE,
            code=StructuredOutputCode.USE_AUTHORIZED,
            action=GuardAction.ALLOW,
            object_digest=validated.object_digest,
            use=use,
            context_reference=expected_context,
        )
        return AuthorizedStructuredOutput(
            value=verified.model_copy(deep=True),
            binding=binding.model_copy(deep=True),
        )

    def new_repair_session(
        self,
        *,
        max_attempts: int | None = None,
    ) -> StructuredOutputRepairSession[TStructured]:
        """Create an explicit full-response revalidation loop with a bounded attempt count."""
        attempts = (
            self._contract.policy.max_repair_attempts if max_attempts is None else max_attempts
        )
        if attempts < 1 or attempts > self._contract.policy.max_repair_attempts:
            raise ValueError("repair attempts must be within the configured policy limit")
        return StructuredOutputRepairSession(self, max_attempts=attempts)

    def _ensure_schema_current(self, phase: StructuredOutputPhase) -> None:
        try:
            current_schema = _validate_contract_schema(self._contract)
            current_digest = _schema_digest(self._contract, current_schema)
        except (TypeError, ValueError, KeyError) as exc:
            try:
                self._raise(
                    phase,
                    StructuredOutputCode.SCHEMA_IDENTITY_CHANGED,
                    Severity.CRITICAL,
                    "Structured-output schema is no longer the validated application contract",
                )
            except StructuredOutputError as structured_exc:
                raise structured_exc from exc
        if current_digest != self._schema_digest:
            self._raise(
                phase,
                StructuredOutputCode.SCHEMA_IDENTITY_CHANGED,
                Severity.CRITICAL,
                "Structured-output schema identity changed after validator construction",
            )

    def _parse_json(self, value: str | bytes) -> object:
        policy = self._contract.policy
        if isinstance(value, bytes):
            if len(value) > policy.max_input_bytes:
                raise _ParseFailureError(
                    StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
                    "Structured output exceeds the configured byte limit",
                )
            try:
                text = value.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise _ParseFailureError(
                    StructuredOutputCode.AMBIGUOUS_ENCODING,
                    "Structured output is not strict UTF-8",
                ) from exc
        else:
            text = value
            if len(text.encode("utf-8", errors="surrogatepass")) > policy.max_input_bytes:
                raise _ParseFailureError(
                    StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
                    "Structured output exceeds the configured byte limit",
                )
        if not text or len(text) > policy.max_input_chars:
            raise _ParseFailureError(
                StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
                "Structured output is empty or exceeds the configured character limit",
            )
        if text.startswith("\ufeff"):
            raise _ParseFailureError(
                StructuredOutputCode.AMBIGUOUS_ENCODING,
                "Structured output must not contain a byte-order mark",
            )

        def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, nested in pairs:
                if key in result:
                    raise _DuplicateKeyError
                result[key] = nested
            return result

        def parse_int(token: str) -> int:
            if len(token) > policy.max_number_chars:
                raise _NumberError
            return int(token)

        def parse_float(token: str) -> float:
            if len(token) > policy.max_number_chars:
                raise _NumberError
            parsed_number = float(token)
            if not math.isfinite(parsed_number):
                raise _NumberError
            return parsed_number

        def reject_constant(_: str) -> float:
            raise _NumberError

        decoder = json.JSONDecoder(
            object_pairs_hook=object_pairs,
            parse_int=parse_int,
            parse_float=parse_float,
            parse_constant=reject_constant,
        )
        start = len(text) - len(text.lstrip())
        try:
            parsed, end = decoder.raw_decode(text, start)
        except _DuplicateKeyError as exc:
            raise _ParseFailureError(
                StructuredOutputCode.DUPLICATE_KEY,
                "Structured output contains a duplicate object key",
            ) from exc
        except _NumberError as exc:
            raise _ParseFailureError(
                StructuredOutputCode.NON_FINITE_NUMBER,
                "Structured output contains a non-finite or oversized number",
            ) from exc
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise _ParseFailureError(
                StructuredOutputCode.INVALID_JSON,
                "Structured output is not one complete strict JSON value",
            ) from exc
        if text[end:].strip():
            raise _ParseFailureError(
                StructuredOutputCode.TRAILING_DATA,
                "Structured output contains trailing data after the JSON value",
            )
        self._validate_runtime_structure(parsed)
        return parsed

    def _validate_runtime_structure(self, value: object) -> None:
        policy = self._contract.policy
        stack: list[tuple[object, int]] = [(value, 0)]
        nodes = 0
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if nodes > policy.max_nodes or depth > policy.max_depth:
                raise _ParseFailureError(
                    StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
                    "Structured output exceeds configured depth or node limits",
                )
            if isinstance(current, dict):
                if len(current) > policy.max_object_properties:
                    raise _ParseFailureError(
                        StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
                        "Structured output exceeds the object property limit",
                    )
                for key, nested in current.items():
                    self._validate_unicode(key)
                    stack.append((nested, depth + 1))
            elif isinstance(current, list):
                if len(current) > policy.max_array_items:
                    raise _ParseFailureError(
                        StructuredOutputCode.STRUCTURE_LIMIT_EXCEEDED,
                        "Structured output exceeds the array item limit",
                    )
                stack.extend((nested, depth + 1) for nested in current)
            elif isinstance(current, str):
                self._validate_unicode(current)
            elif isinstance(current, float) and not math.isfinite(current):
                raise _ParseFailureError(
                    StructuredOutputCode.NON_FINITE_NUMBER,
                    "Structured output contains a non-finite number",
                )

    def _validate_unicode(self, value: str) -> None:
        if (
            "\ufeff" in value
            or any(character in _CONTROL_CHARACTERS for character in value)
            or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
        ):
            raise _ParseFailureError(
                StructuredOutputCode.AMBIGUOUS_ENCODING,
                "Structured output contains ambiguous Unicode or control characters",
            )
        if (
            self._contract.policy.reject_non_normalized_unicode
            and unicodedata.normalize("NFC", value) != value
        ):
            raise _ParseFailureError(
                StructuredOutputCode.AMBIGUOUS_ENCODING,
                "Structured output Unicode must use NFC normalization",
            )

    def _verify_validated(
        self,
        validated: ValidatedStructuredOutput[TStructured],
        *,
        phase: StructuredOutputPhase,
    ) -> TStructured:
        identity_matches = (
            validated.schema_id == self._contract.schema_id
            and validated.schema_version == self._contract.schema_version
            and validated.schema_digest == self._schema_digest
            and structured_output_digest(validated._canonical_json) == validated.object_digest
            and type(validated._value) is self._contract.model
        )
        try:
            parsed = self._parse_json(validated._canonical_json)
            reparsed_model = self._contract.model.model_validate(parsed, strict=True)
            canonical_reparsed = canonical_structured_output_json(
                reparsed_model.model_dump(mode="json")
            )
            canonical_value = canonical_structured_output_json(
                validated._value.model_dump(mode="json")
            )
        except (AttributeError, ValidationError, _ParseFailureError, TypeError, ValueError):
            identity_matches = False
            reparsed_model = None
            canonical_reparsed = ""
            canonical_value = ""
        if (
            not identity_matches
            or reparsed_model is None
            or canonical_reparsed != validated._canonical_json
            or canonical_value != validated._canonical_json
        ):
            self._raise(
                phase,
                StructuredOutputCode.VALIDATED_OBJECT_CHANGED,
                Severity.CRITICAL,
                "Validated structured output or its schema identity changed before use",
                object_digest=validated.object_digest,
            )
        return reparsed_model

    def _context_reference(self, context_id: str, *, phase: StructuredOutputPhase) -> str:
        if (
            not context_id
            or len(context_id) > 4_096
            or any(character in _CONTROL_CHARACTERS for character in context_id)
        ):
            self._raise(
                phase,
                StructuredOutputCode.BINDING_MISMATCH,
                Severity.CRITICAL,
                "Downstream context identifier is missing or invalid",
            )
        return structured_output_reference(context_id)

    def _raise(
        self,
        phase: StructuredOutputPhase,
        code: StructuredOutputCode,
        severity: Severity,
        message: str,
        *,
        object_digest: str | None = None,
        use: StructuredOutputUse | None = None,
        context_reference: str | None = None,
        attempt: int | None = None,
    ) -> NoReturn:
        finding = StructuredOutputFinding(code=code, severity=severity, message=message)
        decision = StructuredOutputDecision(
            phase=phase,
            action=GuardAction.BLOCK,
            schema_id=self._contract.schema_id,
            schema_version=self._contract.schema_version,
            schema_digest=self._schema_digest,
            object_digest=object_digest,
            use=use,
            attempt=attempt,
            findings=(finding,),
        )
        self._emit(
            phase=phase,
            code=code,
            action=GuardAction.BLOCK,
            object_digest=object_digest,
            use=use,
            context_reference=context_reference,
            attempt=attempt,
        )
        raise StructuredOutputError(decision)

    def _emit(
        self,
        *,
        phase: StructuredOutputPhase,
        code: StructuredOutputCode,
        action: GuardAction,
        object_digest: str | None = None,
        use: StructuredOutputUse | None = None,
        context_reference: str | None = None,
        attempt: int | None = None,
    ) -> None:
        if self._audit_sink is None:
            return
        self._audit_sink.emit(
            StructuredOutputAuditEvent(
                phase=phase,
                code=code,
                action=action,
                schema_id=self._contract.schema_id,
                schema_version=self._contract.schema_version,
                schema_digest=self._schema_digest,
                object_digest=object_digest,
                use=use,
                context_reference=context_reference,
                attempt=attempt,
            )
        )


class StructuredOutputRepairSession(Generic[TStructured]):
    """Explicit, bounded loop that accepts only a newly revalidated complete response."""

    def __init__(
        self,
        validator: StructuredOutputValidator[TStructured],
        *,
        max_attempts: int,
    ) -> None:
        self._validator = validator
        self._max_attempts = max_attempts
        self._attempts = 0
        self._closed = False
        self._lock = threading.Lock()

    @property
    def attempts(self) -> int:
        """Return the number of complete responses submitted to this session."""
        with self._lock:
            return self._attempts

    @property
    def remaining_attempts(self) -> int:
        """Return how many complete responses may still be submitted."""
        with self._lock:
            return max(0, self._max_attempts - self._attempts)

    def validate_json(self, value: str | bytes) -> ValidatedStructuredOutput[TStructured]:
        """Validate one full replacement response; never return partial invalid data."""
        with self._lock:
            if self._closed:
                self._validator._raise(
                    StructuredOutputPhase.REPAIR,
                    StructuredOutputCode.REPAIR_SESSION_CLOSED,
                    Severity.HIGH,
                    "Structured-output repair session is closed",
                )
            self._attempts += 1
            attempt = self._attempts
            try:
                validated = self._validator.validate_json(value, _attempt=attempt)
            except StructuredOutputError as exc:
                if attempt >= self._max_attempts:
                    self._closed = True
                    try:
                        self._validator._raise(
                            StructuredOutputPhase.REPAIR,
                            StructuredOutputCode.REPAIR_EXHAUSTED,
                            Severity.HIGH,
                            "Structured-output repair attempt limit was exhausted",
                            attempt=attempt,
                        )
                    except StructuredOutputError as exhausted:
                        raise exhausted from exc
                raise
            self._closed = True
            return validated
