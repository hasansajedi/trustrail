"""Integrity controls for MCP resources, prompts, subscriptions, and completions."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from pydantic import JsonValue

from trustrail.exceptions import MCPPrimitiveError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.mcp import MCPDefinitionChange, MCPDefinitionChangeKind
from trustrail.models.mcp_primitives import (
    MCPCompletionDefinition,
    MCPCompletionMetadata,
    MCPPrimitiveCode,
    MCPPrimitiveDefinition,
    MCPPrimitiveFinding,
    MCPPrimitiveFingerprint,
    MCPPrimitiveKind,
    MCPPrimitivePhase,
    MCPPrimitivePolicy,
    MCPPrimitiveResult,
    MCPPrimitiveSnapshot,
    MCPPromptDefinition,
    MCPPromptRender,
    MCPResourceContent,
    MCPResourceDefinition,
    MCPResourceTemplateDefinition,
    MCPSubscriptionIdentity,
    fingerprint_primitive,
    snapshot_signing_payload,
)

_INSTRUCTION_PATTERNS = (
    re.compile(
        r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|other)\s+instructions?\b",
        re.I,
    ),
    re.compile(r"\b(?:system|developer)\s+(?:prompt|message|instructions?)\b", re.I),
    re.compile(r"\b(?:you|assistant|model)\s+must\b", re.I),
    re.compile(r"\b(?:do\s+not|never)\s+(?:tell|show|reveal|mention|disclose)\b", re.I),
    re.compile(r"\b(?:secretly|covertly|without\s+(?:the\s+)?user)\b", re.I),
    re.compile(r"<\s*/?\s*(?:instructions?|system|assistant|developer)\b", re.I),
)
_BIDI_CLASSES = {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")
_TEMPLATE_VARIABLE_RE = re.compile(r"\{([A-Za-z][A-Za-z0-9_.-]*)\}")
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_$#.-]{1,128}$")
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",
        "\u0410": "a",
        "\u0391": "a",
        "\u0421": "c",
        "\u0441": "c",
        "\u0415": "e",
        "\u0435": "e",
        "\u0456": "i",
        "\u041e": "o",
        "\u043e": "o",
        "\u0420": "p",
        "\u0440": "p",
        "\u0445": "x",
        "\u0425": "x",
        "\u0443": "y",
    }
)


def _walk(value: object, path: str = "", depth: int = 0) -> Iterable[tuple[str, object, int]]:
    yield path or "/", value, depth
    if isinstance(value, dict):
        for key, item in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            child = f"{path}/{escaped}"
            yield f"{child}/#key", key, depth + 1
            yield from _walk(item, child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}/{index}", depth + 1)


def _unicode_smuggling(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cf", "Cs", "Co"}
        or (unicodedata.category(character) == "Cc" and character not in {"\t", "\n", "\r"})
        or unicodedata.bidirectional(character) in _BIDI_CLASSES
        or 0xFE00 <= ord(character) <= 0xFE0F
        or 0xE0000 <= ord(character) <= 0xE007F
        or 0xE0100 <= ord(character) <= 0xE01EF
        for character in value
    )


def _skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).translate(_CONFUSABLES).casefold()
    return "".join(
        character
        for character in normalized
        if character.isalnum() and not unicodedata.combining(character)
    )


def _safe_reference(value: str) -> str:
    return f"sha256:{hashlib.sha256(unicodedata.normalize('NFC', value).encode()).hexdigest()}"


def _safe_path(value: str) -> str:
    segments = []
    for segment in value.split("/")[1:]:
        if _SAFE_PATH_RE.fullmatch(segment):
            segments.append(segment)
        else:
            segments.append(f"sha256-{hashlib.sha256(segment.encode()).hexdigest()[:16]}")
    return f"/{'/'.join(segments)}"


def _is_dangerous_uri(uri: str, allowed_schemes: frozenset[str], *, template: bool = False) -> bool:
    candidate = _TEMPLATE_VARIABLE_RE.sub("value", uri) if template else uri
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return True
    if not parsed.scheme or parsed.scheme.casefold() not in allowed_schemes:
        return True
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        return True
    if template and ("{" in parsed.scheme or "{" in parsed.netloc):
        return True
    if parsed.scheme.casefold() in {"http", "https"}:
        if not parsed.hostname or (port is None and parsed.netloc.endswith(":")):
            return True
        hostname = parsed.hostname.casefold()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return True
        try:
            address = ipaddress.ip_address(hostname.strip("[]"))
        except ValueError:
            pass
        else:
            if not address.is_global:
                return True
    return ".." in parsed.path.split("/")


def _is_cross_server_uri(uri: str, server_id: str, *, template: bool = False) -> bool:
    candidate = _TEMPLATE_VARIABLE_RE.sub("value", uri) if template else uri
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "mcp"
        and parsed.hostname is not None
        and parsed.hostname.casefold() != server_id.casefold()
    )


class MCPPrimitiveGuard:
    """Fail-closed control plane for non-tool MCP primitives.

    The application supplies authenticated ``server_id`` and ``provenance_id``
    values, protects the signing key and snapshots, and calls a validation
    method immediately before content reaches a model or application sink.
    """

    def __init__(self, signing_key: bytes, policy: MCPPrimitivePolicy | None = None) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._key = bytes(signing_key)
        self._policy = (policy or MCPPrimitivePolicy()).model_copy(deep=True)

    @property
    def policy(self) -> MCPPrimitivePolicy:
        """Return a defensive copy of the primitive policy."""
        return self._policy.model_copy(deep=True)

    def inspect(self, definitions: Iterable[MCPPrimitiveDefinition]) -> MCPPrimitiveResult:
        """Scan complete primitive definitions without creating trust."""
        findings = self._inspection_findings(tuple(definitions))
        return MCPPrimitiveResult(
            action=GuardAction.BLOCK if findings else GuardAction.ALLOW,
            findings=tuple(findings),
        )

    def discover(
        self,
        definitions: Iterable[MCPPrimitiveDefinition],
        *,
        now: datetime | None = None,
    ) -> MCPPrimitiveResult:
        """Scan and sign an exact primitive discovery snapshot."""
        items = tuple(definitions)
        findings = self._inspection_findings(items)
        if findings:
            return MCPPrimitiveResult(action=GuardAction.BLOCK, findings=tuple(findings))
        return MCPPrimitiveResult(
            action=GuardAction.ALLOW,
            snapshot=self._build_snapshot(items, MCPPrimitivePhase.DISCOVERY, None, now),
        )

    def require_discovery(
        self,
        definitions: Iterable[MCPPrimitiveDefinition],
        *,
        now: datetime | None = None,
    ) -> MCPPrimitiveSnapshot:
        """Return a signed discovery snapshot or raise."""
        result = self.discover(definitions, now=now)
        if not result.is_allowed or result.snapshot is None:
            raise MCPPrimitiveError(result)
        return result.snapshot

    def approve(
        self,
        definitions: Iterable[MCPPrimitiveDefinition],
        discovery: MCPPrimitiveSnapshot,
        *,
        approved_by: str,
        now: datetime | None = None,
    ) -> MCPPrimitiveResult:
        """Bind explicit approval to an unchanged signed discovery snapshot."""
        items = tuple(definitions)
        findings = self._inspection_findings(items)
        findings.extend(
            self._snapshot_findings(
                items,
                discovery,
                expected_phase=MCPPrimitivePhase.DISCOVERY,
                mismatch_code=MCPPrimitiveCode.DISCOVERY_MISMATCH,
            )
        )
        if findings:
            return MCPPrimitiveResult(action=GuardAction.BLOCK, findings=tuple(findings))
        return MCPPrimitiveResult(
            action=GuardAction.ALLOW,
            snapshot=self._build_snapshot(items, MCPPrimitivePhase.APPROVAL, approved_by, now),
        )

    def require_approval(
        self,
        definitions: Iterable[MCPPrimitiveDefinition],
        discovery: MCPPrimitiveSnapshot,
        *,
        approved_by: str,
        now: datetime | None = None,
    ) -> MCPPrimitiveSnapshot:
        """Return an approval snapshot or raise for unsafe/changed primitives."""
        result = self.approve(definitions, discovery, approved_by=approved_by, now=now)
        if not result.is_allowed or result.snapshot is None:
            raise MCPPrimitiveError(result)
        return result.snapshot

    def verify_use(
        self,
        definition: MCPPrimitiveDefinition,
        approval: MCPPrimitiveSnapshot,
    ) -> MCPPrimitiveResult:
        """Re-scan and re-hash a live definition immediately before use."""
        findings = self._inspection_findings((definition,), check_relationships=False)
        if findings:
            return MCPPrimitiveResult(action=GuardAction.BLOCK, findings=tuple(findings))
        if approval.phase != MCPPrimitivePhase.APPROVAL or not self._signature_matches(approval):
            return self._single(
                GuardAction.BLOCK,
                MCPPrimitiveCode.PIN_INVALID,
                "MCP primitive approval pin is invalid",
                definition.identity,
            )
        fingerprint = next(
            (item for item in approval.fingerprints if item.identity == definition.identity), None
        )
        if fingerprint is None:
            return self._single(
                GuardAction.REQUIRE_APPROVAL,
                MCPPrimitiveCode.PRIMITIVE_NOT_APPROVED,
                "MCP primitive is absent from the approval snapshot",
                definition.identity,
            )
        observed = fingerprint_primitive(definition)
        if fingerprint.definition_digest != observed.definition_digest:
            return MCPPrimitiveResult(
                action=GuardAction.REQUIRE_APPROVAL,
                findings=(
                    self._mutation_finding(
                        fingerprint,
                        observed,
                        MCPPrimitiveCode.PRIMITIVE_CHANGED,
                        "MCP primitive changed after approval",
                    ),
                ),
            )
        return MCPPrimitiveResult(action=GuardAction.ALLOW, snapshot=approval)

    def require_use(
        self,
        definition: MCPPrimitiveDefinition,
        approval: MCPPrimitiveSnapshot,
    ) -> MCPPrimitiveDefinition:
        """Return the verified definition or raise immediately before use."""
        result = self.verify_use(definition, approval)
        if not result.is_allowed:
            raise MCPPrimitiveError(result)
        return definition

    def validate_resource_content(
        self,
        definition: MCPResourceDefinition | MCPResourceTemplateDefinition,
        content: MCPResourceContent,
        approval: MCPPrimitiveSnapshot,
        *,
        template_arguments: dict[str, str] | None = None,
        subscription: MCPSubscriptionIdentity | None = None,
    ) -> MCPPrimitiveResult:
        """Validate fetched or updated resource content before use."""
        pin = self.verify_use(definition, approval)
        if not pin.is_allowed:
            return pin
        findings: list[MCPPrimitiveFinding] = []
        expected_uri = definition.uri if isinstance(definition, MCPResourceDefinition) else None
        if isinstance(definition, MCPResourceTemplateDefinition):
            expected_uri, argument_findings = self._render_uri(definition, template_arguments or {})
            findings.extend(argument_findings)
        if content.server_id != definition.server_id or content.uri != expected_uri:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.IDENTITY_MISMATCH,
                    Severity.CRITICAL,
                    "Fetched MCP resource does not match the approved server and URI",
                    identities=(definition.identity,),
                )
            )
        if content.provenance_id != definition.provenance_id:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.PROVENANCE_MISMATCH,
                    Severity.CRITICAL,
                    "Fetched MCP resource has unexpected provenance",
                    identities=(definition.identity,),
                )
            )
        if not definition.required_scopes.issubset(content.granted_scopes):
            findings.append(
                self._finding(
                    MCPPrimitiveCode.AUTHORIZATION_MISSING,
                    Severity.CRITICAL,
                    "Fetched MCP resource lacks an approved authorization scope",
                    identities=(definition.identity,),
                )
            )
        mime_type = content.mime_type.casefold()
        if (
            mime_type != definition.mime_type.casefold()
            or mime_type not in self._policy.allowed_mime_types
        ):
            findings.append(
                self._finding(
                    MCPPrimitiveCode.MEDIA_TYPE_DENIED,
                    Severity.HIGH,
                    "Fetched MCP resource media type is not approved",
                    identities=(definition.identity,),
                )
            )
        raw = content.data.encode() if isinstance(content.data, str) else content.data
        if len(raw) > definition.max_size:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "Fetched MCP resource exceeds its approved byte limit",
                    identities=(definition.identity,),
                )
            )
        if content.subscription_id is not None or subscription is not None:
            findings.extend(
                self._subscription_findings(definition, content, approval, subscription)
            )
        findings.extend(self._live_text_findings(content.data, definition.identity, "/data"))
        schema = definition.content_schema
        if schema is not None:
            findings.extend(
                self._content_schema_findings(schema, content.data, definition.identity)
            )
        return self._result(findings, approval)

    def validate_prompt_render(
        self,
        definition: MCPPromptDefinition,
        render: MCPPromptRender,
        approval: MCPPrimitiveSnapshot,
    ) -> MCPPrimitiveResult:
        """Validate ``prompts/get`` arguments, messages, origin, and authorization."""
        pin = self.verify_use(definition, approval)
        if not pin.is_allowed:
            return pin
        findings: list[MCPPrimitiveFinding] = []
        if render.server_id != definition.server_id or render.prompt_name != definition.name:
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.IDENTITY_MISMATCH))
        findings.extend(
            self._provenance_scope_findings(definition, render.provenance_id, render.granted_scopes)
        )
        expected = {argument.name: argument for argument in definition.arguments}
        supplied = set(render.arguments)
        required = {argument.name for argument in definition.arguments if argument.required}
        if not required.issubset(supplied) or not supplied.issubset(expected):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.SCHEMA_MISMATCH))
        for name, value in render.arguments.items():
            argument = expected.get(name)
            if argument is not None and len(value) > argument.max_length:
                findings.append(self._use_mismatch(definition, MCPPrimitiveCode.LIMIT_EXCEEDED))
            findings.extend(
                self._live_text_findings(value, definition.identity, f"/arguments/{name}")
            )
        if (
            len(render.messages) > definition.max_messages
            or sum(len(message.content) for message in render.messages) > definition.max_total_chars
        ):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.LIMIT_EXCEEDED))
        for index, message in enumerate(render.messages):
            findings.extend(
                self._live_text_findings(
                    message.content, definition.identity, f"/messages/{index}/content"
                )
            )
        return self._result(findings, approval)

    def validate_completion(
        self,
        definition: MCPCompletionDefinition,
        metadata: MCPCompletionMetadata,
        approval: MCPPrimitiveSnapshot,
    ) -> MCPPrimitiveResult:
        """Validate completion metadata and suggestions against an approved contract."""
        pin = self.verify_use(definition, approval)
        if not pin.is_allowed:
            return pin
        findings: list[MCPPrimitiveFinding] = []
        if (
            metadata.server_id != definition.server_id
            or metadata.reference_kind != definition.reference_kind
            or metadata.reference_name != definition.reference_name
            or metadata.argument_name != definition.argument_name
        ):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.IDENTITY_MISMATCH))
        findings.extend(
            self._provenance_scope_findings(
                definition, metadata.provenance_id, metadata.granted_scopes
            )
        )
        if not set(metadata.context_arguments).issubset(definition.allowed_context_arguments):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.SCHEMA_MISMATCH))
        if len(metadata.values) > definition.max_values or any(
            len(value) > definition.max_value_length for value in metadata.values
        ):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.LIMIT_EXCEEDED))
        live_chars = sum(map(len, metadata.values)) + sum(
            len(key) + len(value) for key, value in metadata.context_arguments.items()
        )
        if live_chars > self._policy.max_total_string_chars:
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.LIMIT_EXCEEDED))
        if metadata.total is not None and metadata.total < len(metadata.values):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.AMBIGUOUS_SEMANTICS))
        for path, value, _depth in _walk(metadata.model_dump(mode="json")):
            if isinstance(value, str):
                findings.extend(self._live_text_findings(value, definition.identity, path))
        return self._result(findings, approval)

    def _inspection_findings(
        self,
        definitions: tuple[MCPPrimitiveDefinition, ...],
        *,
        check_relationships: bool = True,
    ) -> list[MCPPrimitiveFinding]:
        if not definitions or len(definitions) > self._policy.max_primitives:
            return [
                self._finding(
                    MCPPrimitiveCode.LIMIT_EXCEEDED,
                    Severity.HIGH,
                    "MCP discovery returned an invalid primitive count",
                )
            ]
        findings = self._identity_findings(definitions)
        server_ids = {item.server_id.casefold() for item in definitions}
        for definition in definitions:
            findings.extend(self._definition_findings(definition, server_ids))
        if check_relationships:
            findings.extend(self._relationship_findings(definitions))
        return findings

    def _relationship_findings(
        self, definitions: tuple[MCPPrimitiveDefinition, ...]
    ) -> list[MCPPrimitiveFinding]:
        prompts = {
            (item.server_id, item.name): item
            for item in definitions
            if isinstance(item, MCPPromptDefinition)
        }
        templates = {
            (item.server_id, item.uri_template): item
            for item in definitions
            if isinstance(item, MCPResourceTemplateDefinition)
        }
        resource_uris = {
            (item.server_id, item.uri)
            for item in definitions
            if isinstance(item, MCPResourceDefinition)
        }
        findings: list[MCPPrimitiveFinding] = []
        for definition in definitions:
            valid = True
            if isinstance(definition, MCPCompletionDefinition):
                target = (
                    prompts.get((definition.server_id, definition.reference_name))
                    if definition.reference_kind == "prompt"
                    else templates.get((definition.server_id, definition.reference_name))
                )
                valid = target is not None and definition.argument_name in {
                    argument.name for argument in target.arguments
                }
            elif (
                isinstance(definition, MCPSubscriptionIdentity)
                and definition.event_type == "resource_updated"
            ):
                valid = (definition.server_id, definition.resource_uri) in resource_uris
            if not valid:
                findings.append(
                    self._finding(
                        MCPPrimitiveCode.AMBIGUOUS_SEMANTICS,
                        Severity.HIGH,
                        "MCP primitive references an absent or incompatible approved primitive",
                        identities=(definition.identity,),
                    )
                )
        return findings

    def _identity_findings(
        self, definitions: tuple[MCPPrimitiveDefinition, ...]
    ) -> list[MCPPrimitiveFinding]:
        by_identity: dict[str, list[MCPPrimitiveDefinition]] = {}
        by_skeleton: dict[tuple[MCPPrimitiveKind, str], list[MCPPrimitiveDefinition]] = {}
        for definition in definitions:
            normalized = unicodedata.normalize("NFKC", definition.name).casefold()
            by_identity.setdefault(f"{definition.kind}:{normalized}", []).append(definition)
            by_skeleton.setdefault((definition.kind, _skeleton(definition.name)), []).append(
                definition
            )
        findings: list[MCPPrimitiveFinding] = []
        for matches in by_identity.values():
            if len(matches) > 1:
                findings.append(
                    self._finding(
                        MCPPrimitiveCode.DUPLICATE_IDENTITY,
                        Severity.CRITICAL,
                        "Duplicate MCP primitive identity would create shadowing",
                        identities=tuple(item.identity for item in matches),
                    )
                )
        for matches in by_skeleton.values():
            names = {item.name.casefold() for item in matches}
            if len(matches) > 1 and len(names) > 1:
                findings.append(
                    self._finding(
                        MCPPrimitiveCode.CONFUSABLE_IDENTITY,
                        Severity.CRITICAL,
                        "Confusable MCP primitive identities are ambiguous",
                        identities=tuple(item.identity for item in matches),
                    )
                )
        return findings

    def _definition_findings(
        self, definition: MCPPrimitiveDefinition, server_ids: set[str]
    ) -> list[MCPPrimitiveFinding]:
        payload = definition.canonical_payload
        findings: list[MCPPrimitiveFinding] = []
        suspicious: set[str] = set()
        smuggling: set[str] = set()
        cross_server: set[str] = set()
        nodes = 0
        chars = 0
        for path, value, depth in _walk(payload):
            nodes += 1
            if depth > self._policy.max_depth:
                findings.append(
                    self._use_mismatch(definition, MCPPrimitiveCode.LIMIT_EXCEEDED, path)
                )
                break
            if not isinstance(value, str):
                continue
            chars += len(value)
            normalized = unicodedata.normalize("NFKC", value[:16_384])
            if any(pattern.search(normalized) for pattern in _INSTRUCTION_PATTERNS):
                suspicious.add(path)
            if _unicode_smuggling(value):
                smuggling.add(path)
            if self._policy.reject_cross_server_references:
                folded = normalized.casefold()
                others = server_ids - {definition.server_id.casefold()}
                if any(server_id in folded for server_id in others):
                    cross_server.add(path)
        if (
            nodes > self._policy.max_nodes_per_primitive
            or chars > self._policy.max_total_string_chars
        ):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.LIMIT_EXCEEDED))
        if suspicious:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.HIDDEN_INSTRUCTION,
                    Severity.CRITICAL,
                    "MCP primitive metadata contains a model-directed instruction",
                    identities=(definition.identity,),
                    field_paths=tuple(sorted(suspicious)),
                )
            )
        if smuggling:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.UNICODE_SMUGGLING,
                    Severity.CRITICAL,
                    "MCP primitive metadata contains hidden Unicode controls",
                    identities=(definition.identity,),
                    field_paths=tuple(sorted(smuggling)),
                )
            )
        if cross_server:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.CROSS_SERVER_REFERENCE,
                    Severity.CRITICAL,
                    "MCP primitive metadata references another server",
                    identities=(definition.identity,),
                    field_paths=tuple(sorted(cross_server)),
                )
            )
        findings.extend(self._semantic_findings(definition))
        return findings

    def _semantic_findings(self, definition: MCPPrimitiveDefinition) -> list[MCPPrimitiveFinding]:
        paths: set[str] = set()
        uris: list[tuple[str, str, bool, frozenset[str]]] = []
        for index, icon in enumerate(definition.icons):
            uris.append((f"/icons/{index}/src", icon.src, False, self._policy.allowed_icon_schemes))
            if icon.mime_type is not None and not _MIME_RE.fullmatch(icon.mime_type.casefold()):
                paths.add(f"/icons/{index}/mime_type")
        if isinstance(definition, MCPResourceDefinition):
            uris.append(("/uri", definition.uri, False, self._policy.allowed_uri_schemes))
            self._inspect_media_schema(definition.mime_type, definition.content_schema, paths)
        elif isinstance(definition, MCPResourceTemplateDefinition):
            uris.append(
                ("/uriTemplate", definition.uri_template, True, self._policy.allowed_uri_schemes)
            )
            variables = set(_TEMPLATE_VARIABLE_RE.findall(definition.uri_template))
            arguments = {argument.name for argument in definition.arguments}
            if (
                variables != arguments
                or definition.uri_template.count("{") != len(variables)
                or definition.uri_template.count("}") != len(variables)
            ):
                paths.add("/uriTemplate")
            self._inspect_media_schema(definition.mime_type, definition.content_schema, paths)
        elif isinstance(definition, MCPSubscriptionIdentity) and definition.resource_uri:
            uris.append(
                ("/resource_uri", definition.resource_uri, False, self._policy.allowed_uri_schemes)
            )
        elif isinstance(definition, MCPCompletionDefinition):
            if definition.reference_kind == "resource_template":
                uris.append(
                    (
                        "/reference_name",
                        definition.reference_name,
                        True,
                        self._policy.allowed_uri_schemes,
                    )
                )
        dangerous = [
            path
            for path, uri, template, schemes in uris
            if _is_dangerous_uri(uri, schemes, template=template)
        ]
        findings: list[MCPPrimitiveFinding] = []
        if dangerous:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.DANGEROUS_URI,
                    Severity.CRITICAL,
                    "MCP primitive contains an unsafe or disallowed URI",
                    identities=(definition.identity,),
                    field_paths=tuple(dangerous),
                )
            )
        cross_server_uris = [
            path
            for path, uri, template, _schemes in uris
            if _is_cross_server_uri(uri, definition.server_id, template=template)
        ]
        if cross_server_uris:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.CROSS_SERVER_REFERENCE,
                    Severity.CRITICAL,
                    "MCP primitive URI refers to another server identity",
                    identities=(definition.identity,),
                    field_paths=tuple(cross_server_uris),
                )
            )
        if paths:
            findings.append(
                self._finding(
                    MCPPrimitiveCode.AMBIGUOUS_SEMANTICS,
                    Severity.HIGH,
                    "MCP primitive has an ambiguous media, schema, or argument contract",
                    identities=(definition.identity,),
                    field_paths=tuple(sorted(paths)),
                )
            )
        return findings

    def _inspect_media_schema(
        self, mime_type: str, schema: dict[str, JsonValue] | None, paths: set[str]
    ) -> None:
        folded = mime_type.casefold()
        if not _MIME_RE.fullmatch(folded) or folded not in self._policy.allowed_mime_types:
            paths.add("/mimeType")
        if schema is not None:
            if folded != "application/json" or schema.get("type") not in {
                "object",
                "array",
                "string",
                "number",
                "integer",
                "boolean",
                "null",
            }:
                paths.add("/contentSchema/type")
            self._inspect_content_schema(schema, "/contentSchema", paths)

    def _inspect_content_schema(
        self, schema: dict[str, JsonValue], path: str, paths: set[str]
    ) -> None:
        schema_type = schema.get("type")
        allowed_types = {"object", "array", "string", "number", "integer", "boolean", "null"}
        if schema_type not in allowed_types:
            paths.add(f"{path}/type")
            return
        if schema_type == "object":
            properties = schema.get("properties")
            if not isinstance(properties, dict):
                paths.add(f"{path}/properties")
            else:
                for name, child in properties.items():
                    child_path = f"{path}/properties/{name}"
                    if not isinstance(child, dict):
                        paths.add(child_path)
                    else:
                        self._inspect_content_schema(child, child_path, paths)
                required = schema.get("required", [])
                if not isinstance(required, list) or any(
                    not isinstance(name, str) or name not in properties for name in required
                ):
                    paths.add(f"{path}/required")
            if (
                self._policy.require_closed_content_schemas
                and schema.get("additionalProperties") is not False
            ):
                paths.add(f"{path}/additionalProperties")
        elif schema_type == "array":
            items = schema.get("items")
            if not isinstance(items, dict):
                paths.add(f"{path}/items")
            else:
                self._inspect_content_schema(items, f"{path}/items", paths)

    def _render_uri(
        self, definition: MCPResourceTemplateDefinition, values: dict[str, str]
    ) -> tuple[str | None, list[MCPPrimitiveFinding]]:
        arguments = {argument.name: argument for argument in definition.arguments}
        if set(values) != set(arguments):
            return None, [self._use_mismatch(definition, MCPPrimitiveCode.SCHEMA_MISMATCH)]
        rendered = definition.uri_template
        for name, argument in arguments.items():
            value = values[name]
            if len(value) > argument.max_length or re.fullmatch(argument.pattern, value) is None:
                return None, [self._use_mismatch(definition, MCPPrimitiveCode.SCHEMA_MISMATCH)]
            rendered = rendered.replace(f"{{{name}}}", quote(value, safe="-._~"))
        if _is_dangerous_uri(rendered, self._policy.allowed_uri_schemes):
            return None, [self._use_mismatch(definition, MCPPrimitiveCode.DANGEROUS_URI)]
        return rendered, []

    def _subscription_findings(
        self,
        definition: MCPResourceDefinition | MCPResourceTemplateDefinition,
        content: MCPResourceContent,
        approval: MCPPrimitiveSnapshot,
        subscription: MCPSubscriptionIdentity | None,
    ) -> list[MCPPrimitiveFinding]:
        if subscription is None or content.subscription_id != subscription.subscription_id:
            return [self._use_mismatch(definition, MCPPrimitiveCode.SUBSCRIPTION_MISMATCH)]
        pin = self.verify_use(subscription, approval)
        if not pin.is_allowed:
            return list(pin.findings)
        if (
            subscription.server_id != content.server_id
            or subscription.event_type != "resource_updated"
            or subscription.resource_uri != content.uri
            or subscription.provenance_id != content.provenance_id
            or not subscription.required_scopes.issubset(content.granted_scopes)
        ):
            return [self._use_mismatch(subscription, MCPPrimitiveCode.SUBSCRIPTION_MISMATCH)]
        return []

    def _provenance_scope_findings(
        self,
        definition: MCPPrimitiveDefinition,
        provenance_id: str,
        granted_scopes: frozenset[str],
    ) -> list[MCPPrimitiveFinding]:
        findings = []
        if provenance_id != definition.provenance_id:
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.PROVENANCE_MISMATCH))
        if not definition.required_scopes.issubset(granted_scopes):
            findings.append(self._use_mismatch(definition, MCPPrimitiveCode.AUTHORIZATION_MISSING))
        return findings

    def _live_text_findings(
        self, value: str | bytes, identity: str, path: str
    ) -> list[MCPPrimitiveFinding]:
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                return [self._schema_finding(identity)]
        normalized = unicodedata.normalize("NFKC", value[: self._policy.max_total_string_chars])
        findings = []
        if any(pattern.search(normalized) for pattern in _INSTRUCTION_PATTERNS):
            findings.append(
                self._finding(
                    MCPPrimitiveCode.HIDDEN_INSTRUCTION,
                    Severity.CRITICAL,
                    "Live MCP content contains a model-directed instruction",
                    identities=(identity,),
                    field_paths=(path,),
                )
            )
        if _unicode_smuggling(value):
            findings.append(
                self._finding(
                    MCPPrimitiveCode.UNICODE_SMUGGLING,
                    Severity.CRITICAL,
                    "Live MCP content contains hidden Unicode controls",
                    identities=(identity,),
                    field_paths=(path,),
                )
            )
        return findings

    def _content_schema_findings(
        self, schema: dict[str, JsonValue], data: str | bytes, identity: str
    ) -> list[MCPPrimitiveFinding]:
        try:
            text = data.decode("utf-8") if isinstance(data, bytes) else data
            value: JsonValue = json.loads(
                text,
                parse_constant=lambda constant: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON number: {constant}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            return [self._schema_finding(identity)]
        if not self._matches_schema(value, schema):
            return [self._schema_finding(identity)]
        return []

    def _matches_schema(self, value: JsonValue, schema: dict[str, JsonValue]) -> bool:
        expected = schema.get("type")
        if expected == "object":
            if not isinstance(value, dict):
                return False
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            if not isinstance(properties, dict) or not isinstance(required, list):
                return False
            if any(not isinstance(item, str) or item not in value for item in required):
                return False
            if schema.get("additionalProperties") is False and not set(value).issubset(properties):
                return False
            for key, item in value.items():
                property_schema = properties.get(key)
                if property_schema is not None and (
                    not isinstance(property_schema, dict)
                    or not self._matches_schema(item, property_schema)
                ):
                    return False
            return True
        if expected == "array":
            items = schema.get("items")
            return isinstance(value, list) and (
                not isinstance(items, dict)
                or all(self._matches_schema(item, items) for item in value)
            )
        if expected == "string":
            max_length = schema.get("maxLength")
            return isinstance(value, str) and (
                not isinstance(max_length, int) or len(value) <= max_length
            )
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "null":
            return value is None
        return expected is None

    def _schema_finding(self, identity: str) -> MCPPrimitiveFinding:
        return self._finding(
            MCPPrimitiveCode.SCHEMA_MISMATCH,
            Severity.HIGH,
            "Fetched MCP resource does not match its approved content schema",
            identities=(identity,),
        )

    def _build_snapshot(
        self,
        definitions: tuple[MCPPrimitiveDefinition, ...],
        phase: MCPPrimitivePhase,
        approved_by: str | None,
        now: datetime | None,
    ) -> MCPPrimitiveSnapshot:
        unsigned = MCPPrimitiveSnapshot(
            phase=phase,
            fingerprints=tuple(
                sorted(
                    (fingerprint_primitive(item) for item in definitions),
                    key=lambda item: item.identity,
                )
            ),
            issued_at=now or datetime.now(tz=UTC),
            approved_by=approved_by,
            signature="0" * 64,
        )
        return unsigned.model_copy(update={"signature": self._signature(unsigned)})

    def _signature(self, snapshot: MCPPrimitiveSnapshot) -> str:
        encoded = json.dumps(
            snapshot_signing_payload(snapshot),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    def _signature_matches(self, snapshot: MCPPrimitiveSnapshot) -> bool:
        return hmac.compare_digest(snapshot.signature, self._signature(snapshot))

    def _snapshot_findings(
        self,
        definitions: tuple[MCPPrimitiveDefinition, ...],
        snapshot: MCPPrimitiveSnapshot,
        *,
        expected_phase: MCPPrimitivePhase,
        mismatch_code: MCPPrimitiveCode,
    ) -> list[MCPPrimitiveFinding]:
        if snapshot.phase != expected_phase or not self._signature_matches(snapshot):
            return [
                self._finding(
                    MCPPrimitiveCode.PIN_INVALID,
                    Severity.CRITICAL,
                    "MCP primitive snapshot has an invalid phase or signature",
                )
            ]
        expected = {item.identity: item for item in snapshot.fingerprints}
        observed = {item.identity: fingerprint_primitive(item) for item in definitions}
        findings = []
        for identity in sorted(set(expected) | set(observed)):
            before = expected.get(identity)
            after = observed.get(identity)
            if before is None or after is None:
                findings.append(
                    self._finding(
                        mismatch_code,
                        Severity.CRITICAL,
                        "MCP primitive set changed after discovery",
                        identities=(identity,),
                    )
                )
            elif before.definition_digest != after.definition_digest:
                findings.append(
                    self._mutation_finding(
                        before, after, mismatch_code, "MCP primitive changed after discovery"
                    )
                )
        return findings

    def _mutation_finding(
        self,
        before: MCPPrimitiveFingerprint,
        after: MCPPrimitiveFingerprint,
        code: MCPPrimitiveCode,
        message: str,
    ) -> MCPPrimitiveFinding:
        changes = []
        for path in sorted(set(before.field_digests) | set(after.field_digests)):
            previous_digest = before.field_digests.get(path)
            current_digest = after.field_digests.get(path)
            if previous_digest == current_digest:
                continue
            kind = (
                MCPDefinitionChangeKind.ADDED
                if previous_digest is None
                else MCPDefinitionChangeKind.REMOVED
                if current_digest is None
                else MCPDefinitionChangeKind.CHANGED
            )
            changes.append(
                MCPDefinitionChange(
                    path=_safe_path(path),
                    kind=kind,
                    previous_digest=previous_digest,
                    current_digest=current_digest,
                )
            )
        return self._finding(
            code,
            Severity.CRITICAL,
            message,
            identities=(after.identity,),
            field_paths=tuple(change.path for change in changes),
            changes=tuple(changes),
        )

    def _use_mismatch(
        self,
        definition: MCPPrimitiveDefinition,
        code: MCPPrimitiveCode,
        path: str | None = None,
    ) -> MCPPrimitiveFinding:
        return self._finding(
            code,
            Severity.CRITICAL if code != MCPPrimitiveCode.LIMIT_EXCEEDED else Severity.HIGH,
            "Live MCP primitive content violates its approved contract",
            identities=(definition.identity,),
            field_paths=(path,) if path else (),
        )

    def _single(
        self, action: GuardAction, code: MCPPrimitiveCode, message: str, identity: str
    ) -> MCPPrimitiveResult:
        return MCPPrimitiveResult(
            action=action,
            findings=(self._finding(code, Severity.CRITICAL, message, identities=(identity,)),),
        )

    @staticmethod
    def _result(
        findings: list[MCPPrimitiveFinding], approval: MCPPrimitiveSnapshot
    ) -> MCPPrimitiveResult:
        return MCPPrimitiveResult(
            action=GuardAction.BLOCK if findings else GuardAction.ALLOW,
            findings=tuple(findings),
            snapshot=approval if not findings else None,
        )

    @staticmethod
    def _finding(
        code: MCPPrimitiveCode,
        severity: Severity,
        message: str,
        *,
        identities: tuple[str, ...] = (),
        field_paths: tuple[str, ...] = (),
        changes: tuple[MCPDefinitionChange, ...] = (),
    ) -> MCPPrimitiveFinding:
        return MCPPrimitiveFinding(
            code=code,
            severity=severity,
            message=message,
            identities=tuple(_safe_reference(item) for item in identities),
            field_paths=tuple(_safe_path(path) for path in field_paths),
            changes=changes,
        )
