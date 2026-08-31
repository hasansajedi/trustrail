"""Typed registration controls for async rules and external providers."""

from __future__ import annotations

import math
import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Generic, TypeVar

from trustrail.models.enums import FailMode, GuardAction, GuardStage
from trustrail.protocols import AsyncGuardRule

ProviderT = TypeVar("ProviderT", covariant=True)

_CHECK_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$")


def _validate_registration(
    check_id: str,
    timeout_seconds: float | None,
    stages: Collection[GuardStage] | None,
) -> frozenset[GuardStage] | None:
    if not isinstance(check_id, str):
        raise TypeError("async check ID must be a string")
    if not _CHECK_ID_PATTERN.fullmatch(check_id):
        raise ValueError(
            "async check ID must be 1-128 characters containing only letters, numbers, ':', "
            "'_', '.', or '-'"
        )
    if timeout_seconds is not None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise TypeError("async check timeout_seconds must be a number")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("async check timeout_seconds must be positive and finite")
    if stages is None:
        return None
    normalized = frozenset(stages)
    if not normalized:
        raise ValueError("async check stages must not be empty")
    if any(not isinstance(stage, GuardStage) for stage in normalized):
        raise TypeError("async check stages must contain GuardStage values")
    return normalized


@dataclass(frozen=True)
class AsyncRuleRegistration:
    """Configure one async rule without coupling it to global Guard settings."""

    rule: AsyncGuardRule
    timeout_seconds: float | None = None
    fail_mode: FailMode | None = None
    stages: Collection[GuardStage] | None = None

    def __post_init__(self) -> None:
        rule_id = self.rule.id
        normalized = _validate_registration(rule_id, self.timeout_seconds, self.stages)
        object.__setattr__(self, "stages", normalized)
        if self.fail_mode is not None:
            object.__setattr__(self, "fail_mode", FailMode(self.fail_mode))


@dataclass(frozen=True)
class ProviderRegistration(Generic[ProviderT]):
    """Configure one external provider and its execution policy."""

    provider_id: str
    provider: ProviderT
    timeout_seconds: float | None = None
    fail_mode: FailMode | None = None
    stages: Collection[GuardStage] | None = None
    action: GuardAction | None = None

    def __post_init__(self) -> None:
        normalized = _validate_registration(
            self.provider_id,
            self.timeout_seconds,
            self.stages,
        )
        object.__setattr__(self, "stages", normalized)
        if self.fail_mode is not None:
            object.__setattr__(self, "fail_mode", FailMode(self.fail_mode))
        if self.action is not None:
            object.__setattr__(self, "action", GuardAction(self.action))
