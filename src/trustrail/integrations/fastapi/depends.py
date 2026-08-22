"""FastAPI dependency injection for trustrail."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trustrail.guard import Guard


_default_guard: Guard | None = None


def configure_guard(guard: Guard) -> None:
    """Set the default guard instance for dependency injection."""
    global _default_guard
    _default_guard = guard


def get_guard() -> Guard:
    """FastAPI dependency that returns the configured Guard instance."""
    if _default_guard is None:
        from trustrail.guard import Guard

        return Guard.default()
    return _default_guard
