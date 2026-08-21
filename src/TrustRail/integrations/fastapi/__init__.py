"""FastAPI integration for aiRail."""

from aiRail.integrations.fastapi.depends import get_guard
from aiRail.integrations.fastapi.middleware import AegisRailMiddleware

__all__ = ["AegisRailMiddleware", "get_guard"]
