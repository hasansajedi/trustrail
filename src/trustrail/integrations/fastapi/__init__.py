"""FastAPI integration for trustrail."""

from trustrail.integrations.fastapi.depends import get_guard
from trustrail.integrations.fastapi.middleware import AegisRailMiddleware

__all__ = ["AegisRailMiddleware", "get_guard"]
