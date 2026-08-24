"""Models for application-defined sensitive data boundaries."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ProtectedData(BaseModel):
    """A private value that must not be reproduced by generated output.

    The value is deliberately omitted from repr and serialization so it cannot
    be copied into structured logs or error payloads by accident.
    """

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, exclude=True, repr=False)
    min_match_chars: int = Field(default=20, ge=8, le=1_000)
    case_sensitive: bool = False
