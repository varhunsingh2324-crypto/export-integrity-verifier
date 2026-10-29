"""Core result models shared by every integrity layer."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Verdict(StrEnum):
    VERIFIED = "VERIFIED"
    SUSPECT = "SUSPECT"
    CORRUPT = "CORRUPT"
    TOOL_ERROR = "TOOL_ERROR"

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self]


_EXIT_CODES: dict[Verdict, int] = {
    Verdict.VERIFIED: 0,
    Verdict.SUSPECT: 1,
    Verdict.CORRUPT: 2,
    Verdict.TOOL_ERROR: 3,
}


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    WARN = "WARN"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    INFO = "INFO"


class CheckResult(BaseModel):
    """One check's outcome. Always carries evidence and a human message, never a bare bool."""

    layer: int = Field(ge=1, le=5)
    name: str = Field(min_length=1)
    status: Status
    severity: Severity
    evidence: dict[str, Any]
    message: str

    @field_validator("message")
    @classmethod
    def _message_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must explain the result")
        return value
