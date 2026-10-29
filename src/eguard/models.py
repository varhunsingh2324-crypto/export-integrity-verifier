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


class StreamError(BaseModel):
    """Where and why a decoder stopped before a clean end of stream."""

    # bad_magic, bad_method, reserved_flags, header_crc, bad_maxbits, unexpected_eof,
    # inflate_error, decoder_failed, empty_file
    kind: str
    offset: int  # compressed byte offset at which the problem was detected
    detail: str


class GzipMember(BaseModel):
    """Header and trailer of one gzip member (RFC 1952), as parsed by hand."""

    offset: int
    flags: int
    mtime: int
    xfl: int
    os: int
    fname: str | None = None
    comment: str | None = None
    extra_bytes: int = 0
    header_crc_ok: bool | None = None  # None: FHCRC not present
    crc_expected: int | None = None  # None: trailer never reached
    crc_actual: int = 0
    isize_expected: int | None = None
    bytes_out: int = 0
    compressed_bytes: int = 0


class ContainerInfo(BaseModel):
    """Everything the decoder learned about the container; L1 turns this into checks."""

    format: str  # gzip, compress, unknown
    compressed_bytes: int
    bytes_out: int = 0
    members: list[GzipMember] = Field(default_factory=list)
    error: StreamError | None = None
    trailing_bytes: int = 0
    trailing_offset: int | None = None
    trailing_all_zero: bool | None = None
    compress_maxbits: int | None = None
    compress_block_mode: bool | None = None
    decoder_exit: int | None = None
    decoder_stderr: str | None = None


class VerifyReport(BaseModel):
    path: str
    verdict: Verdict
    ral: int = Field(ge=0, le=5)
    checks: list[CheckResult]


class StreamEnd(BaseModel):
    """What every fan-out consumer is told when the decompressed stream stops."""

    clean: bool  # False: the decoder stopped on an error (see ContainerInfo.error)
    bytes_out: int
    lines: int
    unterminated_tail: bool  # the last line delivered had no trailing newline
