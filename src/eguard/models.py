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


class ColumnDef(BaseModel):
    """One column of a CREATE TABLE in the dump (type text as pg_dump printed it)."""

    name: str
    type: str
    not_null: bool = False


class TableDef(BaseModel):
    name: str  # qualified, as written in the dump (e.g. public.transactions)
    columns: list[ColumnDef]
    line: int
    has_data: bool = True  # False for a partitioned parent (its rows live in the partitions)
    primary_key: list[str] | None = None  # declared post-data by ALTER TABLE ... PRIMARY KEY


class CopyBlock(BaseModel):
    """One `COPY ... FROM stdin;` data block and what the stream showed of it."""

    table: str
    columns: list[str]
    header_line: int
    rows: int = 0
    bytes: int = 0  # row bytes including their newlines
    first_row_line: int | None = None
    last_row_line: int | None = None
    closed: bool = False
    end_line: int | None = None  # line of the `\.` terminator


class DumpStructure(BaseModel):
    """Everything the pg plain-dump state machine learned; L2 turns this into checks."""

    state: str  # PREAMBLE, BODY, COPY_ROWS, COMPLETE
    header_line: int | None = None
    dumped_from: str | None = None
    dumped_by: str | None = None
    restrict_key: str | None = None
    unrestrict_key: str | None = None
    tables: dict[str, TableDef] = Field(default_factory=dict)
    copies: list[CopyBlock] = Field(default_factory=list)
    bad_copy_headers: list[dict[str, Any]] = Field(default_factory=list)
    stray_terminators: list[int] = Field(default_factory=list)
    complete_line: int | None = None
    after_complete: list[dict[str, Any]] = Field(default_factory=list)  # first few lines only
    after_complete_count: int = 0
    lines: int = 0
    last_line: str | None = None  # last decompressed line (truncated) for evidence
    partial_line_bytes: int = 0  # unterminated final line; inside COPY it is a partial row
    open_statement: str | None = None  # stream ended inside a SQL statement (truncated text)


class ChunkFingerprint(BaseModel):
    """`chunk_rows` consecutive rows of one COPY block, in stream order (IMPLEMENTATION_PLAN §4)."""

    index: int  # 1-based
    first_row: int  # 1-based row position within the COPY block
    last_row: int
    first_line: int  # dump line numbers of those rows
    last_line: int
    digest: str  # hex blake2b-128 over the rows' 8-byte hashes


class TableFingerprint(BaseModel):
    """One COPY block. 64-bit values are 16-char hex so JSON never carries numbers above 2**53."""

    table: str
    count: int
    sum64: str  # sum of row hashes mod 2**64
    xor64: str  # xor of row hashes
    root: str  # hex blake2b-128 over the chunk digests
    closed: bool  # the block ended with `\.`
    chunks: list[ChunkFingerprint]


class StreamDigestInfo(BaseModel):
    """The whole decompressed stream (DDL and markers included, unlike the row fingerprints)."""

    bytes: int
    lines: int
    sha256: str


class Manifest(BaseModel):
    """What the exporter emitted, recorded from the same stream (IMPLEMENTATION_PLAN §7).

    Only str/int/bool/list fields, so the canonical JSON that the HMAC signs survives a round trip.
    """

    format_version: int
    tool: str
    created_at: str  # ISO 8601 UTC
    algorithms: dict[str, str]
    chunk_rows: int = Field(gt=0)
    stream: StreamDigestInfo
    dumped_by: str | None
    dump_complete: bool  # completion marker seen and every COPY block closed
    tables: list[TableFingerprint]
    signature: str | None = None  # hex HMAC-SHA256 over the canonical JSON of all other fields
