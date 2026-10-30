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


class LayerResult(BaseModel):
    """One layer's checks folded into a single status (verdict.layer_results)."""

    layer: int = Field(ge=1, le=5)
    name: str  # container, structure, rows, reconciliation, restore drill
    status: Status  # FAIL > WARN (incl. PASS+SKIP mixed) > SKIP (nothing ran) > PASS
    full_evidence: bool  # every check PASSed: the layer counts toward the RAL
    checks: int
    reason: str


class VerifyReport(BaseModel):
    path: str
    tool: str = ""  # eguard version that produced the report
    generated_at: str = ""  # ISO 8601 UTC
    manifest: str | None = None  # manifest path the export was reconciled against
    verdict: Verdict
    ral: int = Field(ge=0, le=5)
    exit_code: int = 0  # rule 7
    layers: list[LayerResult] = Field(default_factory=list)
    checks: list[CheckResult]
    reasons: list[str] = Field(default_factory=list)  # why not VERIFIED (verdict.explain)


class Location(BaseModel):
    """Where in the stream a non-PASS check found its problem (report/view.locations)."""

    layer: int = Field(ge=1, le=5)
    check: str
    table: str | None = None
    rows: tuple[int, int] | None = None  # 1-based row positions within the table's COPY block
    lines: tuple[int, int] | None = None  # decompressed dump line numbers
    chunk: tuple[int, int] | None = None  # (k, of n) fingerprint chunk
    byte_offset: int | None = None  # compressed byte offset (container problems)
    detail: str


class Provenance(BaseModel):
    """Who made the export and what it is anchored to; None = not recorded in the evidence."""

    compressor: str | None = None  # from the container bytes
    level_hint: str | None = None
    manifest_compressor: str | None = None  # what the exporter says it ran, e.g. "pigz -6"
    pg_dump: str | None = None
    dumped_from: str | None = None
    snapshot_id: str | None = None
    snapshot_taken_at: str | None = None
    manifest: str | None = None
    manifest_status: str  # signed and valid / invalid ... / no manifest
    manifest_created_at: str | None = None
    l5_seed: int | None = None
    tool: str


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
    ddl: str | None = None  # the CREATE TABLE statement as written; None if it was cut (too long)


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


class SnapshotInfo(BaseModel):
    """The REPEATABLE READ snapshot pg_dump ran in, and count(*) per table taken in it."""

    id: str  # pg_export_snapshot()
    isolation: str
    taken_at: str  # now() of the snapshot transaction
    counts: dict[str, int]  # qualified table -> count(*), named as pg_dump writes COPY headers


class CompressedInfo(BaseModel):
    """The compressed file as the exporter wrote it."""

    format: str  # from the magic bytes
    compressor: str
    bytes: int
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
    # Added by `eguard manifest-seal` once the export finished (hardened export). Left out of the
    # signed JSON when None, so manifests made before these fields existed still verify.
    snapshot: SnapshotInfo | None = None
    compressed: CompressedInfo | None = None
    signature: str | None = None  # hex HMAC-SHA256 over the canonical JSON of all other fields


class DrillTable(BaseModel):
    """One sampled COPY block restored into the scratch schema (L5)."""

    table: str  # as named in the dump
    scratch_table: str
    seen: int  # rows of the block in the stream
    sampled: int
    # ok, empty, no_ddl (no CREATE TABLE in the dump), ddl_refused (not a single plain
    # statement, never executed), ddl_error (PostgreSQL rejected it in isolation)
    status: str = "ok"
    detail: str | None = None
    restored: int = 0
    rejected_count: int = 0
    rejected: list[dict[str, Any]] = Field(default_factory=list)  # first few: line, error
    pk_error: str | None = None
    round_tripped: int = 0
    mismatched_count: int = 0
    mismatched: list[dict[str, Any]] = Field(default_factory=list)  # first few: line, columns
    scratch_bytes: int = 0
    # Dump lines of the rows that restored and came back byte-identical (for the source check).
    clean_lines: list[int] = Field(default_factory=list, exclude=True)


class DrillResult(BaseModel):
    schema_name: str
    tables: list[DrillTable] = Field(default_factory=list)
    stale_dropped: list[str] = Field(default_factory=list)
    scratch_bytes: int = 0
    dropped: bool = False  # confirmed absent from pg_namespace after the drop
    seconds: float = 0.0


class SourceTable(BaseModel):
    """Sampled rows vs the live source table, by primary key (L5 --dsn)."""

    table: str
    status: str = "ok"  # ok, no_table, no_pk, error
    detail: str | None = None
    primary_key: list[str] = Field(default_factory=list)
    compared: int = 0
    matched: int = 0
    drift_changed: int = 0
    drift_deleted: int = 0
    excluded: int = 0  # sampled rows not compared: they failed restore or the round trip
    examples: list[dict[str, Any]] = Field(default_factory=list)


# -- size forensics (`eguard explain`, IMPLEMENTATION_PLAN §5) -------------------------------------


class ColumnProfile(BaseModel):
    """One column of one table, over the rows whose field count matched the COPY header."""

    column: str
    rows: int
    bytes: int  # field bytes as written in the dump (COPY text, `\N` included), no delimiters
    value_bytes: int  # bytes of non-NULL values only (what the entropy is measured over)
    nulls: int
    null_fraction: float
    avg_width: float  # bytes / rows
    distinct_hll: int  # HyperLogLog estimate of distinct non-NULL values
    entropy_bits: float | None  # Shannon, bits per byte of the non-NULL values; None if empty


class TableProfile(BaseModel):
    table: str
    rows: int  # parsed rows
    unparsed_rows: int  # field count differs from the COPY header (bytes go to unparsed_bytes)
    unparsed_bytes: int
    raw_bytes: int  # every row line of the table's COPY block(s), newlines included
    fixed_level_bytes: int  # those row bytes deflated on their own at policy explain.level
    fixed_ratio: float | None
    entropy_bits: float | None
    columns: list[ColumnProfile]


class FileProfile(BaseModel):
    """One export, profiled in one streaming pass. The four byte components sum exactly to
    decompressed_bytes: field + delimiter + unparsed + other."""

    path: str
    format: str  # from the magic bytes
    compressor: str
    level_hint: str | None
    xfl: int | None  # gzip XFL of the first member
    compress_maxbits: int | None
    members: int
    container_error: str | None
    compressed_bytes: int
    decompressed_bytes: int
    lines: int
    rows: int  # every row line in COPY blocks, parsed or not
    field_bytes: int
    delimiter_bytes: int  # tabs between fields + the newline of each parsed row
    unparsed_bytes: int
    other_bytes: int  # non-row stream bytes: header, DDL, COPY headers, `\.`, markers
    fixed_level_bytes: int  # Σ per-table sections + the non-row bytes, each deflated at the level
    entropy_bits: float | None  # whole decompressed stream
    tables: list[TableProfile]
    seconds: float


class Factor(BaseModel):
    """One factor of S = R × W ÷ C. A step's size effect is exp(effect_ln) - 1; C itself is shown
    for reference and is split into the `data` and `compressor` steps (C = C_fixed × E)."""

    name: str  # rows, width, data, compressor, ratio
    label: str
    old: float
    new: float
    change: float  # new / old - 1
    effect_ln: float | None  # signed contribution to ln(S_new / S_old); None: not a step
    size_effect: float | None


class Decomposition(BaseModel):
    factors: list[Factor]
    observed_ratio: float  # S_new / S_old
    observed_change: float
    product: float  # exp(Σ effect_ln): the waterfall multiplied back
    identity_error: float  # product / observed_ratio - 1 (|.| <= policy identity_tolerance)


class ProbeResult(BaseModel):
    """Equal-size samples of both decompressed streams, deflated with the same level."""

    compressor: str
    level: int
    seed: int
    block_bytes: int
    blocks: int  # per file, after the larger reservoir was downsampled to the same count
    sample_bytes: int  # per file, equal
    old_ratio: float | None
    new_ratio: float | None
    probe_change: float | None
    observed_change: float  # C_new / C_old - 1 of the files themselves
    ratio_unchanged: float  # policy: below this observed change there is no gap to attribute
    data_share: float | None  # ln(probe ratio change) / ln(observed ratio change)
    hypothesis: str  # H1, H2/H3, mixed, none


class ColumnDelta(BaseModel):
    """A component of the row width W, old vs new. Widths are bytes per row of the whole file,
    so Σ delta_width over every component equals ΔW exactly."""

    table: str | None  # None for the non-column components
    column: str  # column name, or (delimiters), (unparsed rows), (non-row bytes)
    present: str  # both, old, new
    old_width: float
    new_width: float
    delta_width: float
    old_avg_width: float | None  # bytes per value within the table
    new_avg_width: float | None
    old_null_fraction: float | None
    new_null_fraction: float | None
    old_distinct: int | None
    new_distinct: int | None
    old_entropy: float | None
    new_entropy: float | None
    delta_entropy: float | None
    old_bits_per_row: float | None  # entropy × value bytes ÷ file rows (order-0 information)
    new_bits_per_row: float | None
    delta_bits: float | None
    rank_width: int  # 1 = largest |delta_width|
    rank_bits: int | None  # 1 = largest |delta_bits|


class IntegrityRef(BaseModel):
    """A saved `verify` report for the same file, reused as-is (explain issues no verdict)."""

    status: str  # found, stale (sizes differ from this pass), none
    report: str | None = None
    verdict: Verdict | None = None
    ral: int | None = None
    failed_layers: list[int] = Field(default_factory=list)
    incomplete_layers: list[int] = Field(default_factory=list)  # WARN / SKIP
    generated_at: str | None = None
    detail: str


class ExplainReport(BaseModel):
    tool: str
    generated_at: str
    old: FileProfile
    new: FileProfile
    decomposition: Decomposition
    probe: ProbeResult
    hypothesis: str  # the probe's attribution of the compression-ratio change
    columns: list[ColumnDelta]
    integrity_old: IntegrityRef
    integrity_new: IntegrityRef
    narrative: list[str]
