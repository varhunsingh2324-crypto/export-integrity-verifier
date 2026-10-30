"""Streaming benchmark (phase 2, extended in phase 3): is `eguard verify` memory flat as the input
grows? Since phase 3 the measured pass includes L2 (dump grammar) and L3 (every row + PK tracking).

Runs `eguard verify --json` on v1.sql.gz and on a ≥ 1 GB multi-member gzip made by concatenating
copies of v1 (a valid gzip file: `cat a.gz b.gz` decodes to the concatenated content). The big
file is built by streamed copy; nothing is ever decompressed to disk. Peak RSS comes from wait4()
for that one child; VmRSS is also sampled from /proc every 0.25 s to show the curve is flat, not
just the peak.
Results are appended to bench/results.md (rule 5: only measured numbers in docs). The big
file is deleted as soon as it has been measured (CONTRIBUTING.md rule 10: disk budget).
"""

import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "data" / "exports" / "v1.sql.gz"
BIG = ROOT / "data" / "bench" / "v1x7.sql.gz"
COPIES = 7
EGUARD = Path(sys.executable).with_name("eguard")
RESULTS = ROOT / "bench" / "results.md"
SAMPLE_S = 0.25
WARMUP_S = 1.0
MIB = 1 << 20


def build_big() -> Path:
    BIG.parent.mkdir(parents=True, exist_ok=True)
    with BIG.open("wb") as out:
        for _ in range(COPIES):
            with V1.open("rb") as src:
                shutil.copyfileobj(src, out, MIB)
    return BIG


def _vmrss_kib(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return None
    return None


def measure(path: Path, extra_args: tuple[str, ...] = ()) -> dict:
    samples: list[tuple[float, int]] = []
    with tempfile.TemporaryFile() as out:
        start = time.perf_counter()
        proc = subprocess.Popen(
            [str(EGUARD), "verify", "--json", str(path), *extra_args], stdout=out
        )
        done = threading.Event()

        def sample() -> None:
            while not done.is_set():
                if (rss := _vmrss_kib(proc.pid)) is not None:
                    samples.append((time.perf_counter() - start, rss))
                done.wait(SAMPLE_S)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        _, status, usage = os.wait4(proc.pid, 0)
        wall = time.perf_counter() - start
        done.set()
        sampler.join()
        proc.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0)
        report = json.loads(out.read())
    fmt = report["checks"][0]["evidence"]
    steady = [kib for t, kib in samples if t >= WARMUP_S] or [kib for _, kib in samples]
    return {
        "file": path.relative_to(ROOT).as_posix(),
        "compressed_bytes": fmt["compressed_bytes"],
        "uncompressed_bytes": fmt["uncompressed_bytes"],
        "members": fmt["members"],
        "lines": fmt["decompressed_lines"],
        "verdict": report["verdict"],
        "ral": report.get("ral"),
        "layers": {lr["layer"]: lr["status"] for lr in report.get("layers", [])},
        "l5_scratch_bytes": next(
            (
                c["evidence"].get("scratch_bytes")
                for c in report["checks"]
                if c["name"] == "l5_restore"
            ),
            None,
        ),
        "l5_sample_n": next(
            (c["evidence"].get("n") for c in report["checks"] if c["name"] == "l5_sample"), None
        ),
        "exit": proc.returncode,
        "l1": {c["name"]: c["status"] for c in report["checks"] if c["layer"] == 1},
        "fails": [c["name"] for c in report["checks"] if c["status"] == "FAIL"],
        "l3_rows": next(
            c["evidence"].get("rows_checked", 0)
            for c in report["checks"]
            if c["name"] in ("l3_row_validity", "l3_pending")
        ),
        "wall_s": wall,
        "peak_rss_mib": usage.ru_maxrss / 1024,  # Linux: KiB
        "rss_samples": len(samples),
        "steady_rss_min_mib": min(steady) / 1024,
        "steady_rss_median_mib": statistics.median(steady) / 1024,
        "steady_rss_max_mib": max(steady) / 1024,
    }


def _cpu() -> str:
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def _commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT
    )
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=ROOT
    )
    return proc.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")


def to_markdown(runs: list[dict]) -> str:
    lines = [
        f"## verify streaming memory (L1–L3) — {datetime.now(UTC):%Y-%m-%d %H:%M} UTC",
        "",
        f"`bench/l1_memory.py` · commit {_commit()} · Python {platform.python_version()} · "
        f"{_cpu()} · {os.cpu_count()} CPUs",
        "",
        "| file | compressed | uncompressed | members | lines | L3 rows | wall | compressed MB/s | "
        "uncompressed MB/s | peak RSS | steady RSS min / median / max | verdict |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for r in runs:
        lines.append(
            f"| `{r['file']}` | {r['compressed_bytes'] / 1e6:,.1f} MB | "
            f"{r['uncompressed_bytes'] / 1e6:,.1f} MB | {r['members']} | {r['lines']:,} | "
            f"{r['l3_rows']:,} | "
            f"{r['wall_s']:.1f} s | {r['compressed_bytes'] / 1e6 / r['wall_s']:.1f} | "
            f"{r['uncompressed_bytes'] / 1e6 / r['wall_s']:.1f} | {r['peak_rss_mib']:.1f} MiB | "
            f"{r['steady_rss_min_mib']:.1f} / {r['steady_rss_median_mib']:.1f} / "
            f"{r['steady_rss_max_mib']:.1f} MiB ({r['rss_samples']} samples) | "
            f"{r['verdict']} (exit {r['exit']}) |"
        )
    small, big = runs[0], runs[-1]
    lines += [
        "",
        f"Input grew {big['compressed_bytes'] / small['compressed_bytes']:.1f}× "
        f"(compressed); peak RSS changed {big['peak_rss_mib'] / small['peak_rss_mib']:.2f}×. "
        "L4/L5 are not implemented yet, so a healthy file is SUSPECT. Failing checks: "
        + "; ".join(f"`{r['file']}`: {', '.join(r['fails']) or 'none'}" for r in runs)
        + ". The big file is 7 complete dumps concatenated: L2 rightly flags everything after "
        "the first completion marker and does not parse it, so L3 validates the first dump only "
        "(see the L3 rows column). Row-scaled L3 memory is benched at 5×/10× scale in phase 8.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    if not V1.is_file():
        sys.exit(f"{V1} not found — run `make incident` first")
    runs = [measure(V1)]
    try:  # disk budget (rule 10): generate, measure, delete; only the numbers are kept
        runs.append(measure(build_big()))
    finally:
        BIG.unlink(missing_ok=True)
    text = to_markdown(runs)
    print(text)
    header = (
        "# Benchmarks\n\nEvery number here is produced by a script in `bench/`; newest first.\n\n"
    )
    old = RESULTS.read_text().removeprefix(header) if RESULTS.exists() else ""
    RESULTS.write_text(header + text + "\n" + old)


if __name__ == "__main__":
    main()
