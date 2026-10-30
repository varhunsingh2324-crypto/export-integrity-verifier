"""ExportGuard dashboard: `make dashboard`. Reads the saved reports in data/reports (or
$EGUARD_REPORTS_DIR); only the upload tab runs the verification engine. No external URLs."""

import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # `streamlit run` adds dashboard/

import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from dashboard import data as D  # noqa: E402
from eguard import forensics as F  # noqa: E402
from eguard.models import ExplainReport, Status, VerifyReport  # noqa: E402
from eguard.report import view  # noqa: E402

LAYER_NAMES = {1: "container", 2: "structure", 3: "rows", 4: "reconciliation", 5: "restore drill"}
PLOTLY_CONFIG = {"displaylogo": False, "displayModeBar": False}  # the logo links to plotly.com
FONT = {"size": 17}
HINT = "No reports in `{}` yet: run `make verify-all` (and `make explain`) first."


@st.cache_data(show_spinner=False)
def _verify(path: str, mtime: float) -> VerifyReport:  # mtime: reload only when the file changed
    return D.load_verify(Path(path))


@st.cache_data(show_spinner=False)
def _explain(path: str, mtime: float) -> ExplainReport:
    return D.load_explain(Path(path))


@st.cache_data(show_spinner=False)
def _matrix(reports: str, mtime: float) -> list[dict]:
    return D.matrix(Path(reports))


def _mtime(p: Path) -> float:
    return p.stat().st_mtime if p.exists() else 0.0


def chip(status: str, text: str | None = None, size: str = "1rem") -> str:
    s = D.style(status)
    label = html.escape(text or D.badge(status))
    return (
        f'<span style="background:{s.fill};color:{s.text};padding:.15em .55em;'
        f'border-radius:6px;font-weight:700;font-size:{size};white-space:nowrap">{label}</span>'
    )


# --- verdict card + evidence ------------------------------------------------------------------


def verdict_card(r: VerifyReport) -> None:
    s = D.style(r.verdict)
    layers = " ".join(
        chip(lr.status, f"{D.style(lr.status).symbol} L{lr.layer} {lr.name}") for lr in r.layers
    )
    sentences = " ".join(html.escape(t) for t in view.summary(r))
    st.markdown(
        f'<div style="border-left:14px solid {s.fill};padding:.8em 1.2em;margin:.4em 0 1em;'
        f'background:rgba(0,0,0,.03);border-radius:6px">'
        f"<div>{chip(r.verdict, size='2.2rem')}"
        f'<span style="font-size:2rem;font-weight:700;margin-left:.8em">RAL {r.ral}/5</span></div>'
        f'<div style="margin:.7em 0;line-height:2.1">{layers}</div>'
        f'<p style="font-size:1.25rem;margin:0">{sentences}</p></div>',
        unsafe_allow_html=True,
    )


def evidence(r: VerifyReport) -> None:
    locs = view.locations(r)
    if locs:
        st.markdown("#### Where in the stream")
        rows = [
            {"layer": f"L{x.layer}", "check": x.check, "where": view.where(x), "detail": x.detail}
            for x in locs
        ]
        st.dataframe(rows, hide_index=True, width="stretch")
    st.markdown("#### Confidence")
    for line in view.confidence(r):
        st.markdown(f"- {html.escape(line)}")
    st.markdown("#### Evidence by layer")
    for lr in r.layers:
        title = f"L{lr.layer} {lr.name} — {D.badge(lr.status)} — {lr.reason}"
        with st.expander(title, expanded=lr.status == Status.FAIL):
            for c in (c for c in r.checks if c.layer == lr.layer):
                st.markdown(
                    f"{chip(c.status)} <code>{html.escape(c.name)}</code> · {c.severity}",
                    unsafe_allow_html=True,
                )
                st.text(c.message)
                st.json(c.evidence, expanded=False)


def html_report(path: Path, key: str) -> None:
    if not path.exists():
        st.caption(f"No HTML report at `{path}`.")
        return
    body = path.read_text(encoding="utf-8")
    st.download_button(
        "Download the HTML report", body, file_name=path.name, mime="text/html", key=key
    )
    st.caption(f"On disk: `{path}`")
    with st.expander("Open the full HTML report here"):
        st.iframe(body, height=900)  # our own report: autoescaped, no script, no URL


def verdict_tab(reports: Path) -> None:
    exports = D.list_exports(reports)
    if not exports:
        st.info(HINT.format(reports))
        return
    labels = {p: label for label, p in exports}
    default = next((i for i, (_, p) in enumerate(exports) if p.stem == "verify_v2"), 0)
    path = st.selectbox("Export", list(labels), index=default, format_func=labels.__getitem__)
    r = _verify(str(path), _mtime(path))
    verdict_card(r)
    evidence(r)
    st.markdown("#### Full report")
    html_report(path.with_suffix(".html"), key=f"dl-{path.stem}")


# --- fault matrix -----------------------------------------------------------------------------

MATRIX_COLUMNS = [
    "gzip -t",
    *(f"L{n} {LAYER_NAMES[n]}" for n in D.LAYERS),
    "ExportGuard",
    "gzip -t says / ExportGuard says",
]


def _cells(rec: dict) -> list[tuple[str, str, str]]:
    """(style key, cell text, hover text) per column of one matrix row."""
    gz = "OK" if rec["gzip"] == "OK" else ("n/a" if rec["gzip"] == "n/a" else Status.FAIL)
    cells = [(gz, f"{D.style(gz).symbol} {rec['gzip']}", f"gzip -t: {rec['gzip']}")]
    for n in D.LAYERS:
        st_ = rec[f"L{n}"]
        cells.append((st_, D.badge(st_), f"L{n}: {rec[f'L{n}_reason']}"))
    ral = "" if rec["ral"] is None else f" · RAL {rec['ral']}"
    cells.append((rec["verdict"], D.badge(rec["verdict"]) + ral, rec["error"] or rec["verdict"]))
    versus = rec["versus"] + ("  ⚠ gzip -t missed it" if rec["disagrees"] else "")
    cells.append(("FAIL" if rec["disagrees"] else "", versus, versus))
    return cells


def heatmap(frame: list[dict]) -> go.Figure:
    styles = [D.PASS_STYLE, D.WARN_STYLE, D.FAIL_STYLE, D.SKIP_STYLE, D.NEUTRAL_STYLE]
    index = {id(s): i for i, s in enumerate(styles)}
    k = len(styles)
    scale = [[pos, s.fill] for i, s in enumerate(styles) for pos in (i / k, (i + 1) / k)]
    grid = [_cells(rec) for rec in frame]
    z = [[(index[id(D.style(key))] + 0.5) / k for key, _, _ in row] for row in grid]
    fig = go.Figure(
        go.Heatmap(
            z=z,
            x=MATRIX_COLUMNS,
            y=[rec["label"] for rec in frame],
            colorscale=scale,
            zmin=0,
            zmax=1,
            showscale=False,
            xgap=3,
            ygap=3,
            text=[[hover for _, _, hover in row] for row in grid],
            hovertemplate="<b>%{y}</b> · %{x}<br>%{text}<extra></extra>",
        )
    )
    for y, row in enumerate(grid):
        for x, (key, text, _) in enumerate(row):
            fig.add_annotation(
                x=x, y=y, text=html.escape(text), showarrow=False,
                font={"size": 15, "color": D.style(key).text},
            )  # fmt: skip
    fig.update_layout(
        height=110 + 52 * len(frame),
        margin={"l": 10, "r": 10, "t": 10, "b": 10},
        font=FONT,
        xaxis={"side": "top", "tickfont": {"size": 15}},
        yaxis={"autorange": "reversed", "tickfont": {"size": 16}},
        plot_bgcolor="#FFFFFF",
    )
    return fig


def matrix_tab(reports: Path) -> None:
    path = reports / "verify_all.json"
    frame = _matrix(str(reports), _mtime(path))
    if not frame:
        st.info(HINT.format(reports))
        return
    missed = sum(rec["disagrees"] for rec in frame)
    st.markdown(
        f"**{len(frame)} exports.** `gzip -t` called **{missed}** of them fine that ExportGuard "
        "finds CORRUPT. Hover a cell for the layer's reason."
    )
    st.plotly_chart(heatmap(frame), width="stretch", config=PLOTLY_CONFIG)
    legend = " ".join(chip(s) for s in (Status.PASS, Status.WARN, Status.FAIL, Status.SKIP))
    st.markdown(f"Legend: {legend}", unsafe_allow_html=True)
    with st.expander("Table view"):
        cols = ["label", "gzip", *(f"L{n}" for n in D.LAYERS), "verdict", "ral", "versus"]
        st.dataframe([{c: rec[c] for c in cols} for rec in frame], hide_index=True)


# --- explain ----------------------------------------------------------------------------------

STEP_LABELS = {
    "rows": "Rows",
    "width": "Bytes per row",
    "data": "Data compressibility",
    "compressor": "Compressor",
}


def waterfall(x: ExplainReport) -> go.Figure:
    old, steps, new = D.waterfall_steps(x)
    mib = 1 << 20
    fig = go.Figure(
        go.Waterfall(
            x=["Old file", *(STEP_LABELS[s.name] for s in steps), "New file"],
            measure=["absolute", *("relative" for _ in steps), "absolute"],
            y=[old / mib, *(s.delta_bytes / mib for s in steps), new / mib],
            text=[
                F.fmt_mib(old),
                *(F.fmt_change(s.size_effect) for s in steps),
                f"{F.fmt_mib(new)} ({F.fmt_change(x.decomposition.observed_change)})",
            ],
            textposition="outside",
            textfont={"size": 18},
            increasing={"marker": {"color": D.WARN_STYLE.fill}},  # as the HTML report: up=warn
            decreasing={"marker": {"color": D.PASS_STYLE.fill}},
            totals={"marker": {"color": "#555555"}},
            connector={"line": {"color": "#999999", "width": 1}},
            hovertemplate="%{x}: %{text}<extra></extra>",
        )
    )
    top = max(old, new, *(old + sum(s.delta_bytes for s in steps[: i + 1]) for i in range(4)))
    fig.update_layout(
        height=480,
        margin={"l": 10, "r": 10, "t": 30, "b": 10},
        font=FONT,
        yaxis={"title": "compressed size (MiB)", "range": [0, 1.15 * top / mib]},
        showlegend=False,
        plot_bgcolor="#FFFFFF",
    )
    return fig


def width_bars(rows: list[dict], top: int) -> go.Figure:
    shown = rows[:top][::-1]
    fig = go.Figure(
        go.Bar(
            x=[r["Δ B/row"] for r in shown],
            y=[r["column"] for r in shown],
            orientation="h",
            marker={
                "color": [
                    D.WARN_STYLE.fill if r["Δ B/row"] > 0 else D.PASS_STYLE.fill for r in shown
                ]
            },  # fmt: skip
            text=[f"{r['Δ B/row']:+.1f} B" for r in shown],
            textposition="outside",
            hovertemplate="%{y}: %{x:+.1f} B/row<extra></extra>",
        )
    )
    fig.update_layout(
        height=80 + 44 * len(shown),
        margin={"l": 10, "r": 40, "t": 10, "b": 10},
        font=FONT,
        xaxis={"title": "Δ bytes per row (old → new)", "zeroline": True},
        plot_bgcolor="#FFFFFF",
    )
    return fig


def _pair_label(p: Path) -> str:
    old, _, new = p.stem.removeprefix("explain_").partition("__")
    return f"{old} → {new}"


def explain_tab(reports: Path) -> None:
    files = D.list_explains(reports)
    if not files:
        st.info(f"No explain reports in `{reports}` yet: run `make explain`.")
        return
    path = st.selectbox("Pair", files, format_func=_pair_label)
    x = _explain(str(path), _mtime(path))
    by = {f.name: f for f in x.decomposition.factors}
    cols = st.columns(4)
    cols[0].metric("Rows (R)", F.fmt_count(by["rows"].new), F.fmt_change(by["rows"].change))
    cols[1].metric("Bytes/row (W)", F.fmt_width(by["width"].new), F.fmt_change(by["width"].change))
    cols[2].metric(
        "Compression (C)", F.fmt_ratio(by["ratio"].new), F.fmt_change(by["ratio"].change)
    )
    cols[3].metric(
        "File size (S)",
        F.fmt_mib(x.new.compressed_bytes),
        F.fmt_change(x.decomposition.observed_change),
    )
    st.markdown("#### Size = rows × bytes per row ÷ compression ratio")
    st.plotly_chart(waterfall(x), width="stretch", config=PLOTLY_CONFIG)
    st.caption(
        "Each step multiplies the running size (order: rows, width, data, compressor); orange = "
        f"bigger, blue = smaller. Probe hypothesis: {x.hypothesis}."
    )
    st.markdown("#### What happened")
    for line in x.narrative:
        st.markdown(f"- {line}")
    st.markdown("#### Column drill-down")
    rows = D.column_rows(x)
    st.plotly_chart(width_bars(rows, 8), width="stretch", config=PLOTLY_CONFIG)
    name = st.selectbox("Column", [r["column"] for r in rows])
    rec = next(r for r in rows if r["column"] == name)
    c = st.columns(4)
    c[0].metric("Bytes per row", rec["new B/row"], rec["Δ B/row"])
    c[1].metric("NULL %", rec["new NULL %"], _delta(rec["old NULL %"], rec["new NULL %"]))
    c[2].metric(
        "Distinct (HLL)", rec["new distinct"], _delta(rec["old distinct"], rec["new distinct"])
    )
    c[3].metric("Δ entropy (bits/byte)", rec["Δ entropy bits"])
    with st.expander("All components"):
        st.dataframe(rows, hide_index=True, width="stretch")
    html_report(path.with_suffix(".html"), key=f"dl-{path.stem}")


def _delta(old: float | None, new: float | None) -> float | None:
    return None if old is None or new is None else round(new - old, 1)


# --- upload -----------------------------------------------------------------------------------


def upload_tab() -> None:
    st.markdown(
        "Verify any compressed export with the real engine (one streaming pass; the format comes "
        "from the magic bytes, not the name). Add its signed manifest for L4."
    )
    dump = st.file_uploader("Export (.gz or .Z)", key="dump")
    manifest = st.file_uploader("Manifest (optional, .json)", type=["json"], key="manifest")
    if st.button("Verify", type="primary", disabled=dump is None) and dump is not None:
        with st.spinner("Verifying…"):
            st.session_state["upload"] = D.verify_upload(dump.name, dump, manifest)
    result: D.UploadResult | None = st.session_state.get("upload")
    if result is None:
        return
    row = result.row
    st.caption(f"`{Path(result.path).name}` · gzip -t says: {D.gzip_says(row.gzip_t)}")
    if row.report is None:
        st.error(f"Tool error (exit 3): {row.error}")
        return
    verdict_card(row.report)
    evidence(row.report)
    if result.html_path:
        st.markdown("#### Full report")
        html_report(Path(result.html_path), key="dl-upload")


def main() -> None:
    st.set_page_config(page_title="ExportGuard", layout="wide")
    reports = D.reports_dir()
    st.title("ExportGuard")
    st.caption(f"Reports from `{reports}` · verified without re-importing")
    tabs = st.tabs(["Verdict & evidence", "Fault matrix", "Size explained", "Verify a file"])
    with tabs[0]:
        verdict_tab(reports)
    with tabs[1]:
        matrix_tab(reports)
    with tabs[2]:
        explain_tab(reports)
    with tabs[3]:
        upload_tab()


main()
