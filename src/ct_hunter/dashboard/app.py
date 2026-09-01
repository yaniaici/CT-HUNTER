"""ct-hunter web interface.

    uv run streamlit run src/ct_hunter/dashboard/app.py

Three tabs:
- Detections: review what the firehose has found and set a verdict.
- Test a domain: run any domain through the detector instantly, without
  waiting for the firehose.
- System: status of the Docker container and ct-hunter-hunt, with buttons
  to start/stop it.
"""

from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime

import pandas as pd
import streamlit as st

from ct_hunter.brands import load_brands
from ct_hunter.detect.similarity import build_variant_index, evaluate_hostname, registrable_domain
from ct_hunter.enrich.dns import get_first_ip, resolve_domain
from ct_hunter.enrich.osint import external_links, http_probe, whois_lookup
from ct_hunter.enrich.reputation import VIRUSTOTAL_API_KEY, asn_reuse, check_abuseipdb, check_urlscan, lookup_asn
from ct_hunter.enrich.visual import VISUAL_SIMILARITY_THRESHOLD, compare_visual
from ct_hunter.graph import build_graph, cluster_for_domain, connected_clusters, render_html, shared_attributes_for_domain
from ct_hunter.process.control import PROJECT_ROOT, docker_status, hunt_status, start_hunt, stop_hunt
from ct_hunter.report import write_report
from ct_hunter.scoring import FRESH_DOMAIN_AGE_DAYS, MAX_SCORE, domain_age_bonus, reputation_bonus, score_detection
from ct_hunter.storage.db import (
    VALID_STATUSES,
    get_connection,
    init_db,
    update_reputation,
    update_score,
    update_status,
    update_whois,
)

st.set_page_config(page_title="CT Hunter", page_icon="🎣", layout="wide")

# An unresponsive (not NXDOMAIN) nameserver can cost up to ~9s per domains
# (enrich/dns.py tries A, then AAAA, then MX, 3s timeout each). enrich_pending.py
# now resolves up to MAX_WORKERS domains concurrently, so the worst case for
# a batch of N domains is roughly ceil(N / MAX_WORKERS) * 9s, not N * 9s;
# this button used to time out in production against a sequential batch
# (see docs/architecture.md section 14), the cap below still leaves a wide
# safety margin under the new parallel worst case. Running
# `uv run ct-hunter-enrich` from a terminal has no such cap.
ENRICH_BATCH_LIMIT = 200
ENRICH_TIMEOUT_SECONDS = 450

LIST_COLUMNS = ["domain", "brand", "technique", "score", "status"]
# Internal status values are kept in Spanish (see docs/architecture.md,
# they are already stored as data in the database); this maps them to the
# English labels and st.badge colors shown in the UI.
STATUS_LABELS = {
    "nuevo": "New",
    "en_seguimiento": "Monitoring",
    "confirmado_malicioso": "Confirmed malicious",
    "descartado": "Discarded",
}
STATUS_BADGE_COLORS = {
    "nuevo": "blue",
    "en_seguimiento": "orange",
    "confirmado_malicioso": "red",
    "descartado": "gray",
}
STATUS_HEX = {
    "nuevo": "#3b82f6",
    "en_seguimiento": "#f59e0b",
    "confirmado_malicioso": "#ef4444",
    "descartado": "#6b7280",
}

# Score bands, same scale as scoring.py's 0-100 (see docs/architecture.md
# section 5). Purely a display concept: sorting/filtering still happens on
# the raw numeric score.
SEVERITY_BANDS = (
    (80, "Critical", "red", "#ef4444"),
    (60, "High", "orange", "#f59e0b"),
    (40, "Medium", "yellow", "#eab308"),
    (0, "Low", "blue", "#3b82f6"),
)

# What counts as an "alert" on the Overview tab: Critical severity by
# the existing band, reusing it instead of a second definition of "high
# score" that could quietly drift from the badges everywhere else.
ALERT_SCORE_THRESHOLD = SEVERITY_BANDS[0][0]


def severity_for_score(score: float | None) -> tuple[str, str, str]:
    """(label, st.badge color, hex) for a score, or an 'Unscored' band for None."""
    if score is None or pd.isna(score):
        return "Unscored", "gray", "#6b7280"
    for threshold, label, color, hexcode in SEVERITY_BANDS:
        if score >= threshold:
            return label, color, hexcode
    return "Low", "blue", "#3b82f6"


def status_badge(status: str) -> None:
    st.badge(STATUS_LABELS.get(status, status), color=STATUS_BADGE_COLORS.get(status, "gray"))


def run_background_task(module: str, *args: str, timeout: int) -> str:
    """Runs a ct_hunter module as a subprocess and returns its output.

    A `subprocess.TimeoutExpired` here used to crash the whole dashboard
    session, not just the one button (any unhandled exception at the top
    level of a Streamlit script takes the whole session down); this
    happened for real with the "Enrich pending" button. Progress already
    made is not lost, since each row commits to the database as it is
    processed, so on a timeout the caller can just run the task again.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", module, *args],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired as exc:
        partial_output = exc.stdout or exc.stderr or ""
        return (
            f"Timed out after {timeout}s without finishing. Rows already "
            f"processed before the timeout are saved, run the task again to "
            f"pick up where it left off, or run it from a terminal instead "
            f"(no timeout there).\n\n{partial_output}"
        )


def severity_badge(score: float | None) -> None:
    label, color, _ = severity_for_score(score)
    text = f"{label} ({score:.0f})" if score is not None and not pd.isna(score) else label
    st.badge(text, color=color)


def yes_no_unknown(val) -> str:
    """Formats a nullable boolean coming from a pandas-loaded SQLite
    INTEGER column: pandas upcasts 0/1/NULL to float (1.0/0.0/NaN), so a
    raw f-string would print '1.0' instead of 'Yes'."""
    if val is None or pd.isna(val):
        return "Unknown"
    return "Yes" if bool(val) else "No"


def style_detections_table(df: pd.DataFrame):
    """pandas Styler coloring the score column by severity band, so the
    list reads like a real alert grid at a glance instead of a plain table.

    Colors are computed with vectorized pandas operations (one pd.cut/map
    call per column) instead of a Python callback per cell (Styler.map),
    since this runs on every Streamlit rerun that touches the Detections
    tab, not just when the underlying data changes."""

    def _score_colors(column: pd.Series) -> pd.Series:
        bins = [band[0] for band in reversed(SEVERITY_BANDS)] + [MAX_SCORE + 1]
        hexcodes = [band[3] for band in reversed(SEVERITY_BANDS)]
        colors = pd.cut(column, bins=bins, labels=hexcodes, right=False, include_lowest=True).astype(str)
        colors = colors.where(column.notna(), "#6b7280")
        return "color: " + colors + "; font-weight: 600"

    def _status_colors(column: pd.Series) -> pd.Series:
        colors = column.map(STATUS_HEX).fillna("#6b7280")
        return "color: " + colors + "; font-weight: 600"

    return (
        df.style
        .apply(_score_colors, subset=["score"])
        .apply(_status_colors, subset=["status"])
        .format({"score": lambda v: "N/A" if pd.isna(v) else f"{v:.0f}", "status": lambda v: STATUS_LABELS.get(v, v)})
    )


@st.cache_resource
def _connection():
    conn = get_connection()
    init_db(conn)
    return conn


@st.cache_resource
def _brands_and_index():
    brands = load_brands()
    return brands, build_variant_index(brands)


@st.cache_data(ttl=3)
def _cached_hunt_status() -> dict:
    return hunt_status()


@st.cache_data(ttl=3)
def _cached_docker_status() -> str:
    return docker_status()


def _refresh_status_cache() -> None:
    """Forces a fresh read on the next call, used right after an explicit
    start/stop/refresh action so the button feels immediate instead of
    waiting out the TTL."""
    _cached_hunt_status.clear()
    _cached_docker_status.clear()


def _data_version(conn) -> tuple:
    """Cheap signal (row count + latest update) used as a cache key so
    expensive queries/graph builds only rerun when the underlying data has
    actually changed, not on every Streamlit rerun triggered by an
    unrelated button somewhere else on the page. See docs/architecture.md
    for why this was needed."""
    row = conn.execute("SELECT COUNT(*) AS n, MAX(updated_at) AS latest FROM detections").fetchone()
    return (row["n"], row["latest"])


DETECTIONS_PAGE_SIZE = 50


def _rows_to_df(rows: list) -> pd.DataFrame:
    df = pd.DataFrame([dict(r) for r in rows])
    for col in ("first_seen_at", "last_seen_at", "updated_at"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], unit="s")
    return df


def _filter_clause(brand_filter: list[str], status_filter: list[str], min_score: int) -> tuple[str, list]:
    """WHERE clause + params for the Detections tab's sidebar filters,
    shared by the count query and the page query so they can never
    disagree. NULL scores count as 0 for the threshold, matching how a
    detection with no score yet used to read under the old
    df["score"].fillna(0) >= min_score in-memory filter."""
    if not brand_filter or not status_filter:
        return "0 = 1", []  # an empty multiselect means "match nothing", not "match everything"
    brand_placeholders = ",".join("?" * len(brand_filter))
    status_placeholders = ",".join("?" * len(status_filter))
    clause = (
        f"brand IN ({brand_placeholders}) AND status IN ({status_placeholders}) "
        "AND COALESCE(score, 0) >= ?"
    )
    return clause, [*brand_filter, *status_filter, min_score]


@st.cache_data
def _distinct_brands_cached(_conn, version: tuple) -> list[str]:
    rows = _conn.execute("SELECT DISTINCT brand FROM detections ORDER BY brand").fetchall()
    return [r["brand"] for r in rows]


@st.cache_data
def _summary_counts_cached(_conn, version: tuple) -> dict:
    """Unfiltered KPI totals via cheap indexed aggregate queries instead
    of loading the whole table just to call len()/sum() on it, this is
    the main point of pagination: the dashboard should not need every
    row in memory just to show a count."""
    total = _conn.execute("SELECT COUNT(*) AS n FROM detections").fetchone()["n"]
    confirmed = _conn.execute(
        "SELECT COUNT(*) AS n FROM detections WHERE status = 'confirmado_malicioso'"
    ).fetchone()["n"]
    critical = _conn.execute(
        "SELECT COUNT(*) AS n FROM detections WHERE COALESCE(score, 0) >= ?", (ALERT_SCORE_THRESHOLD,)
    ).fetchone()["n"]
    return {"total": total, "confirmed": confirmed, "critical": critical}


@st.cache_data
def _overview_kpis_cached(_conn, version: tuple) -> dict:
    """KPI row for the Overview tab. 'new_24h' and 'alerts' are the two
    numbers that don't already exist in _summary_counts_cached."""
    day_ago = time.time() - 86400
    new_24h = _conn.execute(
        "SELECT COUNT(*) AS n FROM detections WHERE first_seen_at >= ?", (day_ago,)
    ).fetchone()["n"]
    alerts = _conn.execute(
        "SELECT COUNT(*) AS n FROM detections WHERE COALESCE(score, 0) >= ? "
        "AND status NOT IN ('confirmado_malicioso', 'descartado')",
        (ALERT_SCORE_THRESHOLD,),
    ).fetchone()["n"]
    return {"new_24h": new_24h, "alerts": alerts}


@st.cache_data
def _alerts_cached(_conn, version: tuple, min_score: float, limit: int = 200) -> pd.DataFrame:
    """Critical-severity domains that have not reached a terminal
    status yet, the ones an analyst actually needs to look at. Capped
    so a genuine flood can't blow up the render, this is meant to stay
    a short, actionable list, not a second copy of the full table."""
    cursor = _conn.execute(
        "SELECT * FROM detections WHERE COALESCE(score, 0) >= ? "
        "AND status NOT IN ('confirmado_malicioso', 'descartado') "
        "ORDER BY score DESC, first_seen_at DESC LIMIT ?",
        (min_score, limit),
    )
    rows = cursor.fetchall()
    if not rows:
        return pd.DataFrame(columns=[d[0] for d in cursor.description])
    return _rows_to_df(rows)


@st.cache_data
def _daily_counts_cached(_conn, version: tuple, days: int = 30) -> pd.DataFrame:
    """Detections per day for the last `days` days, by first_seen_at
    (when the certificate was actually issued, not when it was
    enriched/scored later)."""
    cutoff = time.time() - days * 86400
    rows = _conn.execute(
        "SELECT date(first_seen_at, 'unixepoch') AS day, COUNT(*) AS count "
        "FROM detections WHERE first_seen_at >= ? GROUP BY day ORDER BY day",
        (cutoff,),
    ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


@st.cache_data
def _brand_breakdown_cached(_conn, version: tuple) -> pd.DataFrame:
    rows = _conn.execute(
        "SELECT brand, COUNT(*) AS count FROM detections GROUP BY brand ORDER BY count DESC"
    ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


@st.cache_data
def _technique_breakdown_cached(_conn, version: tuple) -> pd.DataFrame:
    rows = _conn.execute(
        "SELECT technique, COUNT(*) AS count FROM detections GROUP BY technique ORDER BY count DESC"
    ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


@st.cache_data
def _status_breakdown_cached(_conn, version: tuple) -> pd.DataFrame:
    rows = _conn.execute(
        "SELECT status, COUNT(*) AS count FROM detections GROUP BY status"
    ).fetchall()
    df = pd.DataFrame([dict(r) for r in rows])
    if not df.empty:
        df["status"] = df["status"].map(lambda s: STATUS_LABELS.get(s, s))
    return df


@st.cache_data
def _filtered_count_cached(_conn, version: tuple, where_clause: str, params: tuple) -> int:
    row = _conn.execute(f"SELECT COUNT(*) AS n FROM detections WHERE {where_clause}", params).fetchone()
    return row["n"]


@st.cache_data
def _page_cached(_conn, version: tuple, where_clause: str, params: tuple, limit: int, offset: int) -> pd.DataFrame:
    cursor = _conn.execute(
        f"SELECT * FROM detections WHERE {where_clause} "
        "ORDER BY score IS NULL, score DESC, last_seen_at DESC "
        "LIMIT ? OFFSET ?",
        (*params, limit, offset),
    )
    rows = cursor.fetchall()
    if not rows:
        # pd.DataFrame([]) has no columns at all, which breaks
        # page_df[LIST_COLUMNS] downstream (e.g. every brand/status
        # deselected in the sidebar, matching nothing). cursor.description
        # is populated from the query's column list even with zero rows,
        # so this keeps the empty page schema-correct.
        return pd.DataFrame(columns=[d[0] for d in cursor.description])
    return _rows_to_df(rows)


@st.cache_data
def _build_graph_cached(_conn, version: tuple, min_score: float | None, statuses: tuple[str, ...] | None):
    """Cached graph build. `version` ties the cache to the actual data
    (see _data_version); min_score/statuses=None means "every row that has
    at least one attribute populated", used by the per-domain cluster
    lookup so it doesn't have to scan the full, mostly attribute-less
    table on every rerun."""
    if min_score is None and statuses is None:
        rows = _conn.execute(
            "SELECT * FROM detections WHERE ip_address IS NOT NULL OR asn IS NOT NULL "
            "OR registrar IS NOT NULL OR nameservers IS NOT NULL"
        ).fetchall()
    else:
        placeholders = ",".join("?" * len(statuses))
        rows = _conn.execute(
            f"SELECT * FROM detections WHERE score >= ? AND status IN ({placeholders})",
            (min_score, *statuses),
        ).fetchall()
    return build_graph(rows)


@st.cache_data
def _graph_html_cached(_conn, version: tuple, min_score: float, statuses: tuple[str, ...]) -> str:
    """pyvis HTML generation is the expensive part of the graph tab
    (serializing every node/edge into a JS document); cached alongside the
    graph build itself so dragging an unrelated widget elsewhere on the
    page never regenerates it."""
    g = _build_graph_cached(_conn, version, min_score, statuses)
    return render_html(g)


_header_left, _header_right = st.columns([3, 2])
with _header_left:
    st.title("🎣 CT Hunter")
    st.caption("Suspicious domains detected in Certificate Transparency logs, before they are used.")
with _header_right:
    _hstatus = _cached_hunt_status()
    _docker_state = _cached_docker_status()
    st.write("")  # vertical alignment with the title
    b1, b2, b3 = st.columns(3)
    with b1:
        st.badge(
            "Firehose running" if _hstatus["running"] else "Firehose stopped",
            color="green" if _hstatus["running"] else "gray",
            icon="🟢" if _hstatus["running"] else "🔴",
        )
    with b2:
        st.badge(
            "Docker up" if _docker_state == "running" else f"Docker: {_docker_state}",
            color="green" if _docker_state == "running" else "orange",
        )
    with b3:
        _certs_seen = _hstatus.get("certs_seen")
        st.badge(f"{_certs_seen:,} certs seen" if _certs_seen is not None else "No data yet", color="blue")

st.divider()

tab_overview, tab_detections, tab_graph, tab_test, tab_system = st.tabs(
    ["📊 Overview", "📋 Detections", "🕸️ Infrastructure graph", "🔍 Test a domain", "⚙️ System"]
)

conn = _connection()
# Computed once and reused everywhere below instead of re-querying
# COUNT(*)/MAX(updated_at) on every tab, since it is the same connection
# (a cached resource) and the same underlying data within one script run.
data_version = _data_version(conn)

with tab_overview:
    summary = _summary_counts_cached(conn, data_version)
    overview_kpis = _overview_kpis_cached(conn, data_version)

    if summary["total"] == 0:
        st.info(
            "No detections yet. Go to the **System** tab to start "
            "`ct-hunter-hunt` and start watching the firehose."
        )
    else:
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            with st.container(border=True):
                st.metric("Total tracked", summary["total"])
        with k2:
            with st.container(border=True):
                st.metric("New (last 24h)", overview_kpis["new_24h"])
        with k3:
            with st.container(border=True):
                st.metric("Confirmed malicious", summary["confirmed"])
        with k4:
            with st.container(border=True):
                st.metric("🚨 Alerts", overview_kpis["alerts"])

        st.subheader("🚨 Alerts: needs attention")
        st.caption(
            f"Score {ALERT_SCORE_THRESHOLD}+ (Critical) and not yet confirmed or discarded. "
            "Read-only here, go to the Detections tab to investigate and set a verdict."
        )
        alerts_df = _alerts_cached(conn, data_version, ALERT_SCORE_THRESHOLD)
        if alerts_df.empty:
            st.info("No alerts right now.")
        else:
            st.dataframe(
                style_detections_table(alerts_df[LIST_COLUMNS]),
                hide_index=True,
                width="stretch",
                height=min(360, 40 + 35 * len(alerts_df)),
            )

        st.divider()
        st.subheader("📈 Detections over time")
        daily = _daily_counts_cached(conn, data_version)
        if daily.empty:
            st.caption("Not enough data yet.")
        else:
            st.area_chart(daily, x="day", y="count", height=260)

        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.subheader("🎯 Top targeted brands")
            brand_breakdown = _brand_breakdown_cached(conn, data_version)
            if brand_breakdown.empty:
                st.caption("No data yet.")
            else:
                st.bar_chart(brand_breakdown, x="brand", y="count", height=280)
        with chart_col2:
            st.subheader("🧬 Techniques")
            technique_breakdown = _technique_breakdown_cached(conn, data_version)
            if technique_breakdown.empty:
                st.caption("No data yet.")
            else:
                st.bar_chart(technique_breakdown, x="technique", y="count", height=280)

        st.subheader("📊 Status breakdown")
        status_breakdown = _status_breakdown_cached(conn, data_version)
        if status_breakdown.empty:
            st.caption("No data yet.")
        else:
            st.bar_chart(status_breakdown, x="status", y="count", height=240)

with tab_detections:
    summary = _summary_counts_cached(conn, data_version)

    if summary["total"] == 0:
        st.info(
            "No detections yet. Go to the **System** tab to start "
            "`ct-hunter-hunt` and start watching the firehose."
        )
    else:
        with st.sidebar:
            st.header("🎛️ Filters")
            brands_present = _distinct_brands_cached(conn, data_version)
            brand_filter = st.multiselect("Brand", brands_present, default=brands_present)
            default_statuses = [s for s in VALID_STATUSES if s != "descartado"]
            status_filter = st.multiselect(
                "Status", list(VALID_STATUSES), default=default_statuses,
                format_func=lambda s: STATUS_LABELS.get(s, s),
                help="Discarded items are hidden by default to keep the list focused on what's actionable.",
            )
            min_score = st.slider("Minimum score", 0, 100, 0)

        where_clause, where_params = _filter_clause(brand_filter, status_filter, min_score)
        filtered_count = _filtered_count_cached(conn, data_version, where_clause, tuple(where_params))

        # A page number only makes sense relative to a specific filter
        # selection; reset to page 1 whenever brand/status/score actually
        # changed, otherwise the old page can point past the end of a
        # newly-narrowed result set, same class of stale-index bug fixed
        # for row selection (see docs/architecture.md section 13).
        filter_sig = (tuple(sorted(brand_filter)), tuple(sorted(status_filter)), min_score)
        if st.session_state.get("detections_filter_sig") != filter_sig:
            st.session_state["detections_filter_sig"] = filter_sig
            st.session_state["detections_page"] = 0

        total_pages = max(1, -(-filtered_count // DETECTIONS_PAGE_SIZE))  # ceil division
        current_page = min(st.session_state.get("detections_page", 0), total_pages - 1)
        st.session_state["detections_page"] = current_page

        page_df = _page_cached(
            conn, data_version, where_clause, tuple(where_params),
            DETECTIONS_PAGE_SIZE, current_page * DETECTIONS_PAGE_SIZE,
        )

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            with st.container(border=True):
                st.metric("Matching filter", filtered_count)
        with k2:
            with st.container(border=True):
                st.metric("Total tracked", summary["total"])
        with k3:
            with st.container(border=True):
                st.metric("Confirmed malicious", summary["confirmed"])
        with k4:
            with st.container(border=True):
                st.metric("Critical severity", summary["critical"])

        list_col, detail_col = st.columns([2, 3])

        with list_col:
            st.subheader("📋 Detections")
            st.caption("Select a row to investigate it in the panel on the right. Color = severity.")
            selection = st.dataframe(
                style_detections_table(page_df[LIST_COLUMNS]),
                hide_index=True,
                width="stretch",
                height=560,
                on_select="rerun",
                selection_mode="single-row",
                key="detections_table",
            )
            selected_rows = selection.selection.rows if selection and selection.selection else []
            # A selection index can go stale (point past the end of the
            # now-shorter page) right after a sidebar filter narrows the
            # table or the page changes: Streamlit keeps the widget's old
            # selection state across the rerun, it does not clear it when
            # the underlying data shrinks. Without this bounds check that
            # crashed the whole app with an IndexError (seen in production).
            selected_rows = [i for i in selected_rows if i < len(page_df)]

            pg_prev, pg_info, pg_next = st.columns([1, 2, 1])
            with pg_prev:
                if st.button("◀ Prev", disabled=current_page == 0):
                    st.session_state["detections_page"] = current_page - 1
                    st.rerun()
            with pg_info:
                st.caption(f"Page {current_page + 1} of {total_pages} ({filtered_count} matching)")
            with pg_next:
                if st.button("Next ▶", disabled=current_page >= total_pages - 1):
                    st.session_state["detections_page"] = current_page + 1
                    st.rerun()

        with detail_col:
            st.subheader("🔬 Detection context")

            if not selected_rows:
                st.info("⬅️ Select a domain from the list to see its context and set a verdict.")
            else:
                row = page_df.iloc[selected_rows[0]]
                domain = row["domain"]
                reg_domain = row["registrable_domain"] or domain

                with st.container(border=True):
                    st.markdown(f"### `{domain}`")
                    badge_col1, badge_col2, badge_col3 = st.columns([1, 1, 2])
                    with badge_col1:
                        status_badge(row["status"])
                    with badge_col2:
                        severity_badge(row["score"] if pd.notna(row["score"]) else None)
                    with badge_col3:
                        st.caption(f"{row['brand']} · {row['technique']}")
                    st.caption(
                        f"First seen: {row['first_seen_at']:%Y-%m-%d %H:%M} · "
                        f"last seen: {row['last_seen_at']:%Y-%m-%d %H:%M} · "
                        f"{row['cert_count']} certificate(s) · issuer: {row['issuer_org']} · "
                        f"edit distance: {row['edit_distance']}"
                    )

                with st.container(border=True):
                    st.markdown("**🌐 DNS enrichment**")
                    e1, e2, e3 = st.columns([1, 1, 2])
                    e1.write(f"Resolves to an IP: **{yes_no_unknown(row['resolves_ip'])}**")
                    e2.write(f"Has MX: **{yes_no_unknown(row['has_mx'])}**")
                    if e3.button("🔎 Resolve DNS now", key=f"dns_{domain}"):
                        with st.spinner("Resolving..."):
                            resolves_ip, has_mx = resolve_domain(reg_domain)
                            new_score = score_detection(row["technique"], row["issuer_org"], resolves_ip, has_mx)
                            update_score(conn, domain, new_score, resolves_ip, has_mx)
                        st.cache_resource.clear()
                        st.rerun()

                with st.container(border=True):
                    st.markdown("**🕵️ Investigation**")
                    inv1, inv2 = st.columns(2)
                    if inv1.button("📋 Run WHOIS", key=f"whois_btn_{domain}"):
                        with st.spinner("Querying WHOIS..."):
                            info = whois_lookup(reg_domain)
                            st.session_state[f"whois_result_{domain}"] = info
                            if "error" not in info and (info.get("registrar") or info.get("nameservers")):
                                current_score = row["score"] if pd.notna(row["score"]) else 0
                                bonus = domain_age_bonus(info.get("creation_date_ts"))
                                new_score = min(current_score + bonus, MAX_SCORE)
                                update_whois(
                                    conn, domain, info.get("registrar"), info.get("nameservers"),
                                    info.get("creation_date_ts"), new_score,
                                )
                                st.cache_resource.clear()
                    if inv2.button("🌐 Check the website", key=f"http_btn_{domain}"):
                        with st.spinner("Connecting..."):
                            st.session_state[f"http_result_{domain}"] = http_probe(reg_domain)

                    whois_result = st.session_state.get(f"whois_result_{domain}")
                    if whois_result:
                        if "error" in whois_result:
                            st.warning(f"WHOIS lookup failed: {whois_result['error']}")
                        else:
                            age_note = ""
                            creation_ts = whois_result.get("creation_date_ts")
                            if creation_ts is not None:
                                age_days = int((time.time() - creation_ts) / 86400)
                                age_note = f" ({age_days} days old"
                                age_note += (
                                    ", fresh domain bonus applied)"
                                    if 0 <= age_days <= FRESH_DOMAIN_AGE_DAYS else ")"
                                )
                            st.write(
                                f"Created: **{whois_result['creation_date']}**{age_note} · "
                                f"Registrar: **{whois_result['registrar']}** · "
                                f"Registrant country: **{whois_result['registrant_country']}**"
                            )
                            with st.expander("Full WHOIS output"):
                                st.code(whois_result["raw"], language=None)

                    http_result = st.session_state.get(f"http_result_{domain}")
                    if http_result:
                        if "error" in http_result:
                            st.warning(f"Could not connect over HTTP: {http_result['error']}")
                        else:
                            st.write(
                                f"HTTP {http_result['status_code']} ({http_result['scheme']}) · "
                                f"title: *{http_result['title'] or '(no title)'}* · "
                                f"server: {http_result['server'] or '?'}"
                            )
                            st.caption(f"Final URL after redirects: {http_result['final_url']}")

                    st.caption(
                        "External links: "
                        + " · ".join(f"[{name}]({url})" for name, url in external_links(reg_domain).items())
                    )

                with st.container(border=True):
                    st.markdown("**📸 Visual comparison**")
                    st.caption(
                        "Captures the site with a real browser and compares it (perceptual hash) "
                        "against the brand's legitimate site. Takes ~10-20s the first time."
                    )
                    if st.button("📸 Capture and compare visually", key=f"visual_btn_{domain}"):
                        brands_vis, _ = _brands_and_index()
                        brand_obj = next((b for b in brands_vis if b.name == row["brand"]), None)
                        if brand_obj is None:
                            st.warning(f"Brand '{row['brand']}' not found in config/brands.yaml.")
                        else:
                            with st.spinner("Capturing screenshots and comparing (may take a while)..."):
                                result = compare_visual(reg_domain, brand_obj)
                            st.session_state[f"visual_result_{domain}"] = result

                            if "error" not in result:
                                resolves_ip = bool(row["resolves_ip"]) if pd.notna(row["resolves_ip"]) else None
                                has_mx = bool(row["has_mx"]) if pd.notna(row["has_mx"]) else None
                                new_score = score_detection(
                                    row["technique"], row["issuer_org"], resolves_ip, has_mx,
                                    visually_similar=result["visually_similar"],
                                )
                                update_score(
                                    conn, domain, new_score, resolves_ip, has_mx,
                                    screenshot_path=str(result["candidate_path"]),
                                    visual_hamming_distance=result["hamming_distance"],
                                )
                                st.cache_resource.clear()

                    visual_result = st.session_state.get(f"visual_result_{domain}")
                    if visual_result:
                        if "error" in visual_result:
                            st.warning(visual_result["error"])
                        else:
                            dist = visual_result["hamming_distance"]
                            similar = visual_result["visually_similar"]
                            (st.error if similar else st.info)(
                                f"Perceptual distance: **{dist}** "
                                f"({'visually similar' if similar else 'visually different'}, "
                                f"threshold {VISUAL_SIMILARITY_THRESHOLD})"
                            )
                            img_ref, img_cand = st.columns(2)
                            img_ref.image(str(visual_result["reference_path"]), caption=f"Reference: {row['brand']}")
                            img_cand.image(str(visual_result["candidate_path"]), caption=f"Candidate: {domain}")

                with st.container(border=True):
                    st.markdown("**🛡️ External reputation**")
                    vt_hint = "" if VIRUSTOTAL_API_KEY else " (VirusTotal not configured, see .env.example)"
                    st.caption(f"ASN + our own infrastructure reuse + URLscan{vt_hint}.")
                    if st.button("🕵️ Check reputation", key=f"reputation_btn_{domain}"):
                        with st.spinner("Querying ASN, URLscan, and AbuseIPDB..."):
                            ip = get_first_ip(reg_domain)
                            asn_info = lookup_asn(ip) if ip else {"error": "the domain does not resolve right now"}
                            urlscan_result = check_urlscan(reg_domain)
                            reused = (
                                asn_reuse(conn, asn_info.get("asn"), exclude_domain=domain)
                                if asn_info.get("asn") else []
                            )
                            abuse_result = check_abuseipdb(ip) if ip else {"configured": False}

                            bonus = reputation_bonus(
                                asn_reuse_count=len(reused),
                                urlscan_tags=urlscan_result.get("tags"),
                                virustotal_malicious_count=None,
                                abuseipdb_score=abuse_result.get("abuse_score"),
                            )
                            current_score = row["score"] if pd.notna(row["score"]) else 0
                            new_score = min(current_score + bonus, MAX_SCORE)
                            update_reputation(
                                conn, domain, new_score, ip,
                                asn_info.get("asn"), asn_info.get("asn_org"),
                                None,
                            )
                            st.session_state[f"reputation_result_{domain}"] = {
                                "ip": ip, "asn_info": asn_info, "urlscan": urlscan_result,
                                "reused": [dict(r) for r in reused], "abuseipdb": abuse_result, "bonus": bonus,
                            }
                            st.cache_resource.clear()

                    rep_result = st.session_state.get(f"reputation_result_{domain}")
                    if rep_result:
                        st.write(
                            f"IP: **{rep_result['ip'] or '?'}** · "
                            f"ASN: **{rep_result['asn_info'].get('asn') or '?'}** "
                            f"({rep_result['asn_info'].get('asn_org') or '?'})"
                        )
                        if rep_result["reused"]:
                            others = ", ".join(f"`{r['domain']}` ({STATUS_LABELS.get(r['status'], r['status'])})" for r in rep_result["reused"])
                            st.error(f"⚠️ This ASN also hosts: {others}")
                        else:
                            st.caption("No ASN reuse detected in your own database.")

                        us = rep_result["urlscan"]
                        if us.get("scanned"):
                            st.write(
                                f"URLscan: seen {us['count']} time(s), tags: {', '.join(us['tags']) or 'none'}"
                                + (", **explicit malicious verdict**" if us.get("malicious_verdict") else "")
                            )
                        else:
                            st.caption("No URLscan.io scans of this domain yet.")

                        ab = rep_result["abuseipdb"]
                        if ab.get("configured"):
                            st.write(f"AbuseIPDB: abuse confidence score **{ab.get('abuse_score')}**/100")
                        else:
                            st.caption("AbuseIPDB not configured (see .env.example).")

                        st.caption(f"Reputation bonus applied to score: +{rep_result['bonus']}")

                with st.container(border=True):
                    st.markdown("**🕸️ Infrastructure cluster**")
                    full_graph = _build_graph_cached(conn, data_version, None, None)
                    cluster_others = cluster_for_domain(full_graph, domain)
                    if cluster_others:
                        shared = shared_attributes_for_domain(full_graph, domain)
                        st.error(
                            f"⚠️ Shares infrastructure with {len(cluster_others)} other domain(s), "
                            f"via: {', '.join(shared)}"
                        )
                        for other in sorted(cluster_others)[:20]:
                            other_data = full_graph.nodes[other]
                            st.write(
                                f"`{other}`: {other_data.get('brand')}, "
                                f"{STATUS_LABELS.get(other_data.get('status'), other_data.get('status'))}, "
                                f"score {other_data.get('score')}"
                            )
                        if len(cluster_others) > 20:
                            st.caption(f"...and {len(cluster_others) - 20} more. See the Infrastructure graph tab for the full view.")
                    else:
                        st.caption(
                            "No shared infrastructure detected with any other tracked domain yet "
                            "(needs IP/ASN/registrar/nameserver data; run 🕵️ Check reputation or 📋 Run WHOIS first)."
                        )

                if pd.notna(row["notes"]) and row["notes"]:
                    st.info(f"**Previous notes:** {row['notes']}")

                with st.container(border=True):
                    st.markdown("**✅ Verdict**")
                    statuses = list(VALID_STATUSES)
                    new_status = st.selectbox(
                        "Status", statuses, index=statuses.index(row["status"]), key=f"status_{domain}",
                        format_func=lambda s: STATUS_LABELS.get(s, s),
                    )
                    new_notes = st.text_area(
                        "Notes (evidence, reasoning: this is what feeds reports/)",
                        value=row["notes"] if pd.notna(row["notes"]) else "",
                        key=f"notes_{domain}",
                    )
                    if st.button("💾 Save verdict", type="primary", key=f"save_{domain}"):
                        update_status(conn, domain, new_status, new_notes)
                        st.success("Verdict saved.")
                        st.cache_resource.clear()
                        st.rerun()

                    if row["status"] == "confirmado_malicioso":
                        st.divider()
                        st.markdown("**📝 Case report**")
                        st.caption(
                            "Generates a draft in reports/ with the timeline and signals already "
                            "on record. The interpretation (why it matters, what it shows) still "
                            "has to be added by hand afterward."
                        )
                        if st.button("📝 Generate report draft", key=f"report_{domain}"):
                            raw_row = conn.execute(
                                "SELECT * FROM detections WHERE domain = ?", (domain,)
                            ).fetchone()
                            path = write_report(raw_row)
                            st.success(f"Written to `{path.relative_to(PROJECT_ROOT)}`")
                            with st.expander("View draft"):
                                st.code(path.read_text(), language="markdown")

with tab_graph:
    st.subheader("🕸️ Infrastructure correlation graph")
    st.caption(
        "Domains connected through a shared IP, ASN, registrar, or nameserver, "
        "surfacing infrastructure reuse across detections. Attribute data (registrar, "
        "nameservers) has to be populated first, via 🕵️ Check reputation and 📋 Run WHOIS "
        "on individual domains, or `uv run ct-hunter-whois` in bulk."
    )
    st.caption(
        "Known limitation: WHOIS output format varies a lot by TLD registry (some ccTLDs "
        "don't even use a 'Registrar:' field), so registrar data is missing for a chunk of "
        "domains regardless of correlation; that shows up as isolated nodes, not as \"no reuse\"."
    )

    graph_conn = conn
    graph_version = data_version

    if graph_version[0] == 0:
        st.info("No detections yet.")
    else:
        with st.container(border=True):
            gcol1, gcol2 = st.columns(2)
            with gcol1:
                graph_min_score = st.slider("Minimum score for the graph", 0, 100, 50, key="graph_min_score")
            with gcol2:
                graph_statuses = st.multiselect(
                    "Status", list(VALID_STATUSES), default=list(VALID_STATUSES),
                    format_func=lambda s: STATUS_LABELS.get(s, s), key="graph_status_filter",
                )

        g = None
        graphed_domains = []
        if graph_statuses:
            g = _build_graph_cached(graph_conn, graph_version, graph_min_score, tuple(graph_statuses))
            graphed_domains = [n for n, data in g.nodes(data=True) if data.get("kind") == "domain"]
            st.caption(f"{len(graphed_domains)} domain(s) match the current filter.")

        if not graphed_domains:
            st.info("No domains match this filter.")
        else:
            clusters = connected_clusters(g)

            m1, m2, m3 = st.columns(3)
            with m1:
                with st.container(border=True):
                    st.metric("Domains graphed", len(graphed_domains))
            with m2:
                with st.container(border=True):
                    st.metric("Infrastructure clusters", len(clusters))
            with m3:
                with st.container(border=True):
                    st.metric("Isolated domains", len(graphed_domains) - sum(len(c) for c in clusters))

            if clusters:
                st.markdown("**Clusters found (domains sharing infrastructure)**")
                for i, cluster in enumerate(sorted(clusters, key=len, reverse=True), start=1):
                    with st.expander(f"Cluster {i}: {len(cluster)} domains"):
                        for d in sorted(cluster):
                            node_data = g.nodes[d]
                            cols = st.columns([3, 1])
                            cols[0].write(f"`{d}`: {node_data.get('brand')}, score {node_data.get('score')}")
                            with cols[1]:
                                status_badge(node_data.get("status"))
                            shared = [n for n in g.neighbors(d)]
                            st.caption("Shared attributes: " + ", ".join(shared))
            else:
                st.info(
                    "No clusters found with the current data. Either these domains really "
                    "don't share infrastructure yet, or registrar/nameserver data hasn't "
                    "been collected for them (see the limitation note above)."
                )

            st.markdown("**Interactive view**")
            st.iframe(
                _graph_html_cached(graph_conn, graph_version, graph_min_score, tuple(graph_statuses)),
                height=680,
            )

with tab_test:
    st.subheader("Test a domain manually")
    st.caption(
        "Run any domain through the detector instantly, without waiting for the firehose. "
        "Useful for exploring the logic or running a live demo."
    )

    brands, variant_index = _brands_and_index()
    domain_input = st.text_input("Domain to test", placeholder="e.g. bbva-secure.tk")
    check_dns = st.checkbox("Also resolve DNS (A/MX), takes a few seconds", value=False)

    if st.button("Test", type="primary"):
        candidate = domain_input.strip().lower()
        if not candidate:
            st.warning("Enter a domain.")
        else:
            match = evaluate_hostname(candidate, brands, variant_index)
            if match is None:
                st.success(f"'{candidate}' does not match any watched brand or its typical variants.")
            else:
                resolves_ip = has_mx = None
                if check_dns:
                    with st.spinner("Resolving DNS..."):
                        resolves_ip, has_mx = resolve_domain(registrable_domain(candidate))
                score = score_detection(match.technique, issuer_org=None, resolves_ip=resolves_ip, has_mx=has_mx)

                with st.container(border=True):
                    st.error(f"⚠️ Possible impersonation of **{match.brand}**")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Technique", match.technique)
                    c2.metric("Edit distance", match.distance)
                    with c3:
                        st.caption("Score")
                        severity_badge(score)
                    if check_dns:
                        st.write(f"Resolves to an IP: **{resolves_ip}** · Has MX: **{has_mx}**")
                    else:
                        st.caption("Partial score: no DNS data (check the box above to include it).")

    with st.expander("Watched brands and technique examples"):
        for b in brands:
            st.write(f"**{b.name}** ({b.category}): {b.domain}, aliases: {', '.join(b.aliases) or 'none'}")
        st.caption(
            "Try e.g.: 'micosoft.com' (omission), 'gooogle.com' (repetition), "
            "'bbva-secure.xyz' (keyword combo + cheap TLD), "
            "'santander.es.attacker-domain.com' (subdomain impersonation)."
        )

with tab_system:
    st.subheader("⚙️ System status")

    docker_state = _cached_docker_status()
    hstatus = _cached_hunt_status()
    running = hstatus["running"]

    with st.container(border=True):
        c1, c2 = st.columns(2)
        with c1:
            st.caption("certstream container (Docker)")
            st.badge(docker_state, color="green" if docker_state == "running" else "orange")
        with c2:
            st.caption("ct-hunter-hunt")
            st.badge("Running" if running else "Stopped", color="green" if running else "red",
                     icon="🟢" if running else "🔴")

        if hstatus.get("certs_seen") is not None:
            c3, c4, c5 = st.columns(3)
            c3.metric("Certificates processed", hstatus.get("certs_seen", 0))
            c4.metric("Hits so far", hstatus.get("hits", 0))
            if hstatus.get("started_at"):
                uptime_min = (hstatus.get("last_update", 0) - hstatus["started_at"]) / 60
                c5.metric("Minutes running", f"{uptime_min:.0f}")
            if hstatus.get("last_update"):
                st.caption(f"Last update: {datetime.fromtimestamp(hstatus['last_update']):%Y-%m-%d %H:%M:%S}")

        col_start, col_stop, col_refresh = st.columns(3)
        if col_start.button("▶️ Start ct-hunter-hunt", disabled=running):
            start_hunt()
            _refresh_status_cache()
            st.rerun()
        if col_stop.button("⏹️ Stop ct-hunter-hunt", disabled=not running):
            stop_hunt()
            _refresh_status_cache()
            st.rerun()
        if col_refresh.button("🔄 Refresh"):
            _refresh_status_cache()
            st.rerun()

    if docker_state not in ("running",):
        st.warning(
            "The `certstream` container is not running. Start it with:\n\n"
            "```\ndocker start certstream\n```\n"
            "or check `README.md` if you have not created it yet."
        )

    st.subheader("🧰 On-demand tasks")
    st.caption(
        "Run separately from the firehose on purpose (see docs/architecture.md); "
        "can take a few seconds to resolve DNS or call an external feed."
    )

    with st.container(border=True):
        col_enrich, col_reputation = st.columns(2)
        if col_enrich.button("🧬 Enrich pending (DNS + score)"):
            with st.spinner("Resolving DNS and computing scores..."):
                output = run_background_task(
                    "ct_hunter.scripts.enrich_pending", str(ENRICH_BATCH_LIMIT),
                    timeout=ENRICH_TIMEOUT_SECONDS,
                )
            st.code(output, language=None)
            st.cache_resource.clear()

        if col_reputation.button("🕵️ Reputation (ASN + AbuseIPDB) in bulk"):
            with st.spinner("Checking ASN/reputation for everything that resolves to an IP..."):
                output = run_background_task("ct_hunter.scripts.enrich_reputation", timeout=300)
            st.code(output, language=None)
            st.cache_resource.clear()

        st.caption(
            "Crosscheck against OpenPhish/URLscan/VirusTotal, capped at 15 candidates from here "
            "(VirusTotal is slow, ~16s per domain); uncapped: `uv run ct-hunter-crosscheck` in a terminal."
        )
        if st.button("🌐 Crosscheck OpenPhish + URLscan + VirusTotal (max 15)"):
            with st.spinner("Comparing against external sources (may take a few minutes)..."):
                output = run_background_task("ct_hunter.scripts.crosscheck", "15", timeout=360)
            st.code(output, language=None)
            st.cache_resource.clear()

        st.caption(
            "Moves 'New' domains straight to 'Monitoring' when the technique is an "
            "exact-match one (subdomain-impersonation, tld-swap, etc.), never fuzzy-edit-distance. "
            "New detections already get this at insert time; this is only for backlog."
        )
        if st.button("🏷️ Auto-triage backlog to Monitoring"):
            with st.spinner("Triaging..."):
                output = run_background_task("ct_hunter.scripts.auto_triage", timeout=60)
            st.code(output, language=None)
            st.cache_resource.clear()
