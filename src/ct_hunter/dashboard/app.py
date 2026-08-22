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
from datetime import datetime

import pandas as pd
import streamlit as st

from ct_hunter.brands import load_brands
from ct_hunter.detect.similarity import build_variant_index, evaluate_hostname, registrable_domain
from ct_hunter.enrich import get_first_ip, resolve_domain
from ct_hunter.osint import external_links, http_probe, whois_lookup
from ct_hunter.process_control import PROJECT_ROOT, docker_status, hunt_status, start_hunt, stop_hunt
from ct_hunter.report import write_report
from ct_hunter.reputation import VIRUSTOTAL_API_KEY, asn_reuse, check_abuseipdb, check_urlscan, lookup_asn
from ct_hunter.scoring import MAX_SCORE, reputation_bonus, score_detection
from ct_hunter.storage.db import VALID_STATUSES, get_connection, init_db, update_reputation, update_score, update_status
from ct_hunter.visual import VISUAL_SIMILARITY_THRESHOLD, compare_visual

st.set_page_config(page_title="CT Hunter", page_icon="🎣", layout="wide")

LIST_COLUMNS = ["domain", "brand", "technique", "score", "status"]
STATUS_BADGE = {
    "nuevo": "🆕", "en_seguimiento": "👀",
    "confirmado_malicioso": "🚨", "descartado": "✅",
}
# Internal status values are kept in Spanish (see docs/architecture.md,
# they are already stored as data in the database); this maps them to the
# English labels shown in the UI.
STATUS_LABELS = {
    "nuevo": "New",
    "en_seguimiento": "Monitoring",
    "confirmado_malicioso": "Confirmed malicious",
    "descartado": "Discarded",
}


@st.cache_resource
def _connection():
    conn = get_connection()
    init_db(conn)
    return conn


@st.cache_resource
def _brands_and_index():
    brands = load_brands()
    return brands, build_variant_index(brands)


def _load(conn) -> pd.DataFrame:
    rows = conn.execute(
        "SELECT * FROM detections ORDER BY score IS NULL, score DESC, last_seen_at DESC"
    ).fetchall()
    df = pd.DataFrame([dict(r) for r in rows])
    for col in ("first_seen_at", "last_seen_at", "updated_at"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], unit="s")
    return df


st.title("🎣 CT Hunter")
st.caption("Suspicious domains detected in Certificate Transparency logs, before they are used.")

tab_detections, tab_test, tab_system = st.tabs(["📋 Detections", "🔍 Test a domain", "⚙️ System"])

with tab_detections:
    conn = _connection()
    df = _load(conn)

    if df.empty:
        st.info(
            "No detections yet. Go to the **System** tab to start "
            "`ct-hunter-hunt` and start watching the firehose."
        )
    else:
        with st.sidebar:
            st.header("Filters")
            brands_present = sorted(df["brand"].unique())
            brand_filter = st.multiselect("Brand", brands_present, default=brands_present)
            status_filter = st.multiselect(
                "Status", list(VALID_STATUSES), default=list(VALID_STATUSES),
                format_func=lambda s: STATUS_LABELS.get(s, s),
            )
            min_score = st.slider("Minimum score", 0, 100, 0)

        filtered = df[
            df["brand"].isin(brand_filter)
            & df["status"].isin(status_filter)
            & (df["score"].fillna(0) >= min_score)
        ].reset_index(drop=True)

        col1, col2, col3 = st.columns(3)
        col1.metric("Detections (current filter)", len(filtered))
        col2.metric("Total in database", len(df))
        col3.metric("Confirmed malicious", int((df["status"] == "confirmado_malicioso").sum()))

        list_col, detail_col = st.columns([2, 3])

        with list_col:
            st.subheader("Detections")
            st.caption("Select a row to investigate it in the panel on the right.")
            selection = st.dataframe(
                filtered[LIST_COLUMNS],
                column_config={"score": st.column_config.NumberColumn("Score", format="%.0f")},
                hide_index=True,
                width="stretch",
                height=560,
                on_select="rerun",
                selection_mode="single-row",
                key="detections_table",
            )
            selected_rows = selection.selection.rows if selection and selection.selection else []

        with detail_col:
            st.subheader("Detection context")

            if not selected_rows:
                st.info("⬅️ Select a domain from the list to see its context and set a verdict.")
            else:
                row = filtered.iloc[selected_rows[0]]
                domain = row["domain"]
                reg_domain = row["registrable_domain"] or domain

                st.markdown(f"#### `{domain}`")
                st.caption(f"{STATUS_BADGE.get(row['status'], '')} current status: **{STATUS_LABELS.get(row['status'], row['status'])}**")

                d1, d2, d3 = st.columns(3)
                d1.metric("Brand", row["brand"])
                d2.metric("Technique", row["technique"])
                d3.metric("Score", f"{row['score']:.0f}" if pd.notna(row["score"]) else "not scored")
                st.caption(
                    f"First seen: {row['first_seen_at']:%Y-%m-%d %H:%M} · "
                    f"last seen: {row['last_seen_at']:%Y-%m-%d %H:%M} · "
                    f"{row['cert_count']} certificate(s) · issuer: {row['issuer_org']} · "
                    f"edit distance: {row['edit_distance']}"
                )

                st.markdown("**DNS enrichment**")
                e1, e2, e3 = st.columns([1, 1, 2])
                e1.write(f"Resolves to an IP: **{row['resolves_ip']}**")
                e2.write(f"Has MX: **{row['has_mx']}**")
                if e3.button("🔎 Resolve DNS now", key=f"dns_{domain}"):
                    with st.spinner("Resolving..."):
                        resolves_ip, has_mx = resolve_domain(reg_domain)
                        new_score = score_detection(row["technique"], row["issuer_org"], resolves_ip, has_mx)
                        update_score(conn, domain, new_score, resolves_ip, has_mx)
                    st.cache_resource.clear()
                    st.rerun()

                st.markdown("**Investigation**")
                inv1, inv2 = st.columns(2)
                if inv1.button("📋 Run WHOIS", key=f"whois_btn_{domain}"):
                    with st.spinner("Querying WHOIS..."):
                        st.session_state[f"whois_result_{domain}"] = whois_lookup(reg_domain)
                if inv2.button("🌐 Check the website", key=f"http_btn_{domain}"):
                    with st.spinner("Connecting..."):
                        st.session_state[f"http_result_{domain}"] = http_probe(reg_domain)

                whois_result = st.session_state.get(f"whois_result_{domain}")
                if whois_result:
                    if "error" in whois_result:
                        st.warning(f"WHOIS lookup failed: {whois_result['error']}")
                    else:
                        st.write(
                            f"Created: **{whois_result['creation_date']}** · "
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

                st.markdown("**Visual comparison**")
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

                st.markdown("**External reputation**")
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

                if pd.notna(row["notes"]) and row["notes"]:
                    st.markdown("**Previous notes**")
                    st.info(row["notes"])

                st.markdown("**Verdict**")
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
                    st.markdown("**Case report**")
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

                st.error(f"⚠️ Possible impersonation of **{match.brand}**")
                c1, c2, c3 = st.columns(3)
                c1.metric("Technique", match.technique)
                c2.metric("Edit distance", match.distance)
                c3.metric("Score", f"{score:.0f}")
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
    st.subheader("System status")

    docker_state = docker_status()
    hstatus = hunt_status()
    running = hstatus["running"]

    c1, c2 = st.columns(2)
    c1.metric("certstream container (Docker)", docker_state)
    c2.metric("ct-hunter-hunt", "🟢 running" if running else "🔴 stopped")

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
        st.rerun()
    if col_stop.button("⏹️ Stop ct-hunter-hunt", disabled=not running):
        stop_hunt()
        st.rerun()
    if col_refresh.button("🔄 Refresh"):
        st.rerun()

    if docker_state not in ("running",):
        st.warning(
            "The `certstream` container is not running. Start it with:\n\n"
            "```\ndocker start certstream\n```\n"
            "or check `README.md` if you have not created it yet."
        )

    st.divider()
    st.subheader("On-demand tasks")
    st.caption(
        "Run separately from the firehose on purpose (see docs/architecture.md); "
        "can take a few seconds to resolve DNS or call an external feed."
    )

    col_enrich, col_reputation = st.columns(2)
    if col_enrich.button("🧬 Enrich pending (DNS + score)"):
        with st.spinner("Resolving DNS and computing scores..."):
            result = subprocess.run(
                [sys.executable, "-m", "ct_hunter.enrich_pending"],
                cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=180,
            )
        st.code(result.stdout or result.stderr, language=None)
        st.cache_resource.clear()

    if col_reputation.button("🕵️ Reputation (ASN + AbuseIPDB) in bulk"):
        with st.spinner("Checking ASN/reputation for everything that resolves to an IP..."):
            result = subprocess.run(
                [sys.executable, "-m", "ct_hunter.enrich_reputation"],
                cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=300,
            )
        st.code(result.stdout or result.stderr, language=None)
        st.cache_resource.clear()

    st.caption(
        "Crosscheck against OpenPhish/URLscan/VirusTotal, capped at 15 candidates from here "
        "(VirusTotal is slow, ~16s per domain); uncapped: `uv run ct-hunter-crosscheck` in a terminal."
    )
    if st.button("🌐 Crosscheck OpenPhish + URLscan + VirusTotal (max 15)"):
        with st.spinner("Comparing against external sources (may take a few minutes)..."):
            result = subprocess.run(
                [sys.executable, "-m", "ct_hunter.crosscheck", "15"],
                cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=360,
            )
        st.code(result.stdout or result.stderr, language=None)
        st.cache_resource.clear()
