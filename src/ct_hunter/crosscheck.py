"""Compares detections against independent external sources. A match is
external, dated corroboration that a domain is real, and is eligible to
auto-confirm it (see docs/architecture.md, "automation boundary": this is
different from letting our own score decide on its own).

    uv run ct-hunter-crosscheck [limit]

Three sources, cheapest to most expensive:
1. OpenPhish (full feed, single fetch) against everything not yet confirmed.
2. URLscan.io (per domain, no API key) only against candidates whose score
   is already high; there is no point spending time on noise.
3. VirusTotal (per domain, optional API key, ~4 req/min on the free tier),
   same filter, only if VIRUSTOTAL_API_KEY is set in .env.

An optional argument caps how many URLscan/VirusTotal candidates get
processed (useful for launching this from the dashboard without blocking
it for minutes); with no argument it processes every candidate, meant for
running from a terminal. OpenPhish is always checked in full since it is a
single, cheap fetch.
"""

from __future__ import annotations

import sys
import time

from ct_hunter.detect.similarity import registrable_domain
from ct_hunter.reputation import VIRUSTOTAL_API_KEY, check_urlscan, check_virustotal
from ct_hunter.storage.db import get_connection, init_db, update_status
from ct_hunter.threat_intel import fetch_openphish_domains

MIN_SCORE_FOR_EXPENSIVE_CHECKS = 50
VIRUSTOTAL_SLEEP_SECONDS = 16  # free tier is roughly 4 req/min


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

    conn = get_connection()
    init_db(conn)
    today = time.strftime("%Y-%m-%d")
    confirmed = 0

    feed_domains = fetch_openphish_domains()
    print(f"{len(feed_domains)} domains in the OpenPhish community feed right now")
    rows = conn.execute(
        "SELECT domain, registrable_domain FROM detections WHERE status != 'confirmado_malicioso'"
    ).fetchall()
    for row in rows:
        reg = row["registrable_domain"] or registrable_domain(row["domain"])
        if reg in feed_domains:
            confirmed += 1
            update_status(
                conn, row["domain"], "confirmado_malicioso",
                notes=f"Confirmed by the OpenPhish community feed, checked {today}.",
            )
            print(f"CONFIRMED (OpenPhish): {row['domain']}")
    print(f"{confirmed} OpenPhish confirmation(s), out of {len(rows)} checked")

    query = (
        "SELECT domain, registrable_domain FROM detections "
        "WHERE status != 'confirmado_malicioso' AND score >= ? ORDER BY score DESC"
    )
    if limit is not None:
        query += f" LIMIT {limit}"
    candidates = conn.execute(query, (MIN_SCORE_FOR_EXPENSIVE_CHECKS,)).fetchall()
    print(
        f"\n{len(candidates)} candidates with score >= {MIN_SCORE_FOR_EXPENSIVE_CHECKS} "
        f"for URLscan/VirusTotal" + (f" (limit {limit})" if limit else "")
    )

    for row in candidates:
        reg = row["registrable_domain"] or registrable_domain(row["domain"])

        urlscan_result = check_urlscan(reg)
        if urlscan_result.get("malicious_verdict") is True:
            confirmed += 1
            update_status(
                conn, row["domain"], "confirmado_malicioso",
                notes=f"Confirmed by URLscan.io (explicit malicious verdict), checked {today}.",
            )
            print(f"CONFIRMED (URLscan): {row['domain']}")
            continue  # already confirmed, no need to spend VirusTotal quota too

        if VIRUSTOTAL_API_KEY:
            vt_result = check_virustotal(reg)
            if vt_result.get("malicious"):
                confirmed += 1
                update_status(
                    conn, row["domain"], "confirmado_malicioso",
                    notes=(
                        f"Confirmed by VirusTotal "
                        f"({vt_result['malicious_count']}/{vt_result['total_engines']} engines), "
                        f"checked {today}."
                    ),
                )
                print(f"CONFIRMED (VirusTotal): {row['domain']}")
            time.sleep(VIRUSTOTAL_SLEEP_SECONDS)

    if not VIRUSTOTAL_API_KEY:
        print("\n(VIRUSTOTAL_API_KEY not set in .env, VirusTotal was skipped, URLscan only)")

    print(f"\n{confirmed} new confirmation(s) in total")


if __name__ == "__main__":
    main()
