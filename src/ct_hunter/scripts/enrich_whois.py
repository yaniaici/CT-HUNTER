"""Bulk WHOIS enrichment (registrar + nameservers) for the infrastructure
correlation graph.

    uv run ct-hunter-whois [limit]

Only processes candidates with score >= MIN_SCORE_FOR_WHOIS and
registrar IS NULL. WHOIS servers are not built for high query volume and
some rate-limit aggressively, so this stays capped to already-interesting
candidates and sleeps between lookups, same reasoning as the VirusTotal
pacing in crosscheck.py.
"""

from __future__ import annotations

import sys
import time

from ct_hunter.enrich.osint import whois_lookup
from ct_hunter.storage.db import get_connection, init_db, update_whois

MIN_SCORE_FOR_WHOIS = 50
WHOIS_SLEEP_SECONDS = 3


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

    conn = get_connection()
    init_db(conn)

    query = (
        "SELECT domain, registrable_domain FROM detections "
        "WHERE registrar IS NULL AND score >= ? ORDER BY score DESC"
    )
    if limit is not None:
        query += f" LIMIT {limit}"
    candidates = conn.execute(query, (MIN_SCORE_FOR_WHOIS,)).fetchall()
    print(f"{len(candidates)} candidates with score >= {MIN_SCORE_FOR_WHOIS} pending WHOIS lookup")

    for row in candidates:
        target = row["registrable_domain"] or row["domain"]
        info = whois_lookup(target)
        if "error" in info:
            print(f"{row['domain']:45} WHOIS failed: {info['error']}")
        else:
            update_whois(conn, row["domain"], info.get("registrar"), info.get("nameservers"))
            ns_note = f", {len(info['nameservers'])} nameserver(s)" if info.get("nameservers") else ""
            print(f"{row['domain']:45} registrar={info.get('registrar')}{ns_note}")
        time.sleep(WHOIS_SLEEP_SECONDS)


if __name__ == "__main__":
    main()
