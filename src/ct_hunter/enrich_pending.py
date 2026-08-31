"""Enriches (DNS) and scores pending detections in the database.

    uv run ct-hunter-enrich [limit]

Runs once and exits. Meant to be launched by hand or from cron, not inside
the firehose loop (see docs/architecture.md for why ingestion and
enrichment are kept separate).

DNS resolution for one domain can take up to a few seconds if its
nameservers are slow or unresponsive rather than a clean NXDOMAIN (see
resolve_domain in enrich.py). This resolves a bounded number of domains
concurrently instead of one at a time; dnspython's resolve() has no
shared mutable state to protect here (no cache is configured on the
default resolver), and DNS resolution against arbitrary domains is not
subject to a shared external rate limit the way the reputation lookups
in enrich_reputation.py are, so a larger worker count is safe. Database
writes still happen one at a time on the main thread as each result
comes back, never concurrently. An optional [limit] argument caps how
many rows get processed in one run, same convention as crosscheck.py,
useful when launching this from the dashboard under a subprocess
timeout.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from ct_hunter.enrich import resolve_domain
from ct_hunter.scoring import score_detection
from ct_hunter.storage.db import get_connection, init_db, update_score

MAX_WORKERS = 10


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

    conn = get_connection()
    init_db(conn)

    query = "SELECT * FROM detections WHERE score IS NULL"
    if limit is not None:
        query += f" LIMIT {limit}"
    pending = conn.execute(query).fetchall()
    print(f"{len(pending)} detections pending enrichment" + (f" (limit {limit})" if limit else ""))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_row = {executor.submit(resolve_domain, row["domain"]): row for row in pending}
        for future in as_completed(future_to_row):
            row = future_to_row[future]
            resolves_ip, has_mx = future.result()
            score = score_detection(
                technique=row["technique"],
                issuer_org=row["issuer_org"],
                resolves_ip=resolves_ip,
                has_mx=has_mx,
            )
            update_score(conn, row["domain"], score, resolves_ip, has_mx)
            print(
                f"{row['domain']:40} score={score:5.1f}  "
                f"resolves_ip={resolves_ip}  mx={has_mx}"
            )


if __name__ == "__main__":
    main()
