"""Re-checks every non-discarded detection against the CURRENT detection
logic (brands.yaml + detect/similarity.py as they are right now, not as
they were when each row was first recorded).

    uv run ct-hunter-reevaluate [limit]

record_detection only ever inserts or bumps last_seen_at/cert_count, it
never re-applies today's logic to a row recorded under yesterday's
thresholds/whitelist/keyword list. That leaves "fossilized" false
positives sitting in the backlog forever once a detection bug is fixed
going forward but not retroactively (found via 'boca.es', a BBVA match
at similarity ratio 0.714, below the MIN_SIMILARITY_RATIO=0.80 safeguard
added after it was recorded; and via the santander.com.mx/br/uy,
bbva.com.co/mx, dhl.com.au/tr, amazon.dev whitelist gaps, all fixed by
hand this same way before this script existed). This is that fix, made
reusable instead of a one-off query every time.

Cheap: pure in-memory comparison, no network, ~5000 rows in ~0.1s.

Never touches a `confirmado_malicioso` row automatically, even if it no
longer matches, that status is human-owned (see docs/architecture.md,
"automation boundary"); those are listed at the end for manual review
instead.
"""

from __future__ import annotations

import datetime
import sys
import time

from ct_hunter.brands import load_brands
from ct_hunter.detect.similarity import (
    build_tld_swap_labels,
    build_variant_index,
    build_whitelist,
    evaluate_hostname,
)
from ct_hunter.storage.db import get_connection, init_db, update_status


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

    conn = get_connection()
    init_db(conn)

    brands = load_brands()
    variant_index = build_variant_index(brands)
    whitelist = build_whitelist(brands)
    tld_swap_labels = build_tld_swap_labels(brands)

    query = "SELECT id, domain, brand, technique, status FROM detections WHERE status != 'descartado'"
    if limit is not None:
        query += f" LIMIT {limit}"
    rows = conn.execute(query).fetchall()
    print(f"{len(rows)} non-discarded row(s) to re-check against current logic")

    start = time.monotonic()
    today = datetime.date.today().isoformat()
    discarded = 0
    needs_review = []

    for row in rows:
        if evaluate_hostname(row["domain"], brands, variant_index, whitelist, tld_swap_labels) is not None:
            continue  # still matches, nothing to do

        if row["status"] == "confirmado_malicioso":
            needs_review.append(row)
            continue

        update_status(
            conn, row["domain"], "descartado",
            notes=(
                f"Discarded {today}: no longer matches current detection logic "
                f"(was {row['technique']} for {row['brand']}), see ct-hunter-reevaluate."
            ),
        )
        discarded += 1

    elapsed = time.monotonic() - start
    print(f"Checked in {elapsed:.2f}s")
    print(f"{discarded} row(s) discarded (no longer match, not previously confirmed)")

    if needs_review:
        print(
            f"\n{len(needs_review)} confirmado_malicioso row(s) no longer match current logic, "
            f"left untouched, review by hand:"
        )
        for row in needs_review:
            print(f"  {row['domain']} ({row['brand']}, was {row['technique']})")


if __name__ == "__main__":
    main()
