"""Enriches (DNS) and scores pending detections in the database.

    uv run ct-hunter-enrich

Runs once and exits. Meant to be launched by hand or from cron, not inside
the firehose loop (see docs/architecture.md for why ingestion and
enrichment are kept separate).
"""

from __future__ import annotations

from ct_hunter.enrich import resolve_domain
from ct_hunter.scoring import score_detection
from ct_hunter.storage.db import get_connection, init_db, update_score


def main() -> None:
    conn = get_connection()
    init_db(conn)

    pending = conn.execute("SELECT * FROM detections WHERE score IS NULL").fetchall()
    print(f"{len(pending)} detections pending enrichment")

    for row in pending:
        resolves_ip, has_mx = resolve_domain(row["domain"])
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
