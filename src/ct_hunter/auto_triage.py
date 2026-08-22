"""Backfills `en_seguimiento` (monitoring) onto existing `nuevo` rows whose
technique is an exact-match one (see scoring.HIGH_CONFIDENCE_TECHNIQUES).

    uv run ct-hunter-triage

Only needed once per historical backlog; going forward, record_detection
already assigns this status at insert time (see storage/db.py). Never
touches `confirmado_malicioso` or `descartado` rows, and never sets
`confirmado_malicioso` itself, that still requires external corroboration
or a human (see docs/architecture.md).
"""

from __future__ import annotations

from ct_hunter.scoring import HIGH_CONFIDENCE_TECHNIQUES
from ct_hunter.storage.db import get_connection, init_db, update_status


def main() -> None:
    conn = get_connection()
    init_db(conn)

    placeholders = ",".join("?" * len(HIGH_CONFIDENCE_TECHNIQUES))
    rows = conn.execute(
        f"SELECT domain, technique FROM detections WHERE status = 'nuevo' AND technique IN ({placeholders})",
        tuple(HIGH_CONFIDENCE_TECHNIQUES),
    ).fetchall()
    print(f"{len(rows)} domain(s) to move from 'nuevo' to 'en_seguimiento'")

    for row in rows:
        update_status(
            conn, row["domain"], "en_seguimiento",
            notes=(
                f"Auto-triaged: '{row['technique']}' is an exact-match typosquat technique, "
                f"not coincidental fuzzy matching."
            ),
        )

    print("Done.")


if __name__ == "__main__":
    main()
