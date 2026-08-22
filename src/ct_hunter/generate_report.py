"""Generates the report draft for a confirmed case.

    uv run ct-hunter-report <domain>

Writes reports/YYYY-MM-DD-domain.md with the timeline and signals already
stored in the database. The interpretation still needs to be added by hand.
"""

from __future__ import annotations

import sys

from ct_hunter.report import write_report
from ct_hunter.storage.db import get_connection


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: uv run ct-hunter-report <domain>", file=sys.stderr)
        sys.exit(1)

    domain = sys.argv[1]
    conn = get_connection()
    row = conn.execute("SELECT * FROM detections WHERE domain = ?", (domain,)).fetchone()
    if row is None:
        print(f"'{domain}' is not in the database.", file=sys.stderr)
        sys.exit(1)

    path = write_report(row)
    print(f"Report written to {path}")


if __name__ == "__main__":
    main()
