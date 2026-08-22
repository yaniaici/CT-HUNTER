"""Generates a case report draft from what is already in the database:
dates, technical signals, investigation notes.

Deliberately does NOT write the interpretation (why the case matters, what
it shows) since that has to be decided and written by whoever did the
triage. This module only saves the mechanical work of copying data by hand.
"""

from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "reports"

# Internal status values stay in Spanish in the database (see
# docs/architecture.md); this maps them to English labels for display.
STATUS_LABELS = {
    "nuevo": "new",
    "en_seguimiento": "monitoring",
    "confirmado_malicioso": "confirmed malicious",
    "descartado": "discarded",
}


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")


def report_path_for(domain: str, confirmed_at: float) -> Path:
    date_str = time.strftime("%Y-%m-%d", time.localtime(confirmed_at))
    return REPORTS_DIR / f"{date_str}-{_slug(domain)}.md"


def generate_report_markdown(row: sqlite3.Row) -> str:
    first_seen = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(row["first_seen_at"]))
    last_seen = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(row["last_seen_at"]))
    confirmed_at = row["updated_at"]
    confirmed_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(confirmed_at))
    generated_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

    gap_days = (confirmed_at - row["first_seen_at"]) / 86400
    status_label = STATUS_LABELS.get(row["status"], row["status"])

    return f"""# Case: {row["domain"]}

**Impersonated brand:** {row["brand"]}
**Detection technique:** {row["technique"]} (edit distance: {row["edit_distance"]})
**Risk score:** {row["score"]}
**Status:** {status_label}

## Timeline

- **{first_seen}**: certificate first seen in CT logs (issuer: {row["issuer_org"]}, log: {row["source_log"]})
- **{last_seen}**: last seen ({row["cert_count"]} certificate(s) total)
- **{confirmed_str}**: marked as `{status_label}`

**Detection to confirmation window: {gap_days:.1f} days**
(this is the actual lead time gained by watching CT logs instead of
finding out some other way)

## Technical signals

- Resolves to an IP: {bool(row["resolves_ip"]) if row["resolves_ip"] is not None else "not checked"}
- Has an MX record: {bool(row["has_mx"]) if row["has_mx"] is not None else "not checked"}
- Registrable domain: `{row["registrable_domain"]}`

## Evidence and investigation notes

{row["notes"] or "_(no notes recorded)_"}

## Interpretation

_(fill in by hand: why this case is interesting, what makes it stand out,
what it shows. This part is not auto-generated.)_

---
*Draft generated automatically on {generated_str} by ct-hunter from
`data/ct_hunter.db`. The timeline data can be verified against that
database.*
"""


def write_report(row: sqlite3.Row) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = report_path_for(row["domain"], row["updated_at"])
    path.write_text(generate_report_markdown(row))
    return path
