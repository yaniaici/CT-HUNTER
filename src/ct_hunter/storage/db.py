"""SQLite storage for detected suspicious domains.

Explicit SQL with the standard library's sqlite3, no ORM. For a project
this size (one table, simple queries) an ORM would add a layer of
indirection that buys nothing and makes it harder to explain exactly what
runs against the database.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from ct_hunter.detect.similarity import SimilarityMatch
from ct_hunter.ingest.certstream_client import CertEvent
from ct_hunter.scoring import HIGH_CONFIDENCE_TECHNIQUES

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "ct_hunter.db"

# Kept as internal identifiers (not translated) since they are already
# stored as real data in the database; see docs/architecture.md.
VALID_STATUSES = ("nuevo", "en_seguimiento", "confirmado_malicioso", "descartado")

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    domain              TEXT NOT NULL UNIQUE,
    registrable_domain  TEXT NOT NULL,
    brand               TEXT NOT NULL,
    technique           TEXT NOT NULL,
    edit_distance       INTEGER NOT NULL DEFAULT 0,
    issuer_org          TEXT,
    source_log          TEXT,
    first_seen_at       REAL NOT NULL,
    last_seen_at        REAL NOT NULL,
    cert_count          INTEGER NOT NULL DEFAULT 1,
    resolves_ip         INTEGER,
    has_mx              INTEGER,
    screenshot_path     TEXT,
    visual_hamming_distance INTEGER,
    ip_address          TEXT,
    asn                 TEXT,
    asn_org             TEXT,
    registrar           TEXT,
    nameservers         TEXT,
    external_intel      TEXT,
    score               REAL,
    status              TEXT NOT NULL DEFAULT 'nuevo'
                         CHECK (status IN ('nuevo', 'en_seguimiento', 'confirmado_malicioso', 'descartado')),
    notes               TEXT,
    updated_at          REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_detections_score ON detections(score);
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);
CREATE INDEX IF NOT EXISTS idx_detections_brand ON detections(brand);
-- Matches the dashboard's actual filter shape (WHERE score >= ? AND
-- status IN (...) ORDER BY ... last_seen_at DESC): the single-column
-- indexes above can only be used for one side of that query, this one
-- covers the combined filter.
CREATE INDEX IF NOT EXISTS idx_detections_status_score ON detections(status, score);
-- Used by _data_version()'s MAX(updated_at) cache-key signal.
CREATE INDEX IF NOT EXISTS idx_detections_updated_at ON detections(updated_at);
-- Used by the dashboard's main ORDER BY ... last_seen_at DESC sort.
CREATE INDEX IF NOT EXISTS idx_detections_last_seen_at ON detections(last_seen_at);
"""


def get_connection(path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    # check_same_thread=False: Streamlit caches this connection with
    # @st.cache_resource and reuses it across script reruns, which can
    # execute on different threads from Streamlit's internal pool. There
    # is no real concurrent write (Streamlit processes one rerun at a time
    # per session), so relaxing sqlite3's check here is safe.
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # hunt.py and the dashboard are two separate OS processes reading and
    # writing the same file concurrently. The default rollback journal
    # blocks readers while a write is in progress; WAL lets readers
    # proceed against the last committed snapshot instead, which matches
    # this access pattern (frequent small writes from hunt.py, frequent
    # reads from the dashboard).
    conn.execute("PRAGMA journal_mode = WAL")
    # NORMAL is the standard safe pairing with WAL: still fsyncs at
    # checkpoints, just not on every single commit. hunt.py commits once
    # per hit inside the async firehose loop (record_detection), so FULL
    # (the default) meant a fsync stall on every hit; the only tradeoff is
    # losing the last few not-yet-checkpointed transactions on an OS
    # crash/power loss, not on an application crash, which is acceptable
    # here.
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    # Migration for databases created before these columns existed:
    # SQLite has no portable "ADD COLUMN IF NOT EXISTS" across versions,
    # so this is attempted and the error is ignored if the column is
    # already there.
    for column_def in (
        "screenshot_path TEXT",
        "visual_hamming_distance INTEGER",
        "ip_address TEXT",
        "asn TEXT",
        "asn_org TEXT",
        "registrar TEXT",
        "nameservers TEXT",
        "external_intel TEXT",
    ):
        try:
            conn.execute(f"ALTER TABLE detections ADD COLUMN {column_def}")
        except sqlite3.OperationalError:
            pass  # column already exists
    # These indexes are created separately (not in SCHEMA) because on an
    # existing database these columns do not exist yet when SCHEMA above
    # runs; they only exist after the migration loop just above.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_asn ON detections(asn)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_registrar ON detections(registrar)")
    conn.commit()


def record_detection(
    conn: sqlite3.Connection,
    match: SimilarityMatch,
    event: CertEvent,
    hostname: str,
) -> None:
    """Inserts a new suspicious domain, or if it already existed (same
    domain reissuing a certificate) updates last_seen_at and bumps the
    counter.

    New rows start as `en_seguimiento` (monitoring) instead of `nuevo`
    when the technique is an exact-match one (see
    scoring.HIGH_CONFIDENCE_TECHNIQUES): the domain name itself is already
    deliberate typosquatting, whether or not the domain has any active
    infrastructure yet. Never auto-set to `confirmado_malicioso`, that
    still requires external corroboration or a human (see
    docs/architecture.md)."""
    now = time.time()
    initial_status = "en_seguimiento" if match.technique in HIGH_CONFIDENCE_TECHNIQUES else "nuevo"
    initial_notes = (
        f"Auto-triaged: '{match.technique}' is an exact-match typosquat technique, "
        f"not coincidental fuzzy matching."
        if initial_status == "en_seguimiento" else None
    )
    conn.execute(
        """
        INSERT INTO detections (
            domain, registrable_domain, brand, technique, edit_distance,
            issuer_org, source_log, first_seen_at, last_seen_at, updated_at,
            status, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            last_seen_at = excluded.last_seen_at,
            cert_count = cert_count + 1,
            updated_at = excluded.updated_at
        """,
        (
            hostname,
            match.candidate,
            match.brand,
            match.technique,
            match.distance,
            event.issuer_org,
            event.source_log,
            event.seen_at,
            event.seen_at,
            now,
            initial_status,
            initial_notes,
        ),
    )
    conn.commit()


def list_detections(
    conn: sqlite3.Connection,
    status: str | None = None,
    min_score: float | None = None,
) -> list[sqlite3.Row]:
    query = "SELECT * FROM detections WHERE 1=1"
    params: list[object] = []
    if status is not None:
        query += " AND status = ?"
        params.append(status)
    if min_score is not None:
        query += " AND score >= ?"
        params.append(min_score)
    query += " ORDER BY last_seen_at DESC"
    return conn.execute(query, params).fetchall()


def update_status(conn: sqlite3.Connection, domain: str, status: str, notes: str | None = None) -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status!r}, must be one of {VALID_STATUSES}")
    conn.execute(
        "UPDATE detections SET status = ?, notes = COALESCE(?, notes), updated_at = ? WHERE domain = ?",
        (status, notes, time.time(), domain),
    )
    conn.commit()


def update_score(
    conn: sqlite3.Connection,
    domain: str,
    score: float,
    resolves_ip: bool | None,
    has_mx: bool | None,
    screenshot_path: str | None = None,
    visual_hamming_distance: int | None = None,
) -> None:
    """screenshot_path / visual_hamming_distance are only overwritten if
    provided (COALESCE), so a call that only updates DNS does not wipe a
    screenshot captured earlier."""
    conn.execute(
        """
        UPDATE detections
        SET score = ?, resolves_ip = ?, has_mx = ?,
            screenshot_path = COALESCE(?, screenshot_path),
            visual_hamming_distance = COALESCE(?, visual_hamming_distance),
            updated_at = ?
        WHERE domain = ?
        """,
        (score, resolves_ip, has_mx, screenshot_path, visual_hamming_distance, time.time(), domain),
    )
    conn.commit()


def update_reputation(
    conn: sqlite3.Connection,
    domain: str,
    score: float,
    ip_address: str | None,
    asn: str | None,
    asn_org: str | None,
    external_intel_json: str | None,
) -> None:
    conn.execute(
        """
        UPDATE detections
        SET score = ?, ip_address = ?, asn = ?, asn_org = ?, external_intel = ?, updated_at = ?
        WHERE domain = ?
        """,
        (score, ip_address, asn, asn_org, external_intel_json, time.time(), domain),
    )
    conn.commit()


def update_whois(
    conn: sqlite3.Connection,
    domain: str,
    registrar: str | None,
    nameservers: list[str] | None,
) -> None:
    conn.execute(
        "UPDATE detections SET registrar = ?, nameservers = ?, updated_at = ? WHERE domain = ?",
        (registrar, ",".join(nameservers) if nameservers else None, time.time(), domain),
    )
    conn.commit()
