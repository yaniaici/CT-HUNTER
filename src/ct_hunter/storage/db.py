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
        "external_intel TEXT",
    ):
        try:
            conn.execute(f"ALTER TABLE detections ADD COLUMN {column_def}")
        except sqlite3.OperationalError:
            pass  # column already exists
    # This index is created separately (not in SCHEMA) because on an
    # existing database the 'asn' column does not exist yet when SCHEMA
    # above runs; it only exists after the migration loop just above.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_asn ON detections(asn)")
    conn.commit()


def record_detection(
    conn: sqlite3.Connection,
    match: SimilarityMatch,
    event: CertEvent,
    hostname: str,
) -> None:
    """Inserts a new suspicious domain, or if it already existed (same
    domain reissuing a certificate) updates last_seen_at and bumps the
    counter."""
    now = time.time()
    conn.execute(
        """
        INSERT INTO detections (
            domain, registrable_domain, brand, technique, edit_distance,
            issuer_org, source_log, first_seen_at, last_seen_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
