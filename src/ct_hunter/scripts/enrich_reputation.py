"""Enriches with external reputation (ASN, own infrastructure reuse,
AbuseIPDB) the detections that already resolve to an IP.

    uv run ct-hunter-reputation

Only processes detections with resolves_ip=1 (an IP is needed to query
ASN/AbuseIPDB) and asn IS NULL (skips anything already processed). The
reputation bonus is ADDED to the existing score, not a replacement for it.
See docs/architecture.md.

The DNS lookup and the two HTTP calls (ip-api.com, AbuseIPDB) per row are
run concurrently across a bounded thread pool, since they do not touch
the database; every sqlite3 read/write still happens one at a time on
the main thread as each result comes back, sqlite3 connections are not
safe to use concurrently from multiple threads. lookup_asn() rate-limits
itself internally (see reputation.py), so the worker count here only
needs to stay modest, not track the external quota directly.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ct_hunter.enrich.dns import get_first_ip
from ct_hunter.enrich.reputation import asn_reuse, check_abuseipdb, lookup_asn
from ct_hunter.scoring import MAX_SCORE, reputation_bonus
from ct_hunter.storage.db import get_connection, init_db, update_reputation

MAX_WORKERS = 6


def _fetch_reputation(domain: str, asn_cache: dict, asn_cache_lock: threading.Lock) -> dict:
    """Pure I/O (DNS + HTTP), no database access, safe to run in a worker
    thread. asn_cache is shared across the whole run so detections that
    resolve to the same IP (common on shared hosting) only hit
    ip-api.com once."""
    ip = get_first_ip(domain)
    if ip is None:
        return {"ip": None}

    with asn_cache_lock:
        cached = asn_cache.get(ip)
    asn_info = cached if cached is not None else lookup_asn(ip)
    with asn_cache_lock:
        asn_cache[ip] = asn_info

    abuse = check_abuseipdb(ip)
    return {"ip": ip, "asn_info": asn_info, "abuse": abuse}


def main() -> None:
    conn = get_connection()
    init_db(conn)

    pending = conn.execute(
        "SELECT * FROM detections WHERE resolves_ip = 1 AND asn IS NULL"
    ).fetchall()
    print(f"{len(pending)} detections with an IP pending reputation lookup")

    asn_cache: dict = {}
    asn_cache_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_row = {
            executor.submit(_fetch_reputation, row["registrable_domain"], asn_cache, asn_cache_lock): row
            for row in pending
        }
        for future in as_completed(future_to_row):
            row = future_to_row[future]
            result = future.result()
            ip = result["ip"]
            if ip is None:
                print(f"{row['domain']:40} no IP resolves right now, skipping")
                continue

            asn_info = result["asn_info"]
            asn = asn_info.get("asn")
            asn_org = asn_info.get("asn_org")
            abuse = result["abuse"]

            reused_in = asn_reuse(conn, asn, exclude_domain=row["domain"]) if asn else []

            bonus = reputation_bonus(
                asn_reuse_count=len(reused_in),
                urlscan_tags=None,  # see crosscheck.py for the URLscan/VT side
                virustotal_malicious_count=None,
                abuseipdb_score=abuse.get("abuse_score"),
            )
            new_score = min((row["score"] or 0) + bonus, MAX_SCORE)

            intel = {"ip": ip, "abuseipdb": abuse, "asn_reuse": [dict(r) for r in reused_in]}
            update_reputation(conn, row["domain"], new_score, ip, asn, asn_org, json.dumps(intel))

            reuse_note = f", ASN shared with {len(reused_in)} domain(s) already tracked" if reused_in else ""
            print(f"{row['domain']:40} ip={ip} asn={asn} ({asn_org}){reuse_note} -> score {new_score:.0f}")


if __name__ == "__main__":
    main()
