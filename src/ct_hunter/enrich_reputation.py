"""Enriches with external reputation (ASN, own infrastructure reuse,
AbuseIPDB) the detections that already resolve to an IP.

    uv run ct-hunter-reputation

Only processes detections with resolves_ip=1 (an IP is needed to query
ASN/AbuseIPDB) and asn IS NULL (skips anything already processed). The
reputation bonus is ADDED to the existing score, not a replacement for it.
See docs/architecture.md.
"""

from __future__ import annotations

import json

from ct_hunter.enrich import get_first_ip
from ct_hunter.reputation import asn_reuse, check_abuseipdb, lookup_asn
from ct_hunter.scoring import MAX_SCORE, reputation_bonus
from ct_hunter.storage.db import get_connection, init_db, update_reputation


def main() -> None:
    conn = get_connection()
    init_db(conn)

    pending = conn.execute(
        "SELECT * FROM detections WHERE resolves_ip = 1 AND asn IS NULL"
    ).fetchall()
    print(f"{len(pending)} detections with an IP pending reputation lookup")

    for row in pending:
        ip = get_first_ip(row["registrable_domain"])
        if ip is None:
            print(f"{row['domain']:40} no IP resolves right now, skipping")
            continue

        asn_info = lookup_asn(ip)
        asn = asn_info.get("asn")
        asn_org = asn_info.get("asn_org")

        reused_in = asn_reuse(conn, asn, exclude_domain=row["domain"]) if asn else []
        abuse = check_abuseipdb(ip)

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
