"""Bulk WHOIS enrichment (registrar + nameservers) for the infrastructure
correlation graph.

    uv run ct-hunter-whois [limit]

Only processes candidates with score >= MIN_SCORE_FOR_WHOIS and
registrar IS NULL. WHOIS servers are not built for high query volume and
some rate-limit aggressively, so this stays capped to already-interesting
candidates and sleeps between lookups, same reasoning as the VirusTotal
pacing in crosscheck.py.
"""

from __future__ import annotations

import sys
import time

from ct_hunter.detect.similarity import DYNAMIC_DNS_SUFFIXES
from ct_hunter.enrich.osint import whois_lookup
from ct_hunter.scoring import MAX_SCORE, domain_age_bonus
from ct_hunter.storage.db import get_connection, init_db, update_whois

MIN_SCORE_FOR_WHOIS = 50
WHOIS_SLEEP_SECONDS = 3


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None

    conn = get_connection()
    init_db(conn)

    query = (
        "SELECT domain, registrable_domain, score FROM detections "
        "WHERE registrar IS NULL AND score >= ? ORDER BY score DESC"
    )
    if limit is not None:
        query += f" LIMIT {limit}"
    candidates = conn.execute(query, (MIN_SCORE_FOR_WHOIS,)).fetchall()
    print(f"{len(candidates)} candidates with score >= {MIN_SCORE_FOR_WHOIS} pending WHOIS lookup")

    for row in candidates:
        target = row["registrable_domain"] or row["domain"]

        if target in DYNAMIC_DNS_SUFFIXES:
            # A shared wildcard-DNS provider (see DYNAMIC_DNS_SUFFIXES):
            # WHOIS on it only ever describes the provider itself
            # (registered long ago), never the attacker behind this
            # specific subdomain, so a real lookup would just waste a
            # rate-limited query and produce a misleading fresh-domain
            # bonus of 0. Marked as handled (registrar set) so the
            # `registrar IS NULL` filter above does not retry it forever.
            update_whois(conn, row["domain"], "(dynamic-dns provider, WHOIS skipped)", None, None, row["score"])
            print(f"{row['domain']:45} skipped, WHOIS meaningless for dynamic-DNS provider '{target}'")
            continue

        info = whois_lookup(target)
        if "error" in info:
            print(f"{row['domain']:45} WHOIS failed: {info['error']}")
        else:
            bonus = domain_age_bonus(info.get("creation_date_ts"))
            new_score = min((row["score"] or 0) + bonus, MAX_SCORE)
            update_whois(
                conn, row["domain"], info.get("registrar"), info.get("nameservers"),
                info.get("creation_date_ts"), new_score,
            )
            ns_note = f", {len(info['nameservers'])} nameserver(s)" if info.get("nameservers") else ""
            age_note = f", +{bonus} fresh-domain bonus" if bonus else ""
            print(f"{row['domain']:45} registrar={info.get('registrar')}{ns_note}{age_note}")
        time.sleep(WHOIS_SLEEP_SECONDS)


if __name__ == "__main__":
    main()
