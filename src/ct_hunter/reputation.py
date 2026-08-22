"""Enrichment from free external reputation sources.

Two categories, with different implications for the verdict (see
docs/architecture.md):

1. **External corroboration** (URLscan, VirusTotal): if an independent
   third party already determined a domain is malicious, that is a
   verifiable fact, not our own heuristic's opinion. Eligible for
   auto-confirmation (see crosscheck.py), the same way OpenPhish already
   was.
2. **Context signals** (ASN reuse within our own database, IP reputation
   on AbuseIPDB): these add to the score for prioritization but never
   decide a verdict on their own. A cheap ASN hosts both malicious
   infrastructure and legitimate sites.

URLscan.io does not require an API key to search (always used). VirusTotal
and AbuseIPDB need their own free key; if one is not set in `.env`, those
checks skip cleanly instead of failing.
"""

from __future__ import annotations

import os
import sqlite3

import requests
from dotenv import load_dotenv

load_dotenv()

REQUEST_TIMEOUT_SECONDS = 10

# Minimum number of engines flagging a domain before a VirusTotal verdict
# counts as a real confirmation instead of noise from a single vendor.
VIRUSTOTAL_MALICIOUS_THRESHOLD = 3

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")


def lookup_asn(ip: str) -> dict:
    """ASN/organization for an IP. Free, no API key (ip-api.com, ~45 req/min)."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,as,asname,isp,org,query"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        return {"error": str(exc)}

    if data.get("status") != "success":
        return {"error": "ip-api.com could not resolve the IP"}

    return {"asn": data.get("as"), "asn_org": data.get("asname") or data.get("isp")}


def check_urlscan(domain: str) -> dict:
    """Public URLscan.io search, no API key required.

    Does not always yield a clean verdict (verdicts.overall.malicious can
    come back empty even on scans tagged as phishing). Returned as-is;
    `malicious_verdict` is only True when URLscan states it explicitly.
    """
    try:
        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.domain:"{domain}"', "size": 5},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        return {"error": str(exc)}

    results = data.get("results", [])
    if not results:
        return {"scanned": False, "count": 0}

    tags = sorted({tag for r in results for tag in r.get("task", {}).get("tags", [])})
    malicious_verdict = None
    for r in results[:1]:  # only the most recent scan, to avoid burning the /result/ quota
        try:
            detail = requests.get(r["result"], timeout=REQUEST_TIMEOUT_SECONDS).json()
            malicious_verdict = detail.get("verdicts", {}).get("overall", {}).get("malicious")
        except (requests.RequestException, ValueError, KeyError):
            pass

    return {
        "scanned": True,
        "count": data.get("total", len(results)),
        "tags": tags,
        "malicious_verdict": malicious_verdict,
        "latest_scan_url": f"https://urlscan.io/domain/{domain}",
    }


def check_virustotal(domain: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"configured": False}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code == 404:
            return {"configured": True, "found": False}
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        return {"configured": True, "error": str(exc)}

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    return {
        "configured": True,
        "found": True,
        "malicious_count": malicious_count,
        "total_engines": sum(stats.values()) if stats else 0,
        # A single flagging engine is almost always noise: single-vendor
        # false positives are common on VT (google.com came back with
        # 1/91 engines flagging it). A minimum is required before this
        # counts as a real confirmation, see VIRUSTOTAL_MALICIOUS_THRESHOLD.
        "malicious": malicious_count >= VIRUSTOTAL_MALICIOUS_THRESHOLD,
    }


def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"configured": False}
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        return {"configured": True, "error": str(exc)}

    score = data.get("data", {}).get("abuseConfidenceScore")
    return {"configured": True, "abuse_score": score}


def asn_reuse(conn: sqlite3.Connection, asn: str, exclude_domain: str) -> list[sqlite3.Row]:
    """Other domains in OUR database that share this ASN and are already
    being tracked or confirmed: infrastructure reuse detected from our own
    data, without depending on a third party."""
    if not asn:
        return []
    return conn.execute(
        """
        SELECT domain, status FROM detections
        WHERE asn = ? AND domain != ? AND status IN ('en_seguimiento', 'confirmado_malicioso')
        """,
        (asn, exclude_domain),
    ).fetchall()
