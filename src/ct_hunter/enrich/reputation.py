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
import threading
import time
from collections import deque

import requests
from dotenv import load_dotenv

load_dotenv()

REQUEST_TIMEOUT_SECONDS = 10

# Minimum number of engines flagging a domain before a VirusTotal verdict
# counts as a real confirmation instead of noise from a single vendor.
VIRUSTOTAL_MALICIOUS_THRESHOLD = 3

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

# One shared session for connection pooling/keep-alive across every call
# in this module, instead of a fresh TCP/TLS handshake per request.
# requests.Session is documented as thread-safe for concurrent requests
# (used from enrich_reputation.py's thread pool).
_session = requests.Session()


class _RateLimiter:
    """Sliding-window limiter shared across threads: blocks the calling
    thread until a call is allowed under max_calls per period_seconds.
    Used to keep concurrent lookups collectively under a free-tier API
    quota, since bounding the thread pool's worker count alone bounds
    concurrency, not requests-per-minute."""

    def __init__(self, max_calls: int, period_seconds: float):
        self._max_calls = max_calls
        self._period = period_seconds
        self._lock = threading.Lock()
        self._calls: deque[float] = deque()

    def acquire(self) -> None:
        with self._lock:
            while True:
                now = time.monotonic()
                while self._calls and now - self._calls[0] > self._period:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return
                time.sleep(self._period - (now - self._calls[0]))


# ip-api.com's free tier is ~45 req/min; stay comfortably under that even
# with several worker threads calling lookup_asn concurrently.
_ip_api_limiter = _RateLimiter(max_calls=40, period_seconds=60)


def lookup_asn(ip: str) -> dict:
    """ASN/organization for an IP. Free, no API key (ip-api.com, ~45 req/min)."""
    _ip_api_limiter.acquire()
    try:
        response = _session.get(
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
        response = _session.get(
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
            detail = _session.get(r["result"], timeout=REQUEST_TIMEOUT_SECONDS).json()
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
        response = _session.get(
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
        response = _session.get(
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
