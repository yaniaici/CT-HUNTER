"""On-demand investigation of a single domain: WHOIS + HTTP probe.

Deliberately per-domain and triggered by hand from the UI, not part of the
bulk firehose pipeline: running a WHOIS lookup or an HTTP request for
every one of the daily hits would be slow and could look like abuse of the
services being queried. The human decides which domain is worth the
context here, mirroring the manual `whois`/`curl` checks used during
triage before this got wired into the UI.
"""

from __future__ import annotations

import re
import subprocess

import requests
from dateutil import parser as dateutil_parser

WHOIS_TIMEOUT_SECONDS = 10
HTTP_TIMEOUT_SECONDS = 8
HTTP_USER_AGENT = "Mozilla/5.0 (ct-hunter personal research project)"


def _parse_creation_date(raw: str | None) -> float | None:
    """Unix timestamp from a WHOIS creation-date string, or None if it is
    missing or unparseable. Registries do not agree on a format (ISO 8601,
    'DD-Mon-YYYY', dotted, with or without time/timezone), dateutil covers
    the realistic spread without a hand-rolled parser per registry."""
    if not raw:
        return None
    try:
        return dateutil_parser.parse(raw).timestamp()
    except (ValueError, OverflowError, TypeError):
        return None


def whois_lookup(domain: str) -> dict:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=WHOIS_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}

    raw = result.stdout

    def _find(pattern: str) -> str | None:
        match = re.search(pattern, raw, re.IGNORECASE)
        return match.group(1).strip() if match else None

    # Nameservers usually appear as several repeated "Name Server:" lines.
    nameservers = sorted({ns.strip().lower().rstrip(".") for ns in re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)})

    creation_date = _find(r"Creation Date:\s*(.+)")

    return {
        "creation_date": creation_date,
        "creation_date_ts": _parse_creation_date(creation_date),
        "registrar": _find(r"Registrar:\s*(.+)"),
        "registrant_country": _find(r"Registrant Country:\s*(.+)"),
        "nameservers": nameservers,
        "raw": raw or result.stderr,
    }


def http_probe(domain: str) -> dict:
    last_error = "no attempts made"
    for scheme in ("https://", "http://"):
        try:
            response = requests.get(
                scheme + domain,
                timeout=HTTP_TIMEOUT_SECONDS,
                allow_redirects=True,
                headers={"User-Agent": HTTP_USER_AGENT},
            )
        except requests.RequestException as exc:
            last_error = str(exc)
            continue

        title_match = re.search(r"<title[^>]*>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL)
        return {
            "scheme": scheme.rstrip(":/"),
            "status_code": response.status_code,
            "final_url": response.url,
            "title": title_match.group(1).strip() if title_match else None,
            "server": response.headers.get("Server"),
        }
    return {"error": last_error}


def external_links(domain: str) -> dict[str, str]:
    """Links for manual investigation, no API keys required."""
    return {
        "urlscan.io": f"https://urlscan.io/search/#{domain}",
        "VirusTotal": f"https://www.virustotal.com/gui/domain/{domain}",
        "crt.sh (certificate history)": f"https://crt.sh/?q={domain}",
    }
