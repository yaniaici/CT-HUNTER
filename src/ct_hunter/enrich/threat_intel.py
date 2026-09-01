"""Crosscheck against public feeds of already-confirmed phishing.

This is not "just reposting what others already publish": the value is in
comparing OUR OWN detection timestamp (`first_seen_at`, when the
certificate was seen in the CT log) against the moment that same domain
shows up in a feed of phishing already confirmed by a third party. That
time difference is the finding: how much real lead time watching CT logs
gives over waiting for someone else to list a domain as malicious.

Source: the OpenPhish community feed (free, no signup, updated roughly
every 12h, redirects to a GitHub raw file). URLhaus has a larger dataset
but has required a free Auth-Key registered at auth.abuse.ch since 2025;
left out of v1 to avoid depending on an external account.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from ct_hunter.detect.similarity import registrable_domain

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
REQUEST_TIMEOUT_SECONDS = 15


def fetch_openphish_domains() -> set[str]:
    """Registrable domains currently present in the OpenPhish community
    feed (active phishing they have confirmed)."""
    response = requests.get(
        OPENPHISH_FEED_URL,
        timeout=REQUEST_TIMEOUT_SECONDS,
        headers={"User-Agent": "ct-hunter/0.1 (personal threat-hunting project)"},
    )
    response.raise_for_status()

    domains = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line:
            continue
        host = urlparse(line).hostname
        if host:
            domains.add(registrable_domain(host))
    return domains
