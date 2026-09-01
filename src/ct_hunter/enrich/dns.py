"""On-demand DNS enrichment: does it resolve to an IP? Does it have an MX record?

Deliberately separate from the ingestion firehose (see docs/architecture.md):
a DNS resolution can take seconds or hang on NXDOMAIN/timeout, and that
should never block consumption of the live certificate stream. This module
runs separately, against whatever is already in the database.
"""

from __future__ import annotations

import dns.resolver

RESOLVE_TIMEOUT_SECONDS = 3.0


def _has_record(domain: str, record_type: str) -> bool:
    try:
        dns.resolver.resolve(domain, record_type, lifetime=RESOLVE_TIMEOUT_SECONDS)
        return True
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return False


def resolve_domain(domain: str) -> tuple[bool, bool]:
    """Returns (resolves_to_ip, has_mx)."""
    resolves_ip = _has_record(domain, "A") or _has_record(domain, "AAAA")
    has_mx = _has_record(domain, "MX")
    return resolves_ip, has_mx


def get_first_ip(domain: str) -> str | None:
    """First IP (A or AAAA) of a domain, for ASN/reputation lookups."""
    try:
        answer = dns.resolver.resolve(domain, "A", lifetime=RESOLVE_TIMEOUT_SECONDS)
        return str(answer[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    try:
        answer = dns.resolver.resolve(domain, "AAAA", lifetime=RESOLVE_TIMEOUT_SECONDS)
        return str(answer[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
