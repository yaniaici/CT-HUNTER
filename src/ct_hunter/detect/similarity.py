"""Typosquatting detection against the list of target brands.

Two layers, from cheap/precise to expensive/loose:

1. **Precomputed variant index**: for each brand, we precompute at startup
   the set of "typical" domains an attacker would register (omission,
   repetition, transposition, homoglyphs, hyphenation, TLD swap, brand +
   phishing keyword). Comparing the firehose against this is an O(1) dict
   lookup, which is what makes it viable to look at every new certificate
   in real time without computing distances on every event.

2. **Edit distance as a safety net**: any variant the attacker invents
   that is not in our generated set (uncommon misspellings, TLDs we did
   not enumerate) is caught with a length-normalized Levenshtein
   similarity ratio against each brand's base domain (an absolute
   distance does not work: for a short domain like 'dhl.com', a distance
   of 2 matches almost anything).

3. **Subdomain impersonation**: a separate check over the full hostname
   (not just the registrable domain) that detects attacks like
   ``bbva.es.attacker-domain.com``, where the brand's real domain shows up
   as a subdomain of a domain the brand does not control.
"""

from __future__ import annotations

from dataclasses import dataclass

import tldextract
from rapidfuzz.distance import Levenshtein

from ct_hunter.brands import Brand

PHISHING_KEYWORDS = (
    "login", "secure", "verify", "account", "signin",
    "portal", "support", "id", "auth", "banking",
)
COMMON_TLDS = ("com", "net", "org", "info", "xyz", "top", "online", "site", "click", "live")

# ASCII homoglyphs: characters that look alike in any standard font.
ASCII_HOMOGLYPHS = {
    "o": "0", "l": "1", "i": "1", "e": "3",
    "a": "4", "s": "5", "g": "9", "b": "6",
}
ASCII_DIGRAPHS = {"rn": "m", "vv": "w", "cl": "d"}

# Unicode homoglyphs -> ASCII (Cyrillic and Greek characters that get
# confused with Latin ones).
UNICODE_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",  # Cyrillic
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",  # Greek
}

# Known CASB providers that legitimately put the monitored SaaS domain as
# a subdomain of their own (conditional-access reverse proxy), the exact
# same syntactic pattern as a real impersonation attack. Confirmed with
# real data: *.office.com.mcas.ms and *.google.com.mcas.ms belong to
# Microsoft Defender for Cloud Apps, not phishing (see docs/architecture.md).
KNOWN_CASB_WRAPPER_DOMAINS = {"mcas.ms", "admin-mcas.ms", "mcas-df.ms", "admin-mcas-df.ms"}

LEVENSHTEIN_THRESHOLD = 2  # absolute distance, only a quick pre-filter before computing the ratio

# An absolute distance threshold does not scale with domain length: a
# distance of 2 matches almost anything against a short domain like
# 'dhl.com' (confirmed with real data: 'uhc.com', 'diy.com', 'cal.com'...
# all sit at distance 2 from 'dhl.com' with no real similarity). A
# length-normalized similarity ratio (0-1) is used instead. 0.80 was
# picked by comparing real typos (0.83-0.92) against the short-domain
# noise observed (0.71), which cleanly separates the two groups.
MIN_SIMILARITY_RATIO = 0.80

_extract = tldextract.TLDExtract()


@dataclass(frozen=True, slots=True)
class SimilarityMatch:
    brand: str
    technique: str
    candidate: str
    distance: int = 0


def registrable_domain(hostname: str) -> str:
    """eTLD+1: 'www.bbva.es' -> 'bbva.es'. Uses the Public Suffix List."""
    parts = _extract(hostname)
    if not parts.domain or not parts.suffix:
        return hostname
    return f"{parts.domain}.{parts.suffix}"


def decode_idn(hostname: str) -> str:
    """Punycode -> Unicode, so real homoglyphs can be compared."""
    try:
        return hostname.encode("ascii").decode("idna")
    except (UnicodeError, LookupError):
        return hostname


def normalize_confusables(hostname: str) -> str:
    return "".join(UNICODE_CONFUSABLES.get(ch, ch) for ch in hostname)


def _omissions(label: str) -> set[str]:
    return {label[:i] + label[i + 1:] for i in range(len(label))}


def _repetitions(label: str) -> set[str]:
    return {label[:i] + label[i] + label[i:] for i in range(len(label))}


def _transpositions(label: str) -> set[str]:
    return {
        label[:i] + label[i + 1] + label[i] + label[i + 2:]
        for i in range(len(label) - 1)
    }


def _homoglyphs(label: str) -> set[str]:
    variants = {
        label[:i] + repl + label[i + 1:]
        for i, ch in enumerate(label)
        if (repl := ASCII_HOMOGLYPHS.get(ch)) is not None
    }
    for digraph, repl in ASCII_DIGRAPHS.items():
        if digraph in label:
            variants.add(label.replace(digraph, repl))
    return variants


def _hyphenations(label: str) -> set[str]:
    return {label[:i] + "-" + label[i:] for i in range(1, len(label))}


def _keyword_combos(label: str) -> set[str]:
    variants = set()
    for kw in PHISHING_KEYWORDS:
        variants.update({f"{label}-{kw}", f"{kw}-{label}", f"{label}{kw}", f"{kw}{label}"})
    return variants


def generate_variants(brand: Brand) -> dict[str, str]:
    """Returns {variant_domain: technique} for the brand's base domain.

    Each label mutation (e.g. 'micosoft' by omission) is combined both
    with the brand's original TLD and with the cheap TLDs typical of
    disposable phishing infrastructure (.xyz, .top, ...); an attacker
    almost never uses the legitimate TLD, so limiting variants to the
    original TLD would miss most real cases.
    """
    parts = _extract(brand.domain)
    label, suffix = parts.domain, parts.suffix
    tlds = {suffix, *COMMON_TLDS}

    label_variants: dict[str, str] = {label: "tld-swap"}  # same label, different TLD
    for labels, technique in (
        (_omissions(label), "omission"),
        (_repetitions(label), "repetition"),
        (_transpositions(label), "transposition"),
        (_homoglyphs(label), "homoglyph-ascii"),
        (_hyphenations(label), "hyphenation"),
        (_keyword_combos(label), "keyword-combo"),
    ):
        for candidate_label in labels:
            label_variants.setdefault(candidate_label, technique)

    variants: dict[str, str] = {}
    for candidate_label, technique in label_variants.items():
        for tld in tlds:
            if candidate_label == label and tld == suffix:
                continue  # the legitimate domain itself, not a variant
            variants.setdefault(f"{candidate_label}.{tld}", technique)

    return variants


def build_variant_index(brands: list[Brand]) -> dict[str, tuple[str, str]]:
    """variant_domain -> (brand_name, technique), merged across all brands."""
    index: dict[str, tuple[str, str]] = {}
    for brand in brands:
        for variant, technique in generate_variants(brand).items():
            index.setdefault(variant, (brand.name, technique))
    return index


def _is_whitelisted(candidate: str, brands: list[Brand]) -> bool:
    legit = {d for b in brands for d in b.legitimate_domains}
    return candidate in legit


def match_registrable_domain(
    candidate: str,
    brands: list[Brand],
    variant_index: dict[str, tuple[str, str]],
) -> SimilarityMatch | None:
    """Compares a registrable domain (eTLD+1) against brands + variants."""
    if _is_whitelisted(candidate, brands):
        return None

    hit = variant_index.get(candidate)
    if hit is not None:
        brand_name, technique = hit
        return SimilarityMatch(brand=brand_name, technique=technique, candidate=candidate)

    # Unicode homoglyphs: normalize and try the index again.
    normalized = normalize_confusables(decode_idn(candidate))
    if normalized != candidate:
        hit = variant_index.get(normalized)
        if hit is not None:
            brand_name, _ = hit
            return SimilarityMatch(brand=brand_name, technique="homoglyph-unicode", candidate=candidate)
        for brand in brands:
            if normalized in brand.legitimate_domains:
                return SimilarityMatch(brand=brand.name, technique="homoglyph-unicode", candidate=candidate)

    best: SimilarityMatch | None = None
    best_ratio = 0.0
    for brand in brands:
        dist = Levenshtein.distance(candidate, brand.domain)
        if dist == 0 or dist > LEVENSHTEIN_THRESHOLD:
            continue  # quick filter: cannot pass the ratio check if it does not even pass this
        ratio = Levenshtein.normalized_similarity(candidate, brand.domain)
        if ratio >= MIN_SIMILARITY_RATIO and ratio > best_ratio:
            best_ratio = ratio
            best = SimilarityMatch(
                brand=brand.name, technique="fuzzy-edit-distance", candidate=candidate, distance=dist
            )
    return best


def match_subdomain_impersonation(hostname: str, brands: list[Brand]) -> SimilarityMatch | None:
    """Detects 'bbva.es.attacker-domain.com': the brand shows up as a
    subdomain instead of being the certificate's real registrable domain.

    Compares by DNS label boundaries (dots), not a plain substring check:
    'live.com' (a Microsoft alias) must not match 'xingkong-live.com',
    where 'live' is only part of a different label, not the domain
    'live.com' itself.
    """
    real_registrable = registrable_domain(hostname)
    if real_registrable in KNOWN_CASB_WRAPPER_DOMAINS:
        return None
    if _is_whitelisted(real_registrable, brands):
        # The certificate's actual registrable domain is itself
        # legitimate (e.g. 'apple.com.cn'): containing 'apple.com' as a
        # label prefix is structural coincidence, not impersonation.
        return None

    padded_host = f".{hostname.rstrip('.')}."
    for brand in brands:
        for legit in brand.legitimate_domains:
            if f".{legit}." in padded_host and real_registrable != legit:
                return SimilarityMatch(brand=brand.name, technique="subdomain-impersonation", candidate=hostname)
    return None


def evaluate_hostname(
    hostname: str,
    brands: list[Brand],
    variant_index: dict[str, tuple[str, str]],
) -> SimilarityMatch | None:
    """Single entry point: applies all three detection layers to a raw
    hostname exactly as it comes from `all_domains` in the certificate."""
    subdomain_hit = match_subdomain_impersonation(hostname, brands)
    if subdomain_hit is not None:
        return subdomain_hit

    candidate = registrable_domain(hostname)
    return match_registrable_domain(candidate, brands, variant_index)
