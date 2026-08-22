"""Risk scoring for suspicious domains.

The score combines two kinds of signal:

1. **The detection technique itself**: the more deliberate/explicit ones
   (subdomain impersonation, phishing keyword combo, unicode homoglyph)
   carry more weight than noisier techniques that can also trigger by
   accidental coincidence rather than real intent to impersonate the brand
   (generic edit distance).
2. **"Ready to attack" signals**: does it resolve to an IP (infrastructure
   is actually behind it)? Does it have an MX record (can send mail, i.e.
   ready for phishing)? Is the issuing CA one of the free, automated ones
   typical of disposable malicious infrastructure (Let's Encrypt, ZeroSSL,
   Buypass; they only validate domain control, not identity)? Does it look
   visually similar (perceptual hash) to the legitimate site it
   impersonates? The last one is the most expensive signal to obtain
   (needs a screenshot from a real browser) and also the strongest: a
   domain that both sounds similar in name *and* looks like the real site
   is almost certainly a phishing clone, not a coincidence.

This is not meant to be an objectively "correct" score, it is an
explainable heuristic: every point can be justified in a sentence, which
is exactly what is needed to defend it in an interview.
"""

from __future__ import annotations

TECHNIQUE_WEIGHTS = {
    "subdomain-impersonation": 40,
    "keyword-combo": 35,
    "homoglyph-unicode": 35,
    "homoglyph-ascii": 25,
    "transposition": 15,
    "omission": 15,
    "repetition": 15,
    "hyphenation": 10,
    "tld-swap": 10,
    "fuzzy-edit-distance": 10,
}
DEFAULT_TECHNIQUE_WEIGHT = 10

# Every technique except fuzzy-edit-distance is an exact match against a
# precomputed transformation of the brand's real domain (see
# detect/similarity.py): it cannot fire on a coincidentally similar but
# unrelated domain the way a fuzzy ratio threshold can (confirmed by the
# 'dhl.com' false-positive episode, see docs/architecture.md). That makes
# them safe to auto-triage into "en_seguimiento" (monitoring) on their own,
# name alone, without waiting for DNS/visual/reputation signals: the name
# itself is already deliberate, even if the domain is currently dormant or
# just parked (see docs/architecture.md section 12).
HIGH_CONFIDENCE_TECHNIQUES = frozenset(TECHNIQUE_WEIGHTS) - {"fuzzy-edit-distance"}

MASS_ISSUANCE_CAS = ("let's encrypt", "zerossl", "buypass")

RESOLVES_IP_BONUS = 20
HAS_MX_BONUS = 25
MASS_CA_BONUS = 10
VISUAL_SIMILARITY_BONUS = 30

# Reputation bonuses (see reputation.py). ADDED to the score already
# computed by score_detection rather than recomputed from scratch, because
# each enrichment step (DNS, visual, reputation) fires independently and
# on demand; none of them necessarily knows the results of the others.
ASN_REUSE_BONUS = 25
URLSCAN_PHISH_TAG_BONUS = 15
VIRUSTOTAL_BONUS_PER_ENGINE = 5
VIRUSTOTAL_MAX_BONUS = 25
ABUSEIPDB_THRESHOLD = 50
ABUSEIPDB_HIGH_SCORE_BONUS = 15

MAX_SCORE = 100


def score_detection(
    technique: str,
    issuer_org: str | None,
    resolves_ip: bool | None,
    has_mx: bool | None,
    visually_similar: bool | None = None,
) -> float:
    score = TECHNIQUE_WEIGHTS.get(technique, DEFAULT_TECHNIQUE_WEIGHT)

    if issuer_org and any(ca in issuer_org.lower() for ca in MASS_ISSUANCE_CAS):
        score += MASS_CA_BONUS
    if resolves_ip:
        score += RESOLVES_IP_BONUS
    if has_mx:
        score += HAS_MX_BONUS
    if visually_similar:
        score += VISUAL_SIMILARITY_BONUS

    return min(score, MAX_SCORE)


def reputation_bonus(
    asn_reuse_count: int,
    urlscan_tags: list[str] | None,
    virustotal_malicious_count: int | None,
    abuseipdb_score: int | None,
) -> int:
    """Additional bonus from external reputation signals. Added to the
    existing score, never a replacement for it. See docs/architecture.md,
    "automation boundary": these signals prioritize, they do not confirm
    anything on their own."""
    bonus = 0
    if asn_reuse_count > 0:
        bonus += ASN_REUSE_BONUS
    if urlscan_tags and any("phish" in tag.lower() for tag in urlscan_tags):
        bonus += URLSCAN_PHISH_TAG_BONUS
    if virustotal_malicious_count:
        bonus += min(virustotal_malicious_count * VIRUSTOTAL_BONUS_PER_ENGINE, VIRUSTOTAL_MAX_BONUS)
    if abuseipdb_score is not None and abuseipdb_score >= ABUSEIPDB_THRESHOLD:
        bonus += ABUSEIPDB_HIGH_SCORE_BONUS
    return bonus
