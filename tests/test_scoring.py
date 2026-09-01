from ct_hunter.scoring import (
    ABUSEIPDB_HIGH_SCORE_BONUS,
    ABUSEIPDB_THRESHOLD,
    DEFAULT_TECHNIQUE_WEIGHT,
    HIGH_CONFIDENCE_TECHNIQUES,
    MASS_CA_BONUS,
    MAX_SCORE,
    TECHNIQUE_WEIGHTS,
    URLSCAN_PHISH_TAG_BONUS,
    VIRUSTOTAL_BONUS_PER_ENGINE,
    VIRUSTOTAL_MAX_BONUS,
    reputation_bonus,
    score_detection,
)


class TestScoreDetection:
    def test_base_score_is_the_technique_weight(self):
        score = score_detection("tld-swap", issuer_org=None, resolves_ip=False, has_mx=False)
        assert score == TECHNIQUE_WEIGHTS["tld-swap"]

    def test_unknown_technique_falls_back_to_default_weight(self):
        score = score_detection("some-future-technique", issuer_org=None, resolves_ip=False, has_mx=False)
        assert score == DEFAULT_TECHNIQUE_WEIGHT

    def test_mass_issuance_ca_adds_bonus(self):
        base = score_detection("tld-swap", issuer_org=None, resolves_ip=False, has_mx=False)
        with_ca = score_detection("tld-swap", issuer_org="Let's Encrypt", resolves_ip=False, has_mx=False)
        assert with_ca == base + MASS_CA_BONUS

    def test_mass_issuance_ca_match_is_case_insensitive(self):
        score = score_detection("tld-swap", issuer_org="ZEROSSL RSA CA", resolves_ip=False, has_mx=False)
        assert score == TECHNIQUE_WEIGHTS["tld-swap"] + MASS_CA_BONUS

    def test_non_mass_issuance_ca_adds_no_bonus(self):
        score = score_detection("tld-swap", issuer_org="DigiCert Inc", resolves_ip=False, has_mx=False)
        assert score == TECHNIQUE_WEIGHTS["tld-swap"]

    def test_bonuses_stack_across_all_signals(self):
        score = score_detection(
            "tld-swap",
            issuer_org="Let's Encrypt",
            resolves_ip=True,
            has_mx=True,
            visually_similar=True,
        )
        expected = (
            TECHNIQUE_WEIGHTS["tld-swap"]
            + 10  # mass CA
            + 20  # resolves IP
            + 25  # MX
            + 30  # visual similarity
        )
        assert score == expected

    def test_score_is_capped_at_max_score(self):
        # subdomain-impersonation (40) + every bonus comfortably exceeds 100.
        score = score_detection(
            "subdomain-impersonation",
            issuer_org="Let's Encrypt",
            resolves_ip=True,
            has_mx=True,
            visually_similar=True,
        )
        assert score == MAX_SCORE

    def test_high_confidence_techniques_exclude_only_fuzzy_edit_distance(self):
        assert "fuzzy-edit-distance" not in HIGH_CONFIDENCE_TECHNIQUES
        assert set(TECHNIQUE_WEIGHTS) - HIGH_CONFIDENCE_TECHNIQUES == {"fuzzy-edit-distance"}


class TestReputationBonus:
    def test_no_signals_gives_zero_bonus(self):
        assert reputation_bonus(0, None, None, None) == 0

    def test_asn_reuse_bonus(self):
        assert reputation_bonus(1, None, None, None) == 25

    def test_urlscan_phish_tag_is_case_insensitive(self):
        assert reputation_bonus(0, ["Phishing"], None, None) == URLSCAN_PHISH_TAG_BONUS

    def test_urlscan_tags_without_phish_add_nothing(self):
        assert reputation_bonus(0, ["malware", "suspicious"], None, None) == 0

    def test_virustotal_bonus_scales_with_engine_count(self):
        assert reputation_bonus(0, None, 3, None) == 3 * VIRUSTOTAL_BONUS_PER_ENGINE

    def test_virustotal_bonus_is_capped(self):
        assert reputation_bonus(0, None, 100, None) == VIRUSTOTAL_MAX_BONUS

    def test_abuseipdb_below_threshold_adds_nothing(self):
        assert reputation_bonus(0, None, None, ABUSEIPDB_THRESHOLD - 1) == 0

    def test_abuseipdb_at_threshold_adds_bonus(self):
        assert reputation_bonus(0, None, None, ABUSEIPDB_THRESHOLD) == ABUSEIPDB_HIGH_SCORE_BONUS

    def test_all_reputation_signals_stack(self):
        bonus = reputation_bonus(
            asn_reuse_count=2,
            urlscan_tags=["phishing"],
            virustotal_malicious_count=10,
            abuseipdb_score=90,
        )
        assert bonus == 25 + URLSCAN_PHISH_TAG_BONUS + VIRUSTOTAL_MAX_BONUS + ABUSEIPDB_HIGH_SCORE_BONUS
