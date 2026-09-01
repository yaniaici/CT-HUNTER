"""Regression tests for the typosquat detection engine.

Several cases here are not made up: they're the exact false positives /
false negatives that showed up against live CT traffic and are documented
in the README and docs/architecture.md. The point of pinning them down as
tests is that a future refactor of similarity.py should not be able to
reintroduce them silently.
"""

from ct_hunter.detect.similarity import (
    build_tld_swap_labels,
    build_whitelist,
    evaluate_hostname,
    generate_variants,
    match_registrable_domain,
    match_subdomain_impersonation,
    registrable_domain,
)


class TestRegistrableDomain:
    def test_strips_subdomain(self):
        assert registrable_domain("www.bbva.es") == "bbva.es"

    def test_multi_label_suffix(self):
        # dhl.com.au: 'com.au' is the public suffix, not just 'au'.
        assert registrable_domain("secure.dhl.com.au") == "dhl.com.au"

    def test_bare_registrable_domain_is_unchanged(self):
        assert registrable_domain("microsoft.com") == "microsoft.com"


class TestGenerateVariants:
    def test_excludes_the_legitimate_domain_itself(self, brand_by_name):
        variants = generate_variants(brand_by_name["Microsoft"])
        assert "microsoft.com" not in variants

    def test_includes_omission_on_original_tld(self, brand_by_name):
        variants = generate_variants(brand_by_name["DHL"])
        # dropping the 'h' from dhl -> dl
        assert variants.get("dl.com") == "omission"

    def test_does_not_seed_plain_tld_swap_itself(self, brand_by_name):
        # tld-swap (same label, different suffix) is handled separately by
        # build_tld_swap_labels()/match_registrable_domain(), suffix-agnostic,
        # so it must not also be seeded here restricted to COMMON_TLDS.
        variants = generate_variants(brand_by_name["Netflix"])
        assert "netflix.xyz" not in variants
        assert "netflix.top" not in variants

    def test_keyword_combo_variant(self, brand_by_name):
        variants = generate_variants(brand_by_name["PayPal"])
        assert variants.get("paypal-login.com") == "keyword-combo"

    def test_hyphenation_variant(self, brand_by_name):
        variants = generate_variants(brand_by_name["Netflix"])
        assert variants.get("net-flix.com") == "hyphenation"


class TestMatchRegistrableDomain:
    def test_legitimate_domain_is_never_flagged(self, brands, variant_index, whitelist):
        assert match_registrable_domain("microsoft.com", brands, variant_index, whitelist) is None

    def test_brand_alias_is_never_flagged(self, brands, variant_index, whitelist):
        # live.com is a Microsoft alias, not a typosquat of anything.
        assert match_registrable_domain("live.com", brands, variant_index, whitelist) is None

    def test_regional_alias_is_never_flagged(self, brands, variant_index, whitelist):
        # bbva.com.mx is whitelisted explicitly (see config/brands.yaml).
        assert match_registrable_domain("bbva.com.mx", brands, variant_index, whitelist) is None

    def test_precomputed_variant_hits_the_index(self, brands, variant_index, whitelist):
        match = match_registrable_domain("micosoft.com", brands, variant_index, whitelist)
        assert match is not None
        assert match.brand == "Microsoft"
        assert match.technique == "omission"

    def test_dhl_short_domain_false_positives_do_not_match_on_fuzzy_layer(self, brands, whitelist):
        # Real false positives found in production: at distance 2 from
        # 'dhl.com', these are unrelated real domains, not typosquats.
        # Tested with an empty variant index to isolate the fuzzy-edit-
        # distance layer specifically (that's the layer that used to
        # false-positive on these before the length-normalized ratio).
        for noisy_domain in ("uhc.com", "diy.com", "cal.com"):
            assert match_registrable_domain(noisy_domain, brands, {}, whitelist) is None

    def test_fuzzy_layer_still_catches_a_real_typo_outside_the_index(self, brands, whitelist):
        # 'micosoft.com' would normally hit the precomputed omission
        # variant; passing an empty index isolates the fuzzy-edit-distance
        # fallback and confirms it independently catches the same typo.
        match = match_registrable_domain("micosoft.com", brands, {}, whitelist)
        assert match is not None
        assert match.brand == "Microsoft"
        assert match.technique == "fuzzy-edit-distance"

    def test_unrelated_domain_is_not_flagged(self, brands, variant_index, whitelist):
        assert match_registrable_domain("example.com", brands, variant_index, whitelist) is None


class TestTldSwapSuffixAgnostic:
    """Same label, any suffix, not just the fixed COMMON_TLDS list.

    Regression coverage for a real gap: 'microsoft.support' or
    'paypal.security', exact label with an unenumerated TLD, used to slip
    past both the precomputed index and the Levenshtein fallback (which
    also penalizes for the suffix difference, so it never scores high
    enough)."""

    def test_flags_exact_label_on_an_uncommon_suffix(self, brands, variant_index, whitelist, tld_swap_labels):
        match = match_registrable_domain("microsoft.support", brands, variant_index, whitelist, tld_swap_labels)
        assert match is not None
        assert match.brand == "Microsoft"
        assert match.technique == "tld-swap"

    def test_flags_a_second_brand_on_an_uncommon_suffix(self, brands, variant_index, whitelist, tld_swap_labels):
        match = match_registrable_domain("paypal.security", brands, variant_index, whitelist, tld_swap_labels)
        assert match is not None
        assert match.brand == "PayPal"
        assert match.technique == "tld-swap"

    def test_is_opt_in_via_the_tld_swap_labels_argument(self, brands, variant_index, whitelist):
        # Omitting tld_swap_labels (the default) must not silently enable
        # this check; callers that don't pass it get the old behavior.
        assert match_registrable_domain("microsoft.support", brands, variant_index, whitelist) is None

    def test_whitelisted_domain_wins_over_a_label_match(self, brands, variant_index, whitelist, tld_swap_labels):
        # amazon.dev is a real, whitelisted Amazon domain (AWS internal
        # service naming); it must not be flagged just because its label
        # ('amazon') matches the brand's own label.
        assert match_registrable_domain("amazon.dev", brands, variant_index, whitelist, tld_swap_labels) is None


class TestMatchSubdomainImpersonation:
    def test_flags_brand_domain_used_as_a_subdomain(self, brands, whitelist):
        match = match_subdomain_impersonation("bbva.es.attacker-domain.com", brands, whitelist)
        assert match is not None
        assert match.brand == "BBVA"
        assert match.technique == "subdomain-impersonation"

    def test_respects_dns_label_boundaries_not_substrings(self, brands, whitelist):
        # 'live' appears inside 'xingkong-live.com' but 'live.com' is not
        # an actual label boundary match, so this must NOT be flagged as
        # Microsoft (live.com) subdomain impersonation.
        assert match_subdomain_impersonation("xingkong-live.com", brands, whitelist) is None

    def test_known_casb_wrapper_domain_is_not_flagged(self, brands, whitelist):
        # *.office.com.mcas.ms is Microsoft Defender for Cloud Apps, a
        # legitimate reverse proxy, not phishing infrastructure.
        assert match_subdomain_impersonation("login.office.com.mcas.ms", brands, whitelist) is None

    def test_apple_china_domain_is_not_flagged(self, brands, whitelist):
        # apple.com.cn is itself whitelisted; containing 'apple.com' as a
        # label prefix is structural, not impersonation.
        assert match_subdomain_impersonation("apple.com.cn", brands, whitelist) is None

    def test_real_registrable_domain_matching_brand_is_not_a_subdomain_attack(self, brands, whitelist):
        # bbva.es is BBVA's own domain: it's the actual registrable
        # domain, not a case of it appearing as someone else's subdomain.
        assert match_subdomain_impersonation("bbva.es", brands, whitelist) is None


class TestEvaluateHostname:
    def test_full_pipeline_flags_a_typosquat(self, brands, variant_index):
        match = evaluate_hostname("micosoft.com", brands, variant_index)
        assert match is not None
        assert match.brand == "Microsoft"

    def test_full_pipeline_clears_a_legitimate_domain(self, brands, variant_index):
        assert evaluate_hostname("microsoft.com", brands, variant_index) is None

    def test_full_pipeline_prefers_subdomain_check_over_registrable_check(self, brands, variant_index):
        # login.bbva.es.attacker.com: registrable domain is attacker.com
        # (unrelated), but bbva.es shows up as a subdomain label.
        match = evaluate_hostname("login.bbva.es.attacker.com", brands, variant_index)
        assert match is not None
        assert match.technique == "subdomain-impersonation"

    def test_builds_its_own_whitelist_when_none_given(self, brands, variant_index):
        # Exercises the "Test a domain" dashboard tab's call path, which
        # does not precompute a whitelist.
        assert evaluate_hostname("microsoft.com", brands, variant_index, whitelist=None) is None

    def test_builds_its_own_tld_swap_labels_when_none_given(self, brands, variant_index):
        # Same dashboard call path, but for the suffix-agnostic tld-swap
        # check: it must not require a precomputed tld_swap_labels either.
        match = evaluate_hostname("microsoft.support", brands, variant_index, tld_swap_labels=None)
        assert match is not None
        assert match.brand == "Microsoft"
        assert match.technique == "tld-swap"
