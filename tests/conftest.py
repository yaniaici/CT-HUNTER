import pytest

from ct_hunter.brands import Brand, load_brands
from ct_hunter.detect.similarity import build_tld_swap_labels, build_variant_index, build_whitelist


@pytest.fixture(scope="session")
def brands() -> list[Brand]:
    """The real config/brands.yaml, so regression cases match production data."""
    return load_brands()


@pytest.fixture(scope="session")
def brand_by_name(brands: list[Brand]) -> dict[str, Brand]:
    return {b.name: b for b in brands}


@pytest.fixture(scope="session")
def variant_index(brands: list[Brand]) -> dict[str, tuple[str, str]]:
    return build_variant_index(brands)


@pytest.fixture(scope="session")
def whitelist(brands: list[Brand]) -> set[str]:
    return build_whitelist(brands)


@pytest.fixture(scope="session")
def tld_swap_labels(brands: list[Brand]) -> dict[str, str]:
    return build_tld_swap_labels(brands)
