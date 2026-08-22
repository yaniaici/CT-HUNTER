"""Screenshot capture + visual comparison (perceptual hash) against the
legitimate site being impersonated.

On demand, per domain (a button in the dashboard), not automatic in bulk:
visiting hundreds of suspicious domains with a real browser at once
carries more operational and safety weight (active content, slow or
hanging pages) than doing it one at a time once a human has decided that
specific domain is worth a look.

Known limitation: many sites show a cookie banner that can cover the real
content and contaminate the comparison (two different sites with the same
generic banner could look visually identical without being related). A
best-effort click is attempted to dismiss the banner before capturing, but
it is not foolproof, which is why the distance is shown to the human
instead of deciding on its own.
"""

from __future__ import annotations

import re
from pathlib import Path

import imagehash
from PIL import Image
from playwright.sync_api import sync_playwright

from ct_hunter.brands import Brand

SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "screenshots"
REFERENCE_DIR = SCREENSHOTS_DIR / "reference"
CANDIDATE_DIR = SCREENSHOTS_DIR / "candidates"

NAV_TIMEOUT_MS = 15000
VIEWPORT = {"width": 1280, "height": 800}

# 64-bit phash (8x8 default in imagehash); <=10 differing bits counts as
# "visually similar". Threshold taken from common perceptual-hashing
# practice; see docs/architecture.md for how it was validated.
VISUAL_SIMILARITY_THRESHOLD = 10

COOKIE_ACCEPT_TEXTS = [
    "Aceptar todo", "Aceptar", "Accept all", "Accept", "I agree",
    "Agree", "Allow all", "Got it",
]


def _dismiss_cookie_banner(page) -> None:
    for text in COOKIE_ACCEPT_TEXTS:
        try:
            page.get_by_role("button", name=text, exact=False).first.click(timeout=1200)
            return
        except Exception:
            continue


def capture_screenshot(url: str, out_path: Path) -> bool:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page(viewport=VIEWPORT)
                page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
                page.wait_for_timeout(1000)
                _dismiss_cookie_banner(page)
                page.wait_for_timeout(500)
                page.screenshot(path=str(out_path))
            finally:
                browser.close()
        return True
    except Exception:
        return False


def _phash(image_path: Path):
    return imagehash.phash(Image.open(image_path))


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")


def reference_screenshot_path(brand: Brand) -> Path:
    return REFERENCE_DIR / f"{_slug(brand.name)}.png"


def candidate_screenshot_path(domain: str) -> Path:
    return CANDIDATE_DIR / f"{_slug(domain)}.png"


def ensure_reference_screenshot(brand: Brand) -> Path | None:
    """Captures and caches the brand's reference screenshot the first time;
    later calls reuse the file already saved."""
    path = reference_screenshot_path(brand)
    if path.exists():
        return path
    return path if capture_screenshot(f"https://{brand.domain}", path) else None


def compare_visual(domain: str, brand: Brand) -> dict:
    ref_path = ensure_reference_screenshot(brand)
    if ref_path is None:
        return {"error": f"Could not capture the reference screenshot for {brand.name} ({brand.domain})."}

    cand_path = candidate_screenshot_path(domain)
    ok = capture_screenshot(f"https://{domain}", cand_path) or capture_screenshot(f"http://{domain}", cand_path)
    if not ok:
        return {"error": f"Could not capture {domain} (timeout, connection refused, or no HTTP response)."}

    distance = _phash(ref_path) - _phash(cand_path)
    return {
        "reference_path": ref_path,
        "candidate_path": cand_path,
        "hamming_distance": distance,
        "visually_similar": distance <= VISUAL_SIMILARITY_THRESHOLD,
    }
