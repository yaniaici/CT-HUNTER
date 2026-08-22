"""Loads the list of target brands from config/brands.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "brands.yaml"


@dataclass(frozen=True, slots=True)
class Brand:
    name: str
    category: str
    domain: str
    aliases: tuple[str, ...]

    @property
    def legitimate_domains(self) -> tuple[str, ...]:
        """All domains that legitimately belong to this brand (never suspicious)."""
        return (self.domain, *self.aliases)


def load_brands(path: Path = DEFAULT_CONFIG_PATH) -> list[Brand]:
    raw = yaml.safe_load(path.read_text())
    return [
        Brand(
            name=entry["name"],
            category=entry["category"],
            domain=entry["domain"],
            aliases=tuple(entry.get("aliases", [])),
        )
        for entry in raw["brands"]
    ]
