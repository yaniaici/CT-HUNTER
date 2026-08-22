"""CertStream firehose client (self-hosted certstream-server-rust).

Connects to the "lite" stream (every field except the raw DER and the
certificate chain), which is enough for typosquatting + scoring: it
carries domains, issuer, and validity dates from the leaf cert.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

DEFAULT_URL = "ws://localhost:8080/"


@dataclass(frozen=True, slots=True)
class CertEvent:
    """A new certificate seen in a CT log, already flattened to what we care about."""

    all_domains: list[str]
    issuer_org: str | None
    seen_at: float
    source_log: str | None

    @classmethod
    def from_message(cls, message: dict) -> "CertEvent | None":
        if message.get("message_type") != "certificate_update":
            return None

        data = message["data"]
        leaf_cert = data["leaf_cert"]

        return cls(
            all_domains=leaf_cert.get("all_domains", []),
            issuer_org=leaf_cert.get("issuer", {}).get("O"),
            seen_at=data["seen"],
            source_log=data.get("source", {}).get("name"),
        )


async def stream_certificates(url: str = DEFAULT_URL) -> AsyncIterator[CertEvent]:
    """Connects to the firehose and yields one CertEvent per new certificate.

    Reconnects indefinitely on connection loss (a CT log stream never
    "ends" in a normal sense: if it closes, that is a transient failure).
    """
    while True:
        try:
            async with connect(url) as ws:
                async for raw in ws:
                    message = json.loads(raw)
                    event = CertEvent.from_message(message)
                    if event is not None:
                        yield event
        except ConnectionClosed:
            await asyncio.sleep(2)
            continue


async def _main() -> None:
    """Manual smoke test: prints live domains to validate the pipeline."""
    count = 0
    async for event in stream_certificates():
        count += 1
        print(f"[{count}] issuer={event.issuer_org!r} domains={event.all_domains}")


if __name__ == "__main__":
    asyncio.run(_main())
