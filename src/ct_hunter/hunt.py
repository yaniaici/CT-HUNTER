"""Entry point: consumes the live CT firehose and persists hits.

    uv run ct-hunter-hunt

Runs indefinitely. Ctrl+C to stop.
"""

from __future__ import annotations

import asyncio
import sys
import time

from ct_hunter.brands import load_brands
from ct_hunter.detect.similarity import build_variant_index, evaluate_hostname
from ct_hunter.ingest.certstream_client import stream_certificates
from ct_hunter.process_state import claim_single_instance, write_status
from ct_hunter.storage.db import get_connection, init_db, record_detection

STATUS_WRITE_INTERVAL = 20  # certificates between hunt_status.json writes


async def _run() -> None:
    brands = load_brands()
    variant_index = build_variant_index(brands)
    conn = get_connection()
    init_db(conn)

    print(f"Watching {len(brands)} brands ({', '.join(b.name for b in brands)})")
    print(f"Variant index: {len(variant_index)} precomputed entries")
    print("Connecting to the firehose...\n")

    started_at = time.time()
    seen = 0
    hits = 0
    write_status(started_at, seen, hits)

    async for event in stream_certificates():
        seen += 1
        for hostname in event.all_domains:
            match = evaluate_hostname(hostname, brands, variant_index)
            if match is None:
                continue
            hits += 1
            record_detection(conn, match, event, hostname)
            print(
                f"[HIT #{hits}] brand={match.brand} technique={match.technique} "
                f"domain={hostname!r} issuer={event.issuer_org!r}"
            )
            write_status(started_at, seen, hits)

        if seen % STATUS_WRITE_INTERVAL == 0:
            write_status(started_at, seen, hits)

        if seen % 5000 == 0:
            print(f"... {seen} certificates processed, {hits} hits so far")


def main() -> None:
    if not claim_single_instance():
        print(
            "A ct-hunter-hunt process is already running (see data/hunt.pid). "
            "Stop it first (from the dashboard's System tab, or by killing "
            "the process) before starting another one.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nStopped by user.")


if __name__ == "__main__":
    main()
