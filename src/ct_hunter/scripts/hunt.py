"""Entry point: consumes the live CT firehose and persists hits.

    uv run ct-hunter-hunt

Runs indefinitely. Ctrl+C to stop.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time

from ct_hunter.brands import load_brands
from ct_hunter.detect.similarity import build_variant_index, build_whitelist, evaluate_hostname
from ct_hunter.ingest.certstream_client import stream_certificates
from ct_hunter.process.logging_setup import configure_hunt_logging
from ct_hunter.process.state import claim_single_instance, write_status
from ct_hunter.storage.db import get_connection, init_db, record_detection

STATUS_WRITE_INTERVAL = 20  # certificates between hunt_status.json writes

logger = logging.getLogger(__name__)


async def _run() -> None:
    brands = load_brands()
    variant_index = build_variant_index(brands)
    whitelist = build_whitelist(brands)
    conn = get_connection()
    init_db(conn)

    logger.info(f"Watching {len(brands)} brands ({', '.join(b.name for b in brands)})")
    logger.info(f"Variant index: {len(variant_index)} precomputed entries")
    logger.info("Connecting to the firehose...")

    started_at = time.time()
    seen = 0
    hits = 0
    write_status(started_at, seen, hits)

    async for event in stream_certificates():
        seen += 1
        for hostname in event.all_domains:
            try:
                match = evaluate_hostname(hostname, brands, variant_index, whitelist)
                if match is None:
                    continue
                hits += 1
                record_detection(conn, match, event, hostname)
                logger.info(
                    f"[HIT #{hits}] brand={match.brand} technique={match.technique} "
                    f"domain={hostname!r} issuer={event.issuer_org!r}"
                )
                write_status(started_at, seen, hits)
            except Exception:
                # One bad hostname (or a transient SQLite lock hitting the
                # 5s busy_timeout while the dashboard is also writing)
                # must not lose the rest of this certificate's domains, let
                # alone the whole run. Logged, then move on.
                logger.exception(f"Error processing {hostname!r} from this certificate")

        if seen % STATUS_WRITE_INTERVAL == 0:
            write_status(started_at, seen, hits)

        if seen % 5000 == 0:
            logger.info(f"... {seen} certificates processed, {hits} hits so far")


def main() -> None:
    configure_hunt_logging()

    if not claim_single_instance():
        logger.error(
            "A ct-hunter-hunt process is already running (see data/hunt.pid). "
            "Stop it first (from the dashboard's System tab, or by killing "
            "the process) before starting another one."
        )
        sys.exit(1)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        logger.info("Stopped by user.")
    except Exception:
        # Anything that reaches here is a bug, not an expected condition
        # (per-hostname errors are already caught inside _run). Logged with
        # a full traceback and a non-zero exit so systemd's Restart=on-failure
        # picks it back up instead of ingestion silently staying dead.
        logger.exception("Fatal error in ct-hunter-hunt")
        sys.exit(1)


if __name__ == "__main__":
    main()
