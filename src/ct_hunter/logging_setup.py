"""Rotating file logger for the long-running hunt process.

hunt.py runs for days at a time under systemd. It used to write with
plain `print()`, with systemd appending stdout/stderr straight to
data/hunt.log (`StandardOutput=append` in the unit file); that file grew
without limit, 1.2MB and climbing when this was first noticed. This
replaces that with the standard library's logging module and a
RotatingFileHandler on the package root logger ("ct_hunter").

Every module logs via `logging.getLogger(__name__)` and propagates up to
the handlers configured once here, in hunt.py's entry point, instead of
each module owning its own file handler, which would race against the
others rotating the same file from independent size checks.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "hunt.log"
MAX_BYTES = 5_000_000  # rotate at ~5MB
BACKUP_COUNT = 3  # hunt.log plus 3 rotated copies, ~20MB total worst case


def configure_hunt_logging() -> None:
    logger = logging.getLogger("ct_hunter")
    if logger.handlers:
        return  # already configured, avoids duplicate handlers on re-import
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
