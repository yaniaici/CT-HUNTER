"""Paths and helpers for the state shared between `hunt.py` (which writes)
and the web UI (which reads) to know whether the firehose is alive and
how much it has processed, without coupling the UI to the process itself.
See docs/architecture.md.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
PID_FILE = DATA_DIR / "hunt.pid"
STATUS_FILE = DATA_DIR / "hunt_status.json"
LOG_FILE = DATA_DIR / "hunt.log"


def is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def claim_single_instance() -> bool:
    """Claims the pidfile for the current process. Returns False (without
    touching anything) if another instance is already alive. Prevents two
    `ct-hunter-hunt` processes from running at once regardless of how they
    were launched (CLI by hand or the UI's button), which is exactly what
    caused a race condition in write_status previously."""
    if PID_FILE.exists():
        try:
            existing_pid = int(PID_FILE.read_text().strip())
        except ValueError:
            existing_pid = None
        if existing_pid is not None and existing_pid != os.getpid() and is_pid_alive(existing_pid):
            return False
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    return True


def write_status(started_at: float, certs_seen: int, hits: int) -> None:
    """Atomic write (write + rename) so a reader never sees a half-written JSON.

    The temp filename includes the PID: if two processes ever end up
    writing at the same time again (should not happen, see
    claim_single_instance), each uses its own temp file and the rename
    step cannot collide.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "started_at": started_at,
        "certs_seen": certs_seen,
        "hits": hits,
        "last_update": time.time(),
    }
    tmp = STATUS_FILE.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload))
    tmp.replace(STATUS_FILE)


def read_status() -> dict:
    if not STATUS_FILE.exists():
        return {}
    try:
        return json.loads(STATUS_FILE.read_text())
    except json.JSONDecodeError:
        return {}
