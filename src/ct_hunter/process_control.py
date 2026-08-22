"""Start/stop/query `ct-hunter-hunt` from the web UI.

`ct-hunter-hunt` remains a separate OS process rather than a thread inside
Streamlit: Streamlit re-executes the whole script on every user
interaction, which does not fit a long-running asyncio loop consuming a
WebSocket. The UI just launches/kills that process with subprocess and
reads its state from a pidfile plus the hunt_status.json the process
writes itself, so the reported state looks the same whether the UI
started it or you launched it by hand in a terminal.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys

from ct_hunter.process_state import DATA_DIR, LOG_FILE, PID_FILE, is_pid_alive, read_status

PROJECT_ROOT = DATA_DIR.parent


def hunt_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
    except ValueError:
        return None
    if is_pid_alive(pid):
        return pid
    PID_FILE.unlink(missing_ok=True)  # stale pidfile left behind by a process that died uncleanly
    return None


def start_hunt() -> None:
    if hunt_pid() is not None:
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log = open(LOG_FILE, "a")
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "ct_hunter.hunt"],
        cwd=PROJECT_ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # survives the UI being closed or reloaded
    )
    PID_FILE.write_text(str(proc.pid))


def stop_hunt() -> bool:
    pid = hunt_pid()
    if pid is None:
        return False
    os.kill(pid, signal.SIGTERM)
    PID_FILE.unlink(missing_ok=True)
    return True


def hunt_status() -> dict:
    return {"running": hunt_pid() is not None, **read_status()}


def docker_status(container_name: str = "certstream") -> str:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container_name],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    if result.returncode != 0:
        return "not found"
    return result.stdout.strip()
