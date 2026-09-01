"""Start/stop/query `ct-hunter-hunt` from the web UI, via systemd.

`ct-hunter-hunt` and the dashboard itself run as systemd user services
(`~/.config/systemd/user/ct-hunter-hunt.service` /
`ct-hunter-dashboard.service`), not as bare background processes: a bare
`nohup ... &` does not survive a reboot or an unhandled crash, which is
exactly what happened in practice (see docs/architecture.md). The whole
machine restarted and neither process came back, while the Docker
container did, because only the container had a restart policy attached
to it.

The UI's start/stop buttons shell out to `systemctl --user`, they do not
spawn or kill the process directly. Doing that instead would fight
systemd: if the UI killed the process with a raw signal, systemd's
`Restart=on-failure` would treat that as a crash and immediately bring it
back, undoing the "stop" the user asked for. Letting systemd own the
process lifecycle end to end (boot, crash recovery, explicit start/stop)
means there is exactly one supervisor, not two disagreeing ones.
"""

from __future__ import annotations

import subprocess

from ct_hunter.process.state import DATA_DIR, read_status

PROJECT_ROOT = DATA_DIR.parent

HUNT_SERVICE = "ct-hunter-hunt.service"
SYSTEMCTL_TIMEOUT_SECONDS = 10


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", "--user", *args],
        capture_output=True, text=True, timeout=SYSTEMCTL_TIMEOUT_SECONDS,
    )


def hunt_is_active() -> bool:
    try:
        result = _systemctl("is-active", HUNT_SERVICE)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.stdout.strip() == "active"


def start_hunt() -> None:
    _systemctl("start", HUNT_SERVICE)


def stop_hunt() -> bool:
    if not hunt_is_active():
        return False
    _systemctl("stop", HUNT_SERVICE)
    return True


def hunt_status() -> dict:
    return {"running": hunt_is_active(), **read_status()}


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
