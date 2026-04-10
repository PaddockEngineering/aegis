#!/usr/bin/env python3
"""
Aegis Layer 5 — smartmontools.py
Disk S.M.A.R.T. health monitoring module.
"""

import subprocess
from datetime import datetime
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


SMARTD_CONF = Path("/etc/smartd.conf")


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command with safe defaults; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def _backup_file(path: Path) -> Path | None:
    """Backup *path* with a timestamped .aegis-backup suffix; return backup path or None."""
    if not path.exists():
        return None
    import shutil
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_suffix(f".{timestamp}.aegis-backup")
    shutil.copy2(str(path), str(backup))
    log_info(f"Backed up {path} -> {backup}")
    return backup


def install() -> bool:
    """Install smartmontools package."""
    log_info("Installing smartmontools...")
    if not install_package("smartmontools"):
        log_error("Failed to install smartmontools")
        return False
    log_success("smartmontools installed")
    return True


def configure() -> bool:
    """
    Detect drives, write /etc/smartd.conf, enable and start smartd.
    Idempotent: backs up existing config before overwriting.
    """
    # Detect drives
    devices: list[str] = []
    if command_exists("smartctl"):
        scan = _run(["smartctl", "--scan"])
        if scan.returncode == 0:
            for line in scan.stdout.splitlines():
                parts = line.split()
                if parts and parts[0].startswith("/dev/"):
                    devices.append(parts[0])

    # Backup existing config
    _backup_file(SMARTD_CONF)

    # Build config content
    lines: list[str] = [
        "# /etc/smartd.conf — managed by Aegis",
        f"# Generated: {datetime.now().isoformat()}",
        "",
    ]
    if devices:
        for dev in devices:
            # -H: health check  -l: log errors+self-tests  -C: temperature attr
            # -W 2,40,45: warn at +2°C / 40°C / crit at 45°C  -m root: mail root
            lines.append(f"{dev} -H -l error -l selftest -C 194 -W 2,40,45 -m root")
        log_info(f"Configured smartd for {len(devices)} device(s): {devices}")
    else:
        lines.append("DEVICESCAN -H -l error -l selftest -C 194 -W 2,40,45 -m root")
        log_warning("No drives detected via smartctl --scan; using DEVICESCAN fallback")

    SMARTD_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")
    SMARTD_CONF.chmod(0o644)
    log_info(f"Wrote {SMARTD_CONF}")

    # Enable and start service
    for args in (["systemctl", "enable", "smartd"], ["systemctl", "restart", "smartd"]):
        result = _run(args)
        if result.returncode != 0:
            log_warning(f"{' '.join(args)} failed: {result.stderr.strip()}")

    log_success("smartd enabled and monitoring disk health")
    return True


def check() -> bool:
    """Return True if smartctl is available."""
    return command_exists("smartctl")


def status() -> str:
    """Return monitored devices and smartd service state."""
    parts: list[str] = []

    scan = _run(["smartctl", "--scan"])
    if scan.returncode == 0 and scan.stdout.strip():
        parts.append("Monitored devices:\n" + scan.stdout.strip())
    else:
        parts.append("Monitored devices: (none detected or smartctl unavailable)")

    active = _run(["systemctl", "is-active", "smartd"])
    parts.append(f"smartd service: {active.stdout.strip() or 'unknown'}")

    return "\n".join(parts)
