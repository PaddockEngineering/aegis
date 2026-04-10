"""
Aegis Layer 3 — smartmontools.py
Disk S.M.A.R.T. health monitoring module.
"""

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SMARTD_CONF = Path("/etc/smartd.conf")
SMARTD_CONF_BACKUP = Path("/etc/smartd.conf.aegis-backup")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def command_exists(cmd: str) -> bool:
    """Return True if *cmd* is found on PATH."""
    return shutil.which(cmd) is not None


def install_package(packages: str) -> bool:
    """Install one or more packages via apt-get."""
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    result = subprocess.run(
        ["apt-get", "install", "-y", *packages.split()],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        logger.error("apt-get install failed: %s", result.stderr.strip())
        return False
    return True


def _backup_file(path: Path) -> Path | None:
    """Backup *path* with an .aegis-backup suffix; return backup path or None."""
    if not path.exists():
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_suffix(f".{timestamp}.aegis-backup")
    shutil.copy2(str(path), str(backup))
    logger.info("Backed up %s -> %s", path, backup)
    return backup


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command with safe defaults; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def install() -> bool:
    """Install smartmontools package."""
    logger.info("Installing smartmontools…")
    install_package("smartmontools")
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
                if parts:
                    dev = parts[0]
                    if dev.startswith("/dev/"):
                        devices.append(dev)
                        logger.debug("Detected drive: %s", dev)

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
            lines.append(
                f"{dev} -H -l error -l selftest -C 194 -W 2,40,45 -m root"
            )
        logger.info("Configured smartd for %d device(s): %s", len(devices), devices)
    else:
        lines.append(
            "DEVICESCAN -H -l error -l selftest -C 194 -W 2,40,45 -m root"
        )
        logger.warning("No drives detected via smartctl --scan; using DEVICESCAN fallback")

    SMARTD_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(SMARTD_CONF, 0o644)
    logger.info("Wrote %s", SMARTD_CONF)

    # Enable and start service
    for args in (["systemctl", "enable", "smartd"], ["systemctl", "restart", "smartd"]):
        result = _run(args)
        if result.returncode != 0:
            logger.error("Command failed %s: %s", args, result.stderr.strip())

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
