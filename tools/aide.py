"""
Aegis Layer 3 — aide.py
AIDE file integrity monitoring module.
"""

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

AIDE_CONF_DIR = Path("/etc/aide/aide.conf.d")
AIDE_CONF = AIDE_CONF_DIR / "aegis.conf"
AIDE_DB = Path("/var/lib/aide/aide.db")
AIDE_DB_NEW = Path("/var/lib/aide/aide.db.new")
CRON_DAILY = Path("/etc/cron.daily/aegis-aide-check")

AIDE_CONF_CONTENT = """\
# Aegis AIDE configuration
# Directories to monitor with full checking (SHA512)
/usr/bin CONTENT_EX
/usr/sbin CONTENT_EX
/bin CONTENT_EX
/sbin CONTENT_EX
/etc CONTENT_EX
/boot CONTENT_EX
/home CONTENT_EX

# Exclusions
!/tmp
!/var/log
!/var/cache
!/var/run
!/proc
!/sys
!/dev
!/lost+found
"""

CRON_SCRIPT = """\
#!/bin/bash
# Aegis — Daily AIDE file integrity check (background priority)
LOG=/var/log/aide/check.log
mkdir -p /var/log/aide
echo "--- AIDE check $(date) ---" >> $LOG
nice -n 19 ionice -c 3 aide --check >> $LOG 2>&1
RC=$?
if [ $RC -eq 0 ]; then
  echo "No changes detected." >> $LOG
elif [ $RC -eq 1 ]; then
  echo "WARNING: File changes detected!" >> $LOG
else
  echo "ERROR: AIDE check failed (exit $RC)" >> $LOG
fi
"""


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


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command safely; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def install() -> bool:
    """Install AIDE and aide-common packages."""
    logger.info("Installing aide aide-common…")
    install_package("aide aide-common")
    return True


def configure() -> bool:
    """
    Write Aegis AIDE config, initialise the database, and install a daily cron job.
    Idempotent: backs up existing aegis.conf before overwriting.
    """
    # Ensure config directory exists
    AIDE_CONF_DIR.mkdir(parents=True, exist_ok=True)

    # Backup existing Aegis AIDE config if present
    if AIDE_CONF.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = AIDE_CONF.with_suffix(".{}.aegis-backup".format(timestamp))
        shutil.copy2(str(AIDE_CONF), str(backup))
        logger.info("Backed up %s -> %s", AIDE_CONF, backup)

    # Write config
    AIDE_CONF.write_text(AIDE_CONF_CONTENT, encoding="utf-8")
    os.chmod(AIDE_CONF, 0o644)
    logger.info("Wrote AIDE config to %s", AIDE_CONF)

    # Initialise database (may take 1-2 minutes)
    logger.info(
        "Initialising AIDE database — this may take 1-2 minutes on large filesystems…"
    )
    init_result = subprocess.run(
        ["aideinit", "-y", "-f"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if init_result.returncode != 0:
        logger.warning(
            "aideinit returned non-zero (%d): %s",
            init_result.returncode,
            init_result.stderr.strip(),
        )
    else:
        logger.info("AIDE database initialised successfully")

    # Copy new DB into place
    if AIDE_DB_NEW.exists():
        copy_result = _run(["cp", "-f", str(AIDE_DB_NEW), str(AIDE_DB)])
        if copy_result.returncode != 0:
            logger.warning("Failed to copy AIDE database: %s", copy_result.stderr.strip())
        else:
            logger.info("AIDE database installed at %s", AIDE_DB)
    else:
        logger.warning("AIDE new database not found at %s; skipping copy", AIDE_DB_NEW)

    # Install daily cron job
    CRON_DAILY.write_text(CRON_SCRIPT, encoding="utf-8")
    os.chmod(CRON_DAILY, 0o755)
    logger.info("Installed daily AIDE cron job at %s", CRON_DAILY)

    return True


def check() -> bool:
    """Return True if aide is available."""
    return command_exists("aide")


def status() -> str:
    """Report AIDE database existence, size, and modification date."""
    if not AIDE_DB.exists():
        return "AIDE database not found at {} — run configure() to initialise".format(AIDE_DB)

    stat = AIDE_DB.stat()
    size_kb = stat.st_size // 1024
    mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    return "AIDE database: {} | size: {} KB | last modified: {}".format(
        AIDE_DB, size_kb, mtime
    )
