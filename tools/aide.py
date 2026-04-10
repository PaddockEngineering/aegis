#!/usr/bin/env python3
"""
Aegis Layer 5 — aide.py
AIDE file integrity monitoring module.
"""

import subprocess
from datetime import datetime
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


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


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command safely; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def install() -> bool:
    """Install AIDE and aide-common packages."""
    log_info("Installing aide aide-common...")
    if not install_package("aide aide-common"):
        log_error("Failed to install AIDE")
        return False
    log_success("AIDE installed")
    return True


def configure() -> bool:
    """
    Write Aegis AIDE config, initialise the database, and install a daily cron job.
    Idempotent: backs up existing aegis.conf before overwriting.
    """
    import shutil

    # Ensure config directory exists
    AIDE_CONF_DIR.mkdir(parents=True, exist_ok=True)

    # Backup existing Aegis AIDE config if present
    if AIDE_CONF.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = AIDE_CONF.with_suffix(f".{timestamp}.aegis-backup")
        shutil.copy2(str(AIDE_CONF), str(backup))
        log_info(f"Backed up {AIDE_CONF} -> {backup}")

    # Write config
    AIDE_CONF.write_text(AIDE_CONF_CONTENT, encoding="utf-8")
    AIDE_CONF.chmod(0o644)
    log_info(f"Wrote AIDE config to {AIDE_CONF}")

    # Initialise database (may take 1-2 minutes on large filesystems)
    log_info("Initialising AIDE database — this may take 1-2 minutes...")
    try:
        # Try with -y -f flags first; fall back to bare aideinit
        init_result = subprocess.run(
            ["aideinit", "-y", "-f"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if init_result.returncode != 0:
            log_warning(f"aideinit -y -f failed (exit {init_result.returncode}), trying plain aideinit...")
            init_result = subprocess.run(
                ["aideinit"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if init_result.returncode != 0:
                log_warning(f"aideinit returned non-zero: {init_result.stderr.strip()}")
            else:
                log_success("AIDE database initialised")
        else:
            log_success("AIDE database initialised")
    except subprocess.TimeoutExpired:
        log_warning("aideinit timed out — database may be initialised on next run")

    # Copy new DB into place
    if AIDE_DB_NEW.exists():
        result = _run(["cp", "-f", str(AIDE_DB_NEW), str(AIDE_DB)])
        if result.returncode != 0:
            log_warning(f"Failed to copy AIDE database: {result.stderr.strip()}")
        else:
            log_info(f"AIDE database installed at {AIDE_DB}")
    else:
        log_warning(f"AIDE new database not found at {AIDE_DB_NEW}; skipping copy")

    # Install daily cron job
    CRON_DAILY.write_text(CRON_SCRIPT, encoding="utf-8")
    CRON_DAILY.chmod(0o755)
    log_success(f"Daily AIDE integrity check installed at {CRON_DAILY}")

    return True


def check() -> bool:
    """Return True if aide is available."""
    return command_exists("aide")


def status() -> str:
    """Report AIDE database existence, size, and modification date."""
    if not AIDE_DB.exists():
        return f"AIDE database not found at {AIDE_DB} — run configure() to initialise"

    stat = AIDE_DB.stat()
    size_kb = stat.st_size // 1024
    mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    return f"AIDE database: {AIDE_DB} | size: {size_kb} KB | last modified: {mtime}"
