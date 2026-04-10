#!/usr/bin/env python3
"""
Aegis Layer 6 — lynis.py
Lynis system hardening auditor.

Lynis performs a local security audit and produces a hardening index score
plus a prioritized list of actionable suggestions. Complements OpenSCAP
(which checks against a specific benchmark) by giving a broader host-level
picture regardless of distro.
"""

import subprocess
from pathlib import Path
from datetime import datetime

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


LYNIS_LOG = Path("/var/log/lynis.log")
LYNIS_REPORT = Path("/var/log/lynis-report.dat")
AEGIS_REPORT_DIR = Path("/var/log/aegis/lynis")
CRON_WEEKLY = Path("/etc/cron.weekly/aegis-lynis-audit")

CRON_SCRIPT = """\
#!/bin/bash
# Aegis — Weekly Lynis system hardening audit
LOG_DIR="/var/log/aegis/lynis"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$LOG_DIR/lynis-$TIMESTAMP.log"

echo "[$(date)] Starting weekly Lynis audit..." >> "$LOG_DIR/audit.log"
nice -n 19 ionice -c3 lynis audit system --quiet --no-colors \
    --logfile "$REPORT" \
    >> "$LOG_DIR/audit.log" 2>&1

# Extract hardening index for the log
INDEX=$(grep "Hardening index" "$REPORT" 2>/dev/null | tail -1)
echo "[$(date)] $INDEX" >> "$LOG_DIR/audit.log"
echo "[$(date)] Full report: $REPORT" >> "$LOG_DIR/audit.log"
"""


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def install() -> bool:
    """
    Install Lynis.
    Prefers the official CISOfy PPA for the latest version;
    falls back to the distro package if the PPA setup fails.
    """
    if command_exists("lynis"):
        log_success("Lynis is already installed")
        return True

    log_info("Installing Lynis...")

    # Try distro package first (fast, no key setup needed)
    if install_package("lynis"):
        log_success("Lynis installed from system repos")
        return True

    # Fallback: official CISOfy repo (always up to date)
    log_info("Trying CISOfy repository for latest Lynis...")
    try:
        key_result = subprocess.run(
            ["wget", "-qO", "-", "https://packages.cisofy.com/keys/cisofy-software-public.key"],
            capture_output=True,
            timeout=30,
        )
        if key_result.returncode != 0:
            log_warning("Could not download CISOfy key — using distro version")
            return install_package("lynis")

        keyring = Path("/usr/share/keyrings/cisofy-lynis.gpg")
        dearmor = subprocess.run(
            ["gpg", "--dearmor"],
            input=key_result.stdout,
            capture_output=True,
            timeout=10,
        )
        if dearmor.returncode != 0:
            log_warning("GPG dearmor failed — using distro version")
            return install_package("lynis")

        keyring.write_bytes(dearmor.stdout)
        keyring.chmod(0o644)

        codename_result = _run(["lsb_release", "-sc"], timeout=5)
        codename = codename_result.stdout.strip() if codename_result.returncode == 0 else "noble"

        sources = Path("/etc/apt/sources.list.d/cisofy-lynis.list")
        sources.write_text(
            f"deb [signed-by={keyring}] https://packages.cisofy.com/community/lynis/deb/ {codename} main\n",
            encoding="utf-8",
        )
        sources.chmod(0o644)

        subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=60)
        if install_package("lynis"):
            log_success("Lynis installed from CISOfy repository")
            return True

    except Exception as e:
        log_warning(f"CISOfy repo setup failed ({e}) — trying distro package")
        return install_package("lynis")

    log_error("Failed to install Lynis")
    return False


def _run_audit(report_path: Path | None = None) -> bool:
    """Run a Lynis audit, optionally writing the log to *report_path*."""
    cmd = ["lynis", "audit", "system", "--quiet", "--no-colors"]
    if report_path:
        cmd += ["--logfile", str(report_path)]

    log_info("Running Lynis audit (this takes 1-2 minutes)...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        # Lynis exits non-zero when suggestions exist — that's normal
        return True
    except subprocess.TimeoutExpired:
        log_warning("Lynis audit timed out")
        return False
    except Exception as e:
        log_error(f"Lynis audit failed: {e}")
        return False


def configure() -> bool:
    """
    Run an initial Lynis audit, save the report, and install a weekly cron job.
    Idempotent: safe to re-run.
    """
    if not command_exists("lynis"):
        log_error("Lynis not found — run install first")
        return False

    AEGIS_REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Run initial audit
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = AEGIS_REPORT_DIR / f"lynis-initial-{timestamp}.log"
    _run_audit(report_path)

    # Extract and display hardening index
    if report_path.exists():
        content = report_path.read_text(errors="replace")
        for line in reversed(content.splitlines()):
            if "Hardening index" in line:
                log_success(f"Lynis audit complete — {line.strip()}")
                break
        else:
            log_success(f"Lynis audit complete — report saved to {report_path}")
    else:
        log_info("Lynis audit ran (report may be at /var/log/lynis.log)")

    # Install weekly cron
    try:
        CRON_WEEKLY.write_text(CRON_SCRIPT, encoding="utf-8")
        CRON_WEEKLY.chmod(0o755)
        log_success(f"Weekly Lynis audit scheduled at {CRON_WEEKLY}")
    except Exception as e:
        log_warning(f"Could not write weekly cron job: {e}")

    log_info(f"Review suggestions: sudo lynis show details <TEST-ID>")
    return True


def check() -> bool:
    """Return True if lynis is installed."""
    return command_exists("lynis")


def status() -> str:
    """Return Lynis version and last hardening index if available."""
    parts = []

    result = _run(["lynis", "--version"], timeout=5)
    if result.returncode == 0:
        parts.append(f"Lynis: {result.stdout.strip()}")
    else:
        return "Lynis is not installed"

    # Find most recent report
    try:
        reports = sorted(AEGIS_REPORT_DIR.glob("lynis-*.log"), reverse=True)
        if reports:
            content = reports[0].read_text(errors="replace")
            for line in reversed(content.splitlines()):
                if "Hardening index" in line:
                    parts.append(f"Last audit: {line.strip()} ({reports[0].name})")
                    break
        elif LYNIS_REPORT.exists():
            parts.append(f"Report available at {LYNIS_REPORT}")
        else:
            parts.append("No audit reports found — run configure to run initial audit")
    except Exception:
        pass

    return "\n".join(parts)
