#!/usr/bin/env python3
"""OpenSCAP compliance verification module - CIS/DISA security compliance auditing."""

import subprocess
from pathlib import Path
from datetime import datetime

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists, get_os_info


# SCAP Security Guide content directory (installed by scap-security-guide package)
SSG_CONTENT_DIR = Path("/usr/share/xml/scap/ssg/content")

# Datastream filename per distro ID and version — extend as needed
_DATASTREAM_MAP = {
    ("ubuntu", "24"): "ssg-ubuntu2404-ds.xml",
    ("ubuntu", "22"): "ssg-ubuntu2204-ds.xml",
    ("ubuntu", "20"): "ssg-ubuntu2004-ds.xml",
    ("debian", "12"): "ssg-debian12-ds.xml",
    ("debian", "11"): "ssg-debian11-ds.xml",
    ("debian", "10"): "ssg-debian10-ds.xml",
    ("linuxmint", "22"): "ssg-ubuntu2404-ds.xml",   # Mint 22 is Ubuntu 24.04-based
    ("linuxmint", "21"): "ssg-ubuntu2204-ds.xml",   # Mint 21 is Ubuntu 22.04-based
    ("pop", "22"): "ssg-ubuntu2204-ds.xml",          # Pop!_OS 22.04
}


def _get_datastream() -> Path | None:
    """
    Detect the running distro and return the correct SSG datastream path.
    Returns None if no matching datastream is found.
    """
    info = get_os_info()
    distro_id = info.get("ID", "").lower()
    version_id = info.get("VERSION_ID", "")

    # Match on major version prefix (e.g. "24" matches "24.04")
    major = version_id.split(".")[0]

    # Direct match
    key = (distro_id, major)
    filename = _DATASTREAM_MAP.get(key)

    # Fallback: check ID_LIKE (e.g. "ubuntu" base for derivatives)
    if not filename:
        for like_id in info.get("ID_LIKE", "").lower().split():
            filename = _DATASTREAM_MAP.get((like_id, major))
            if filename:
                break

    if not filename:
        log_warning(
            f"No SSG datastream mapping for {distro_id} {version_id}. "
            "Check /usr/share/xml/scap/ssg/content/ for available files."
        )
        return None

    path = SSG_CONTENT_DIR / filename
    if not path.exists():
        log_warning(f"Expected datastream not found: {path}")
        return None

    return path


def install() -> bool:
    """Install OpenSCAP tools and the SCAP Security Guide."""
    log_info("Installing OpenSCAP compliance framework...")

    if not install_package("libopenscap8 openscap-scanner openscap-utils"):
        log_warning("OpenSCAP core package install had issues")

    # scap-security-guide provides the CIS/DISA datastreams
    install_package("scap-security-guide")

    log_success("OpenSCAP tools installed")
    return True


def _setup_weekly_scan(datastream: Path) -> bool:
    """Write a weekly cron job that scans with the correct datastream."""
    try:
        cron_dir = Path("/etc/cron.weekly")
        cron_dir.mkdir(parents=True, exist_ok=True)

        cron_script = cron_dir / "aegis-openscap-scan"
        cron_content = f"""\
#!/bin/bash
# Aegis-managed OpenSCAP weekly compliance scan
# Datastream: {datastream}

REPORT_DIR="/var/log/openscap/reports"
mkdir -p "$REPORT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$REPORT_DIR/cis-weekly-$TIMESTAMP.html"
LOG="/var/log/openscap/scan.log"

echo "[$(date)] Running weekly OpenSCAP compliance scan..." >> "$LOG"

nice -n 19 ionice -c3 oscap xccdf eval \\
    --profile cis_level2_server \\
    --report "$REPORT" \\
    {datastream} \\
    >> "$LOG" 2>&1

if [ -f "$REPORT" ]; then
    echo "[$(date)] Scan completed. Report: $REPORT" >> "$LOG"
else
    echo "[$(date)] Scan failed to generate report." >> "$LOG"
fi
"""
        cron_script.write_text(cron_content, encoding="utf-8")
        cron_script.chmod(0o755)
        log_success(f"Weekly OpenSCAP scan scheduled at {cron_script}")
        return True

    except Exception as e:
        log_error(f"Cron setup failed: {e}")
        return False


def run_compliance_scan() -> str | None:
    """Run a compliance scan against the CIS Benchmark for this distro."""
    log_info("Running compliance scan (this may take a few minutes)...")

    datastream = _get_datastream()
    if not datastream:
        log_error("Cannot run scan — no datastream found for this distro")
        return None

    try:
        report_dir = Path("/var/log/openscap/reports")
        report_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_html = report_dir / f"cis-compliance-{timestamp}.html"

        result = subprocess.run(
            [
                "oscap", "xccdf", "eval",
                "--profile", "cis_level2_server",
                "--report", str(report_html),
                str(datastream),
            ],
            capture_output=True,
            timeout=300,
        )

        # oscap returns 2 for "scan complete but failures found" — that's expected
        if result.returncode in (0, 2):
            log_success(f"Compliance scan completed. Report: {report_html}")
            return str(report_html)
        else:
            log_warning("Compliance scan returned unexpected exit code — partial report may exist")
            return str(report_html)

    except subprocess.TimeoutExpired:
        log_error("Compliance scan timed out")
        return None
    except Exception as e:
        log_error(f"Compliance scan error: {e}")
        return None


def configure() -> bool:
    """Configure OpenSCAP: verify datastream, install weekly cron."""
    datastream = _get_datastream()

    if datastream:
        log_success(f"Using datastream: {datastream}")
        _setup_weekly_scan(datastream)
    else:
        log_warning(
            "No matching SSG datastream found for this distro. "
            "On-demand scans still available once you identify the correct datastream in "
            f"{SSG_CONTENT_DIR}"
        )

    log_success("OpenSCAP configured — run a scan with: sudo oscap xccdf eval --profile cis_level2_server --report /tmp/report.html <datastream>")
    return True


def check() -> bool:
    """Check if OpenSCAP is installed."""
    return command_exists("oscap")


def status() -> str:
    """Show OpenSCAP version, detected datastream, and report count."""
    try:
        result = subprocess.run(
            ["oscap", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.splitlines()[0] if result.returncode == 0 else "unknown"

        datastream = _get_datastream()
        ds_status = str(datastream) if datastream else "no matching datastream for this distro"

        report_count = 0
        try:
            report_count = len(list(Path("/var/log/openscap/reports").glob("*.html")))
        except Exception:
            pass

        return (
            f"OpenSCAP: {version}\n"
            f"  Datastream: {ds_status}\n"
            f"  Compliance reports: {report_count}"
        )
    except Exception as e:
        return f"Unable to check OpenSCAP status: {e}"
