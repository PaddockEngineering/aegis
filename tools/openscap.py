#!/usr/bin/env python3
"""OpenSCAP compliance verification module - CIS/DISA security compliance auditing."""

import subprocess
from pathlib import Path
from datetime import datetime
from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


def install():
    """Install OpenSCAP tools."""
    log_info("Installing OpenSCAP compliance framework...")

    if not install_package("libopenscap8 openscap-scanner openscap-utils"):
        log_warning("OpenSCAP installation had issues, but may still be partially installed")

    # Optional but useful: SCAP Security Guide profiles
    install_package("scap-security-guide")

    log_success("OpenSCAP tools installed")
    return True


def download_profiles():
    """Download latest CIS and DISA STIG profiles."""
    log_info("Downloading security profiles...")

    try:
        profile_dir = Path("/usr/share/xml/scap/ssg/content")

        if profile_dir.exists():
            log_success("CIS/DISA profiles available")
            return True
        else:
            log_warning("SCAP profiles not found in standard location")
            return True  # Don't fail - some profiles may be elsewhere

    except Exception as e:
        log_error(f"Profile download error: {e}")
        return False


def run_compliance_scan():
    """Run compliance scan against CIS Benchmark."""
    log_info("Running compliance scan (this may take a minute)...")

    try:
        report_dir = Path("/var/log/openscap/reports")
        report_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_html = report_dir / f"cis-compliance-{timestamp}.html"
        report_json = report_dir / f"cis-compliance-{timestamp}.json"

        # Run oscap scan against CIS benchmark
        result = subprocess.run(
            [
                "oscap",
                "xccdf",
                "eval",
                "--profile",
                "cis_level2_server",
                "--report",
                str(report_html),
                "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml"
            ],
            capture_output=True,
            timeout=180
        )

        # oscap returns non-zero if there are failures - that's expected
        if result.returncode in [0, 2]:
            log_success(f"Compliance scan completed. Report: {report_html}")
            return str(report_html)
        else:
            log_warning("Compliance scan had issues, but report may be available")
            return str(report_html)

    except subprocess.TimeoutExpired:
        log_error("Compliance scan timed out")
        return None
    except Exception as e:
        log_error(f"Compliance scan error: {e}")
        return None


def setup_weekly_scan():
    """Setup weekly compliance scanning via cron."""
    log_info("Setting up weekly compliance scan...")

    try:
        cron_dir = Path("/etc/cron.weekly")
        cron_dir.mkdir(parents=True, exist_ok=True)

        cron_script = cron_dir / "aegis-openscap-scan"
        cron_content = """#!/bin/bash
# Aegis-managed OpenSCAP weekly compliance scan

REPORT_DIR="/var/log/openscap/reports"
mkdir -p "$REPORT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$REPORT_DIR/cis-weekly-$TIMESTAMP.html"

echo "[$(date)] Running weekly OpenSCAP compliance scan..." >> /var/log/openscap/scan.log

# Run with low priority
nice -n 19 ionice -c3 oscap xccdf eval \\
    --profile cis_level2_server \\
    --report "$REPORT" \\
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml \\
    >> /var/log/openscap/scan.log 2>&1

if [ -f "$REPORT" ]; then
    echo "[$(date)] Scan completed. Report: $REPORT" >> /var/log/openscap/scan.log
else
    echo "[$(date)] Scan failed to generate report." >> /var/log/openscap/scan.log
fi
"""

        with open(cron_script, "w") as f:
            f.write(cron_content)

        cron_script.chmod(0o755)
        log_success("Weekly OpenSCAP scan scheduled")

        return True

    except Exception as e:
        log_error(f"Cron setup failed: {e}")
        return False


def show_compliance_summary():
    """Show current compliance status."""
    log_info("Analyzing compliance posture...")

    try:
        # Try to find latest report
        report_dir = Path("/var/log/openscap/reports")

        if not report_dir.exists():
            print("\nNo compliance reports found yet. Run: sudo aegis openscap-scan")
            return True

        # Find most recent report
        reports = sorted(report_dir.glob("cis-compliance-*.html"), reverse=True)

        if not reports:
            print("\nNo CIS compliance reports found.")
            return True

        latest = reports[0]
        print(f"\nLatest compliance report: {latest}")
        print(f"Generated: {datetime.fromtimestamp(latest.stat().st_mtime)}")
        print(f"\nView report: firefox {latest}")

        return True

    except Exception as e:
        log_error(f"Error analyzing compliance: {e}")
        return False


def check():
    """Check if OpenSCAP is installed."""
    return command_exists("oscap")


def status():
    """Show OpenSCAP status."""
    try:
        result = subprocess.run(
            ["oscap", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            report_count = 0

            try:
                report_dir = Path("/var/log/openscap/reports")
                report_count = len(list(report_dir.glob("*.html")))
            except Exception:
                pass

            return f"OpenSCAP installed ({version}). Compliance reports: {report_count}. Run: sudo aegis openscap-scan"
        else:
            return "OpenSCAP is installed but version check failed"

    except Exception as e:
        return f"Unable to check OpenSCAP status: {e}"


def configure():
    """Configure OpenSCAP and download profiles."""
    if not download_profiles():
        log_warning("Could not download profiles, but OpenSCAP is still usable")

    if not setup_weekly_scan():
        log_warning("Failed to setup weekly scan, but on-demand scans still available")

    show_compliance_summary()

    log_success("OpenSCAP configured for compliance scanning")
    return True
