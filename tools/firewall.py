#!/usr/bin/env python3
"""UFW firewall module for Aegis."""

import subprocess
from utils.logger import log_info, log_success, log_error
from utils.apt import install_package
from utils.system import command_exists


def install():
    """Install UFW firewall."""
    log_info("Installing UFW firewall...")

    if not install_package("ufw"):
        log_error("Failed to install UFW")
        return False

    log_success("UFW installed successfully")
    return True


def configure():
    """Configure UFW with secure defaults.

    Idempotent: skips if UFW is already active.
    SSH is explicitly allowed before enabling to prevent lockout.
    """
    log_info("Configuring UFW firewall...")

    try:
        # Check idempotency — skip if already active
        result = subprocess.run(
            ["ufw", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and "Status: active" in result.stdout:
            log_success("UFW is already active — skipping configuration")
            return True

        # Default deny incoming
        result = subprocess.run(
            ["ufw", "default", "deny", "incoming"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            log_error("Failed to set default deny incoming")
            return False

        # Default allow outgoing
        result = subprocess.run(
            ["ufw", "default", "allow", "outgoing"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            log_error("Failed to set default allow outgoing")
            return False

        # Allow SSH before enabling — prevents lockout
        result = subprocess.run(
            ["ufw", "allow", "ssh"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            log_error("Failed to allow SSH — aborting to prevent lockout")
            return False

        # Enable UFW non-interactively
        result = subprocess.run(
            ["ufw", "--force", "enable"],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            log_error("Failed to enable UFW")
            return False

        log_success("UFW enabled with default deny incoming, allow outgoing, SSH permitted")
        return True

    except subprocess.TimeoutExpired:
        log_error("UFW command timed out")
        return False
    except PermissionError:
        log_error("Permission denied — run Aegis with sudo")
        return False
    except Exception as e:
        log_error(f"UFW configuration failed: {e}")
        return False


def check():
    """Check if UFW is installed."""
    return command_exists("ufw")


def status():
    """Return UFW verbose status."""
    try:
        result = subprocess.run(
            ["ufw", "status", "verbose"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return "UFW not active"
    except Exception as e:
        return f"UFW status check failed: {e}"
