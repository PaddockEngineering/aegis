#!/usr/bin/env python3
"""System utilities for Aegis."""

import os
import subprocess
from pathlib import Path


def is_root():
    """Check if running as root."""
    return os.geteuid() == 0


def check_sudo():
    """Check if sudo is available without password."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_os_info():
    """Get OS information from /etc/os-release."""
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    info[key] = value.strip('"')
    except FileNotFoundError:
        pass
    return info


def is_debian_based():
    """Check if system is Debian-based."""
    return Path("/etc/debian_version").exists()


def command_exists(cmd):
    """Check if a command exists in PATH."""
    try:
        result = subprocess.run(
            ["which", cmd],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_log_dir():
    """Get or create Aegis log directory."""
    log_dir = Path.home() / ".aegis" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def require_root():
    """Exit if not running as root."""
    if not is_root():
        print("Error: Aegis requires root privileges. Run with sudo.")
        exit(1)
