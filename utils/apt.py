#!/usr/bin/env python3
"""APT package management utilities for Aegis."""

import subprocess
from utils.logger import log_info, log_success, log_error


def update_package_list():
    """Update APT package list."""
    try:
        result = subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True,
            timeout=120
        )
        return result.returncode == 0
    except Exception as e:
        log_error(f"Failed to update package list: {e}")
        return False


def install_package(package_name, install_cmd=None):
    """Install a package via APT or custom command."""
    if install_cmd:
        try:
            result = subprocess.run(
                install_cmd,
                shell=True,
                capture_output=True,
                timeout=300
            )
            return result.returncode == 0
        except Exception as e:
            log_error(f"Custom install failed: {e}")
            return False

    packages = package_name.split()
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y"] + packages,
            capture_output=True,
            timeout=300
        )
        if result.returncode == 0:
            return True
        else:
            error_msg = result.stderr.decode() if result.stderr else "Unknown error"
            log_error(f"Failed to install {package_name}: {error_msg}")
            return False
    except subprocess.TimeoutExpired:
        log_error(f"Installation of {package_name} timed out")
        return False
    except Exception as e:
        log_error(f"Failed to install {package_name}: {e}")
        return False


def package_installed(package_name):
    """Check if a package is installed."""
    try:
        result = subprocess.run(
            ["dpkg", "-l", package_name],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_installed_version(package_name):
    """Get installed version of a package."""
    try:
        result = subprocess.run(
            ["dpkg", "-l", package_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        return None
    except Exception:
        return None
