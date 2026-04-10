#!/usr/bin/env python3
"""VPN setup module - AirVPN Eddie installation."""

import subprocess
from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package, package_installed, update_package_list
from utils.system import command_exists


def install():
    """Install AirVPN Eddie client."""
    log_info("Installing AirVPN Eddie...")

    # Try adding Eddie repository and installing
    try:
        # Add Eddie GPG key
        log_info("Adding AirVPN repository key...")
        key_cmd = "curl -s https://eddie.website/repository/keys/eddie.gpg.key | apt-key add -"
        result = subprocess.run(key_cmd, shell=True, capture_output=True, timeout=30)

        if result.returncode != 0:
            log_warning("Could not add GPG key automatically, trying direct install...")

        # Add repository
        log_info("Adding AirVPN repository...")
        repo_cmd = "echo 'deb https://eddie.website/repository/debian stable main' | tee /etc/apt/sources.list.d/eddie.list"
        result = subprocess.run(repo_cmd, shell=True, capture_output=True, timeout=10)

        # Update and install
        if not update_package_list():
            log_warning("Package update failed, attempting direct install anyway...")

        if not install_package("eddie-cli"):
            log_warning("Eddie package install failed, trying alternative method...")
            return False

        log_success("AirVPN Eddie installed")
        return True

    except Exception as e:
        log_error(f"Eddie installation failed: {e}")
        return False


def check():
    """Check if Eddie is installed."""
    return command_exists("eddie") or package_installed("eddie-cli")


def status():
    """Show Eddie status."""
    if command_exists("eddie"):
        return "AirVPN Eddie is installed"
    return "AirVPN Eddie is not installed"
