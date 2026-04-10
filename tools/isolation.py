#!/usr/bin/env python3
"""Process isolation module - Firejail setup."""

from utils.logger import log_info, log_success, log_error
from utils.apt import install_package, package_installed
from utils.system import command_exists


def install():
    """Install Firejail."""
    log_info("Installing Firejail...")

    if not install_package("firejail"):
        return False

    log_success("Firejail installed")
    return True


def check():
    """Check if Firejail is installed."""
    return command_exists("firejail")


def status():
    """Show Firejail status."""
    if command_exists("firejail"):
        return "Firejail is installed"
    return "Firejail is not installed"
