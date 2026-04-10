#!/usr/bin/env python3
"""Unattended-upgrades automatic security updates module."""

import subprocess
from pathlib import Path
from utils.logger import log_info, log_success, log_error
from utils.apt import install_package, package_installed
from utils.system import command_exists


def install():
    """Install unattended-upgrades."""
    log_info("Installing unattended-upgrades...")

    if not install_package("unattended-upgrades"):
        return False

    log_success("unattended-upgrades installed")
    return True


def backup_config():
    """Backup current configuration."""
    config_file = Path("/etc/apt/apt.conf.d/50unattended-upgrades")

    if not config_file.exists():
        return None

    try:
        backup_file = Path(f"{config_file}.aegis-backup")

        with open(config_file, "r") as src:
            content = src.read()

        with open(backup_file, "w") as dst:
            dst.write(content)

        backup_file.chmod(0o644)
        log_success(f"Config backed up to {backup_file}")
        return backup_file

    except Exception as e:
        log_error(f"Failed to backup config: {e}")
        return None


def configure():
    """Configure unattended-upgrades for security updates only."""
    log_info("Configuring unattended-upgrades...")

    try:
        # Backup first
        backup_config()

        config_file = Path("/etc/apt/apt.conf.d/50unattended-upgrades")

        config_content = """// Aegis-managed unattended-upgrades configuration
// Security updates only, no automatic major version upgrades

Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};

// Package-Blacklist lets you specify packages to never upgrade
Unattended-Upgrade::Package-Blacklist {
        // Add packages here if needed
};

// Split the upgrade into the smallest possible chunks so that
// the upgrade process can be stopped whilst we reboot for security
// updates (the time window for snapd etc. to mess with your /etc
// will be minimal)
Unattended-Upgrade::MinimalSteps "true";

// Install all unattended-upgrades when the machine is shutting
// down. This will cause shutdown to take a long time.
Unattended-Upgrade::InstallOnShutdown "false";

// Send email report of what was upgraded
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "on-change";

// Remove unused kernel packages automatically
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove new unused dependencies after upgrade
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Do not remove unused dependencies if the package removed
// enhanced the system performance, even if not required.
Unattended-Upgrade::Remove-Unused-Dependencies "false";

// Automatically reboot WITHOUT CONFIRMATION if Unattended-Upgrade::Automatic-Reboot is enabled
// WARNING: This will reboot your system! Only enable after testing
Unattended-Upgrade::Automatic-Reboot "false";

// If automatic reboot is enabled and a user is logged in when
// the automatic reboot is triggered, the system will allow them
// to save their work before rebooting (default)
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";

// The time in minutes to wait before rebooting if users are still logged in.
// Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Use the DPKG::Pre-Install-Pkgs to run custom pre-upgrade checks
// (e.g., a backup of your data), and DPKG::Post-Install-Pkgs to
// run custom post-upgrade checks.

// Unattended-Upgrade::Pre-Reboot-Commands "";
// Unattended-Upgrade::Post-Reboot-Commands "";

// Verbose logging of what packages get upgraded
Unattended-Upgrade::Verbose "false";

// Unattended-Upgrade::Packages::Hold {};

// APT Periodic configuration
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
"""

        with open(config_file, "w") as f:
            f.write(config_content)

        config_file.chmod(0o644)
        log_success("unattended-upgrades configured")
        return True

    except PermissionError:
        log_error("Permission denied - need sudo")
        return False
    except Exception as e:
        log_error(f"Configuration failed: {e}")
        return False


def enable():
    """Enable unattended-upgrades."""
    log_info("Enabling unattended-upgrades...")

    try:
        # Enable the service
        result = subprocess.run(
            ["systemctl", "enable", "unattended-upgrades"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to enable unattended-upgrades")
            return False

        log_success("unattended-upgrades enabled")
        return True

    except Exception as e:
        log_error(f"Failed to enable: {e}")
        return False


def test_dry_run():
    """Test configuration with dry-run."""
    log_info("Running dry-run test...")

    try:
        result = subprocess.run(
            ["unattended-upgrades", "--dry-run", "--debug"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            log_success("Dry-run test passed")
            return True
        else:
            error_msg = result.stderr.decode() if result.stderr else "Unknown error"
            log_error(f"Dry-run test failed: {error_msg}")
            return False

    except subprocess.TimeoutExpired:
        log_error("Dry-run test timed out")
        return False
    except Exception as e:
        log_error(f"Dry-run test error: {e}")
        return False


def check():
    """Check if unattended-upgrades is installed."""
    return package_installed("unattended-upgrades")


def status():
    """Show unattended-upgrades status."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "unattended-upgrades"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            return "unattended-upgrades is active (security updates enabled)"
        else:
            return "unattended-upgrades is inactive"

    except Exception:
        return "Unable to check unattended-upgrades status"
