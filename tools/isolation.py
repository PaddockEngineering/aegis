#!/usr/bin/env python3
"""Process isolation module - Firejail setup."""

import subprocess
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


# Firejail profile directories
PROFILE_DIR = Path("/etc/firejail")
LOCAL_PROFILE_DIR = Path("/usr/local/etc/firejail")


def install():
    """Install Firejail."""
    log_info("Installing Firejail...")

    if not install_package("firejail"):
        log_error("Failed to install Firejail")
        return False

    log_success("Firejail installed")
    return True


def configure():
    """
    Configure Firejail with sensible hardening defaults.

    Writes /etc/firejail/firejail.config to enable:
      - private-dev by default (restrict /dev access)
      - restrict-namespaces (prevent namespace escapes)
      - seccomp by default (system call filter)
    Idempotent: safe to run multiple times.
    """
    if not command_exists("firejail"):
        log_warning("Firejail not found — skipping configuration (run install first)")
        return False

    config_path = Path("/etc/firejail/firejail.config")

    # Aegis defaults — conservative, compatible with most desktop apps
    config_content = """\
# /etc/firejail/firejail.config — managed by Aegis
# Restrict /dev access in all sandboxes by default
private-dev yes
# Block namespace escapes
restrict-namespaces yes
# Apply seccomp syscall filter by default
seccomp yes
# Do not allow shells inside sandboxes
shell none
"""

    try:
        PROFILE_DIR.mkdir(parents=True, exist_ok=True)

        # Backup existing config if present
        if config_path.exists():
            backup = config_path.with_suffix(".aegis-backup")
            import shutil
            shutil.copy2(str(config_path), str(backup))
            log_info(f"Backed up existing config to {backup}")

        config_path.write_text(config_content, encoding="utf-8")
        config_path.chmod(0o644)
        log_success(f"Firejail global config written to {config_path}")

        # Verify firejail works
        result = subprocess.run(
            ["firejail", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version_line = result.stdout.splitlines()[0] if result.stdout else "unknown"
            log_success(f"Firejail active — {version_line}")

        return True

    except PermissionError:
        log_error("Permission denied — run Aegis with sudo")
        return False
    except Exception as e:
        log_error(f"Firejail configuration failed: {e}")
        return False


def check():
    """Check if Firejail is installed."""
    return command_exists("firejail")


def status():
    """Show Firejail status."""
    if not command_exists("firejail"):
        return "Firejail is not installed"

    try:
        result = subprocess.run(
            ["firejail", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = result.stdout.splitlines()[0] if result.stdout else "unknown version"
        config_path = Path("/etc/firejail/firejail.config")
        config_status = "Aegis config present" if config_path.exists() else "no Aegis config"
        return f"Firejail installed ({version}) — {config_status}"
    except Exception as e:
        return f"Firejail installed but status check failed: {e}"
