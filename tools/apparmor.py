#!/usr/bin/env python3
"""
Aegis Layer 3 — apparmor.py
AppArmor mandatory access control module.
"""

import subprocess

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command safely; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def install() -> bool:
    """
    Install AppArmor packages.
    If AppArmor is already kernel-active, log and continue.
    Soft-fails if packages are unavailable (AppArmor may be built into the kernel).
    """
    # Check if already active
    probe = _run(["aa-status", "--enabled"])
    if probe.returncode == 0:
        log_info("AppArmor is already active in the kernel — skipping package install")
        return True

    log_info("Installing AppArmor packages...")
    # Soft-fail: AppArmor may be loaded by kernel even if packages are not present
    if not install_package("apparmor apparmor-profiles apparmor-profiles-extra"):
        log_warning("AppArmor package install soft-failed; AppArmor may still be kernel-loaded")
    else:
        log_success("AppArmor packages installed")
    return True


def configure() -> bool:
    """
    Enable and start apparmor service, then reload all profiles.
    Idempotent: safe to run multiple times.
    """
    log_info("Enabling AppArmor service...")
    enable = _run(["systemctl", "enable", "apparmor"])
    if enable.returncode != 0:
        log_warning(f"systemctl enable apparmor: {enable.stderr.strip()}")

    start = _run(["systemctl", "start", "apparmor"])
    if start.returncode != 0:
        log_warning(f"systemctl start apparmor: {start.stderr.strip()}")

    # Reload profiles — soft-fail (directory may be empty on minimal installs)
    reload = _run(["apparmor_parser", "-r", "/etc/apparmor.d/"])
    if reload.returncode != 0:
        log_warning(f"apparmor_parser reload soft-failed: {reload.stderr.strip()}")
    else:
        log_success("AppArmor profiles reloaded")

    return True


def check() -> bool:
    """Return True if aa-status is available."""
    return command_exists("aa-status")


def status() -> str:
    """Return AppArmor status summary."""
    try:
        summary = _run(["aa-status", "--summary"])
        if summary.returncode == 0 and summary.stdout.strip():
            return summary.stdout.strip()

        # Fallback: full aa-status, first 20 lines
        full = _run(["aa-status"])
        lines = full.stdout.splitlines()[:20]
        return "\n".join(lines) if lines else "aa-status returned no output"
    except Exception as exc:
        return f"AppArmor status unavailable: {exc}"
