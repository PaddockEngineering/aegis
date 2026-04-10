"""
Aegis Layer 3 — apparmor.py
AppArmor mandatory access control module.
"""

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def command_exists(cmd: str) -> bool:
    """Return True if *cmd* is found on PATH."""
    return shutil.which(cmd) is not None


def install_package(packages: str) -> bool:
    """Install one or more packages via apt-get."""
    import os
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    result = subprocess.run(
        ["apt-get", "install", "-y", *packages.split()],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        logger.error("apt-get install failed: %s", result.stderr.strip())
        return False
    return True


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command safely; no shell=True."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def install() -> bool:
    """
    Install AppArmor packages.
    If AppArmor is already kernel-active, log and continue.
    Soft-fails if packages are unavailable (AppArmor may be built into kernel).
    """
    # Check if already active
    probe = _run(["aa-status", "--enabled"])
    if probe.returncode == 0:
        logger.info("AppArmor is already active in the kernel; skipping package install")
        return True

    logger.info("Installing AppArmor packages…")
    # Soft-fail: AppArmor may be loaded by kernel even if packages fail
    success = install_package("apparmor apparmor-profiles apparmor-profiles-extra")
    if not success:
        logger.warning(
            "AppArmor package install soft-failed; AppArmor may still be kernel-loaded"
        )
    return True  # Always return True — kernel may already have AppArmor


def configure() -> bool:
    """
    Enable and start apparmor service, then reload profiles.
    Idempotent: safe to run multiple times.
    """
    logger.info("Enabling AppArmor service…")
    enable = _run(["systemctl", "enable", "apparmor"])
    if enable.returncode != 0:
        logger.warning("systemctl enable apparmor: %s", enable.stderr.strip())

    start = _run(["systemctl", "start", "apparmor"])
    if start.returncode != 0:
        logger.warning("systemctl start apparmor: %s", start.stderr.strip())

    # Reload profiles — soft-fail (directory may be empty on minimal installs)
    reload = _run(["apparmor_parser", "-r", "/etc/apparmor.d/"])
    if reload.returncode != 0:
        logger.warning(
            "apparmor_parser reload soft-failed: %s", reload.stderr.strip()
        )
    else:
        logger.info("AppArmor profiles reloaded")

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
    except Exception as exc:  # noqa: BLE001
        return f"AppArmor status unavailable: {exc}"
