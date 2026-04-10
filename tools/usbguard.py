#!/usr/bin/env python3
"""
Aegis Layer 3 — usbguard.py
USBGuard device authorization policy module.

Blocks unauthorized USB devices at the kernel level. Prevents BadUSB,
rubber ducky, and rogue HID attacks on unattended machines.
"""

import subprocess
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


RULES_FILE = Path("/etc/usbguard/rules.conf")
DAEMON_CONF = Path("/etc/usbguard/usbguard-daemon.conf")

# Default policy: allow all currently connected devices, block everything new.
# This is the safest first-run policy — it won't lock the user out of their
# existing keyboard/mouse, but will block any new device plugged in afterwards.
DEFAULT_POLICY = "allow"   # "allow" | "block"


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def _list_current_devices() -> list[str]:
    """Return usbguard policy lines for all currently connected USB devices."""
    result = _run(["usbguard", "generate-policy"], timeout=15)
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def install() -> bool:
    """Install USBGuard."""
    log_info("Installing USBGuard...")
    if not install_package("usbguard"):
        log_error("Failed to install USBGuard")
        return False
    log_success("USBGuard installed")
    return True


def configure(unattended: bool = False) -> bool:
    """
    Generate an allow-list for currently connected devices, write rules,
    then enable and start the daemon.

    Interactive mode: asks whether to block all new devices or allow by default.
    Unattended mode: generates policy for current devices, blocks everything new.

    Idempotent: backs up existing rules before overwriting.
    """
    if not command_exists("usbguard"):
        log_error("USBGuard not found — run install first")
        return False

    # Generate policy for currently connected devices
    log_info("Scanning currently connected USB devices...")
    current_devices = _list_current_devices()

    if not current_devices:
        log_warning(
            "No USB devices detected by usbguard generate-policy. "
            "This may mean the daemon isn't started yet — continuing with empty allow-list."
        )

    if not unattended:
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║           USBGuard — USB Device Policy                  ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║                                                          ║")
        print("║  Currently connected devices will be ALLOWED.            ║")
        print("║  What should happen when a NEW device is plugged in?     ║")
        print("║                                                          ║")
        print("║  1. Block new devices (most secure — recommended)        ║")
        print("║     Authorize manually with: usbguard allow-device <id>  ║")
        print("║                                                          ║")
        print("║  2. Allow new devices (less secure, more convenient)     ║")
        print("║     Any USB device plugged in will be authorized.        ║")
        print("║                                                          ║")
        print("╚══════════════════════════════════════════════════════════╝\n")

        while True:
            choice = input("Select option (1 or 2): ").strip()
            if choice == "1":
                default_policy = "block"
                break
            elif choice == "2":
                default_policy = "allow"
                break
            else:
                print("  Please enter 1 or 2.")
    else:
        log_info("Unattended mode — blocking all new USB devices")
        default_policy = "block"

    # Build rules file
    lines = ["# /etc/usbguard/rules.conf — managed by Aegis"]
    lines += current_devices
    lines.append(f"\n# Default policy for unrecognized devices")
    lines.append(f"{default_policy} id *:* label \"unrecognized\"")
    rules_content = "\n".join(lines) + "\n"

    try:
        # Backup existing rules
        if RULES_FILE.exists():
            import shutil, datetime
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = RULES_FILE.with_suffix(f".{ts}.aegis-backup")
            shutil.copy2(str(RULES_FILE), str(backup))
            log_info(f"Backed up existing rules to {backup}")

        RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        RULES_FILE.write_text(rules_content, encoding="utf-8")
        RULES_FILE.chmod(0o600)
        log_success(f"USBGuard rules written ({len(current_devices)} device(s) allowed, default: {default_policy})")

        # Enable and start daemon
        for action in ("enable", "restart"):
            result = _run(["systemctl", action, "usbguard"], timeout=15)
            if result.returncode != 0:
                log_warning(f"systemctl {action} usbguard: {result.stderr.strip()}")

        log_success("USBGuard daemon active")
        if default_policy == "block":
            log_info("To authorize a new device: sudo usbguard allow-device <id>")
            log_info("To list pending devices:   sudo usbguard list-devices --blocked")

        return True

    except PermissionError:
        log_error("Permission denied — run Aegis with sudo")
        return False
    except Exception as e:
        log_error(f"USBGuard configuration failed: {e}")
        return False


def check() -> bool:
    """Return True if usbguard is installed."""
    return command_exists("usbguard")


def status() -> str:
    """Return USBGuard daemon state and current device count."""
    parts = []

    active = _run(["systemctl", "is-active", "usbguard"], timeout=5)
    parts.append(f"usbguard daemon: {active.stdout.strip() or 'unknown'}")

    if command_exists("usbguard"):
        devices = _run(["usbguard", "list-devices"], timeout=5)
        if devices.returncode == 0:
            count = len([l for l in devices.stdout.splitlines() if l.strip()])
            parts.append(f"Authorized devices: {count}")

        if RULES_FILE.exists():
            rule_count = len([
                l for l in RULES_FILE.read_text().splitlines()
                if l.strip() and not l.startswith("#")
            ])
            parts.append(f"Rules file: {RULES_FILE} ({rule_count} rules)")
        else:
            parts.append(f"Rules file: not found at {RULES_FILE}")

    return "\n".join(parts)
