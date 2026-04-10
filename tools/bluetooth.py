#!/usr/bin/env python3
"""Bluetooth security controls module - User-controlled settings."""

import subprocess
from pathlib import Path
from utils.logger import log_info, log_success, log_error, log_warning
from utils.system import command_exists


def check():
    """Check if Bluetooth hardware exists."""
    try:
        result = subprocess.run(
            ["bluetoothctl", "list"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_bluetooth_status():
    """Get current Bluetooth status."""
    try:
        result = subprocess.run(
            ["bluetoothctl", "show"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            status = {}
            for line in result.stdout.split('\n'):
                if '\t' in line:
                    key, value = line.split('\t', 1)
                    status[key.strip()] = value.strip()
            return status
        return {}
    except Exception:
        return {}


def backup_bluetooth_config():
    """Backup Bluetooth config before modifications."""
    config_file = Path("/etc/bluetooth/main.conf")

    if not config_file.exists():
        return None

    try:
        backup_path = Path(f"{config_file}.aegis-backup")

        with open(config_file, "r") as src:
            content = src.read()

        with open(backup_path, "w") as dst:
            dst.write(content)

        backup_path.chmod(0o644)
        log_success("Bluetooth config backed up")
        return backup_path

    except Exception as e:
        log_error(f"Failed to backup Bluetooth config: {e}")
        return None


def disable_service():
    """Disable Bluetooth service."""
    log_info("Disabling Bluetooth service...")

    try:
        result = subprocess.run(
            ["systemctl", "disable", "bluetooth"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to disable bluetooth service")
            return False

        result = subprocess.run(
            ["systemctl", "stop", "bluetooth"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to stop bluetooth service")
            return False

        log_success("Bluetooth service disabled")
        return True

    except Exception as e:
        log_error(f"Failed to disable Bluetooth: {e}")
        return False


def harden_bluetooth_config():
    """Harden Bluetooth configuration."""
    log_info("Hardening Bluetooth configuration...")

    try:
        config_file = Path("/etc/bluetooth/main.conf")

        if not config_file.exists():
            log_warning("Bluetooth main.conf not found")
            return False

        # Backup
        backup_bluetooth_config()

        # Read config
        with open(config_file, "r") as f:
            lines = f.readlines()

        # Settings to apply
        hardened_settings = {
            "Discoverable": "false",  # Not discoverable to strangers
            "PairableTimeout": "0",   # No auto-pairing
            "RememberPaired": "false", # Don't auto-connect
        }

        # Parse and update config
        output_lines = []
        found_settings = set()

        for line in lines:
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                output_lines.append(line)
                continue

            # Check if line is a setting we want to harden
            is_setting = False
            for key, value in hardened_settings.items():
                if stripped.startswith(f"{key}"):
                    # Update the setting
                    output_lines.append(f"{key}={value}\n")
                    found_settings.add(key)
                    is_setting = True
                    break

            if not is_setting:
                output_lines.append(line)

        # Add any missing hardened settings
        if found_settings != set(hardened_settings.keys()):
            output_lines.append("\n")
            for key in hardened_settings:
                if key not in found_settings:
                    output_lines.append(f"{key}={hardened_settings[key]}\n")

        # Write updated config
        with open(config_file, "w") as f:
            f.writelines(output_lines)

        config_file.chmod(0o644)
        log_success("Bluetooth configuration hardened")
        return True

    except PermissionError:
        log_error("Permission denied - need sudo")
        return False
    except Exception as e:
        log_error(f"Bluetooth hardening failed: {e}")
        return False


def show_interactive_options():
    """Show Bluetooth security options to user."""
    print("\n╔═══════════════════════════════════════════════════════════╗")
    print("║          Bluetooth Security Configuration Options         ║")
    print("╠═══════════════════════════════════════════════════════════╣")
    print("║                                                           ║")
    print("║  1. Disable Bluetooth entirely (if not needed)            ║")
    print("║     - Removes wireless attack surface                     ║")
    print("║     - Can be re-enabled later                             ║")
    print("║                                                           ║")
    print("║  2. Harden Bluetooth configuration (keep enabled)         ║")
    print("║     - Set non-discoverable mode                           ║")
    print("║     - Disable auto-pairing                                ║")
    print("║     - Existing devices will still work                    ║")
    print("║                                                           ║")
    print("║  3. Keep current Bluetooth settings                       ║")
    print("║     - No changes (least secure)                           ║")
    print("║                                                           ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")


def configure():
    """Configure Bluetooth security (interactive)."""
    if not check():
        log_warning("Bluetooth hardware not detected or not available")
        return True

    status = get_bluetooth_status()
    if status:
        log_info(f"Current Bluetooth status: Powered={status.get('Powered', '?')}, "
                f"Discoverable={status.get('Discoverable', '?')}")

    show_interactive_options()

    while True:
        choice = input("Select option (1, 2, or 3): ").strip()

        if choice == "1":
            log_info("Disabling Bluetooth...")
            if disable_service():
                log_success("Bluetooth service disabled")
                return True
            else:
                log_error("Failed to disable Bluetooth")
                return False

        elif choice == "2":
            log_info("Hardening Bluetooth configuration...")
            if harden_bluetooth_config():
                log_success("Bluetooth hardened and service will be configured")
                # Try to restart bluetooth if it's running
                try:
                    subprocess.run(
                        ["systemctl", "restart", "bluetooth"],
                        capture_output=True,
                        timeout=10
                    )
                except Exception:
                    pass
                return True
            else:
                log_error("Failed to harden Bluetooth")
                return False

        elif choice == "3":
            log_info("Keeping current Bluetooth settings")
            return True

        else:
            print("  Invalid choice. Please enter 1, 2, or 3.")


def status():
    """Show Bluetooth security status."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "bluetooth"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            service_status = "active"

            # Get detailed status
            status_dict = get_bluetooth_status()
            powered = status_dict.get("Powered", "unknown")
            discoverable = status_dict.get("Discoverable", "unknown")

            return f"Bluetooth is {service_status} (Powered={powered}, Discoverable={discoverable})"
        else:
            return "Bluetooth is inactive (service disabled for security)"

    except Exception as e:
        return f"Unable to check Bluetooth status: {e}"
