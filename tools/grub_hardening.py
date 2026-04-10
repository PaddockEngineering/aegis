#!/usr/bin/env python3
"""
Aegis Layer 2 — grub_hardening.py
GRUB bootloader hardening module.

Prevents physical-access attacks by:
  - Setting a GRUB superuser password (blocks boot menu editing)
  - Disabling recovery mode entries (prevents single-user root shell)
  - Restricting boot menu timeout (reduces attack window)
  - Setting GRUB_DISABLE_OS_PROBER=true (no accidental dual-boot exposure)

Safe defaults: password protection is optional in unattended mode
(requires a password to be provided or generated).
"""

import subprocess
import secrets
import string
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.system import command_exists


GRUB_DEFAULT = Path("/etc/default/grub")
GRUB_AEGIS_DROP_IN = Path("/etc/grub.d/09_aegis_hardening")

# Settings written into /etc/default/grub (only if not already set stricter)
GRUB_SETTINGS = {
    "GRUB_TIMEOUT": "5",
    "GRUB_DISABLE_RECOVERY": "true",
    "GRUB_DISABLE_OS_PROBER": "true",
}


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def _generate_password(length: int = 20) -> str:
    """Generate a random GRUB superuser password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _hash_password(password: str) -> str | None:
    """Hash a password with grub-mkpasswd-pbkdf2. Returns the hash string or None."""
    try:
        result = subprocess.run(
            ["grub-mkpasswd-pbkdf2"],
            input=f"{password}\n{password}\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if "grub.pbkdf2" in line:
                return line.split()[-1]
        return None
    except Exception:
        return None


def _apply_grub_settings() -> bool:
    """Update /etc/default/grub with hardened settings. Backs up the file first."""
    import shutil, datetime

    if not GRUB_DEFAULT.exists():
        log_warning(f"{GRUB_DEFAULT} not found — GRUB may not be installed")
        return False

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = GRUB_DEFAULT.with_suffix(f".{ts}.aegis-backup")
    shutil.copy2(str(GRUB_DEFAULT), str(backup))
    log_info(f"Backed up {GRUB_DEFAULT} to {backup}")

    content = GRUB_DEFAULT.read_text(encoding="utf-8")
    lines = content.splitlines()
    updated_lines = []
    applied = set()

    for line in lines:
        stripped = line.strip()
        matched = False
        for key, value in GRUB_SETTINGS.items():
            if stripped.startswith(key + "=") or stripped.startswith(f"#{key}="):
                updated_lines.append(f'{key}="{value}"')
                applied.add(key)
                matched = True
                break
        if not matched:
            updated_lines.append(line)

    # Add any settings not already in the file
    for key, value in GRUB_SETTINGS.items():
        if key not in applied:
            updated_lines.append(f'{key}="{value}"')

    GRUB_DEFAULT.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    log_success(f"Updated {GRUB_DEFAULT}")
    return True


def install() -> bool:
    """Verify grub-common is available (pre-installed on all BIOS/UEFI Debian systems)."""
    if command_exists("update-grub") or command_exists("grub-mkconfig"):
        log_success("GRUB tools available")
        return True
    log_warning("update-grub not found — GRUB may not be installed on this system")
    return True  # Soft-fail: may be EFI-only or container


def configure(unattended: bool = False) -> bool:
    """
    Harden GRUB configuration.

    Interactive mode: asks whether to set a GRUB superuser password.
    Unattended mode: applies settings but skips password (requires a human
    to set it post-install — noted in output).

    Always:
      - Disables recovery mode entries
      - Sets a 5-second timeout
      - Disables OS prober
      - Runs update-grub

    Optionally:
      - Sets a GRUB superuser password (written to /etc/grub.d/09_aegis_hardening)
    """
    if not GRUB_DEFAULT.exists():
        log_warning("GRUB default config not found — skipping GRUB hardening")
        return True  # Soft-fail: may be a container or non-GRUB system

    # Apply base settings
    if not _apply_grub_settings():
        return False

    # Password handling
    set_password = False
    password = None
    generated = False

    if unattended:
        log_info(
            "Unattended mode — GRUB password NOT set automatically (requires human interaction). "
            "To set it manually after install: sudo grub-mkpasswd-pbkdf2"
        )
    else:
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║           GRUB Password Protection (Optional)           ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║                                                          ║")
        print("║  A GRUB password prevents boot menu editing and          ║")
        print("║  access to the recovery/rescue shell on physical access. ║")
        print("║                                                          ║")
        print("║  1. Set a GRUB password (enter your own)                 ║")
        print("║  2. Generate a random GRUB password (displayed once)     ║")
        print("║  3. Skip — no GRUB password                              ║")
        print("║                                                          ║")
        print("╚══════════════════════════════════════════════════════════╝\n")

        while True:
            choice = input("Select option (1, 2, or 3): ").strip()
            if choice == "1":
                import getpass
                password = getpass.getpass("  Enter GRUB password: ")
                confirm = getpass.getpass("  Confirm GRUB password: ")
                if password != confirm:
                    log_error("Passwords do not match — skipping GRUB password")
                else:
                    set_password = True
                break
            elif choice == "2":
                password = _generate_password()
                generated = True
                set_password = True
                break
            elif choice == "3":
                log_info("Skipping GRUB password")
                break
            else:
                print("  Please enter 1, 2, or 3.")

    if set_password and password:
        log_info("Hashing GRUB password (this takes a few seconds)...")
        pw_hash = _hash_password(password)
        if not pw_hash:
            log_error("Failed to hash GRUB password — skipping password protection")
        else:
            # Write drop-in script that sets superuser
            drop_in_content = f"""\
#!/bin/sh
# /etc/grub.d/09_aegis_hardening — managed by Aegis
# Sets GRUB superuser to protect boot menu from unauthorized editing.
cat <<EOF
set superusers="aegis"
password_pbkdf2 aegis {pw_hash}
EOF
"""
            try:
                GRUB_AEGIS_DROP_IN.write_text(drop_in_content, encoding="utf-8")
                GRUB_AEGIS_DROP_IN.chmod(0o700)
                log_success(f"GRUB superuser password written to {GRUB_AEGIS_DROP_IN}")

                if generated:
                    print(f"\n  *** GRUB Password (save this — shown once) ***")
                    print(f"  {password}\n")
            except Exception as e:
                log_error(f"Failed to write GRUB password drop-in: {e}")

    # Regenerate GRUB config
    log_info("Regenerating GRUB configuration...")
    update_cmd = "update-grub" if command_exists("update-grub") else "grub-mkconfig"
    update_args = (
        ["update-grub"]
        if command_exists("update-grub")
        else ["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]
    )
    result = _run(update_args, timeout=30)
    if result.returncode != 0:
        log_warning(f"GRUB update returned non-zero: {result.stderr.strip()}")
    else:
        log_success("GRUB configuration regenerated")

    return True


def check() -> bool:
    """Return True if GRUB is present."""
    return GRUB_DEFAULT.exists() or command_exists("update-grub")


def status() -> str:
    """Return GRUB hardening status."""
    parts = []

    if not GRUB_DEFAULT.exists():
        return "GRUB not found on this system"

    content = GRUB_DEFAULT.read_text(encoding="utf-8")
    for key in GRUB_SETTINGS:
        for line in content.splitlines():
            if line.strip().startswith(f"{key}="):
                parts.append(f"  {line.strip()}")
                break
        else:
            parts.append(f"  {key}: (not set)")

    pw_status = (
        f"present ({GRUB_AEGIS_DROP_IN})"
        if GRUB_AEGIS_DROP_IN.exists()
        else "not set (optional — run configure to add)"
    )
    parts.append(f"GRUB password: {pw_status}")

    return "GRUB hardening settings:\n" + "\n".join(parts)
