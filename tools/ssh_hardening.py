#!/usr/bin/env python3
"""SSH hardening module - Secure drop-in configuration via sshd_config.d."""

import subprocess
from pathlib import Path
from datetime import datetime

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import package_installed
from utils.system import command_exists

# Drop-in file — never touches /etc/ssh/sshd_config directly.
# Requires OpenSSH 8.2+ (Ubuntu 20.04+, Debian 11+).
DROPIN_DIR = Path("/etc/ssh/sshd_config.d")
DROPIN_FILE = DROPIN_DIR / "99-aegis.conf"

# Hardened settings applied via the drop-in.
# PasswordAuthentication left enabled — user should disable once keys are confirmed.
DROPIN_CONTENT = """\
# /etc/ssh/sshd_config.d/99-aegis.conf — managed by Aegis
# Applied on top of the system sshd_config. Edit here, not in sshd_config.
# Review effective config with: sudo sshd -T

# Access control
PermitRootLogin no
PermitEmptyPasswords no
PermitUserRC no
PermitTunnel no

# Authentication
PubkeyAuthentication yes
PasswordAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes

# Session / forwarding
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding no
GatewayPorts no
Compression no
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
PrintMotd no
StrictModes yes

# Modern key exchange — only forward-secret algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Strong ciphers — ChaCha20 preferred, AES-GCM as fallback
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr

# ETM MACs only — prevents SSH protocol downgrades
MACs umac-256-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
"""

SSH_KEY_GUIDE = """
╔═══════════════════════════════════════════════════════════════╗
║              SSH Key Setup Guide (Optional)                   ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  For improved security, set up SSH key authentication:        ║
║                                                               ║
║  1. Generate a key pair (if you don't have one):              ║
║     $ ssh-keygen -t ed25519 -C "your-email@example.com"       ║
║                                                               ║
║  2. Copy public key to this server:                           ║
║     $ ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host          ║
║                                                               ║
║  3. Test that key auth works, then disable passwords:         ║
║     Edit /etc/ssh/sshd_config.d/99-aegis.conf and set:       ║
║     PasswordAuthentication no                                 ║
║     Then: sudo systemctl reload ssh                           ║
║                                                               ║
║  Current setting: PasswordAuthentication yes (safe default)   ║
╚═══════════════════════════════════════════════════════════════╝
"""


def check():
    """Check if OpenSSH-server is installed."""
    return package_installed("openssh-server")


def validate_sshd_config():
    """Validate SSH config syntax."""
    try:
        result = subprocess.run(
            ["sshd", "-t"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def configure(unattended: bool = False):
    """
    Write the Aegis SSH drop-in config and reload the daemon.

    Uses /etc/ssh/sshd_config.d/99-aegis.conf — never modifies the
    system sshd_config. Requires OpenSSH 8.2+ (Ubuntu 20.04 / Debian 11+).
    Idempotent: safe to re-run; backs up existing drop-in before overwriting.
    """
    if not check():
        log_error("OpenSSH-server is not installed — skipping SSH hardening")
        return False

    # Ensure drop-in directory exists (created by openssh-server on modern distros)
    if not DROPIN_DIR.exists():
        log_warning(
            f"{DROPIN_DIR} not found — your OpenSSH may be too old for drop-in configs. "
            "Skipping SSH hardening."
        )
        return False

    # Backup existing Aegis drop-in if present
    if DROPIN_FILE.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = DROPIN_FILE.with_suffix(f".{timestamp}.aegis-backup")
        import shutil
        shutil.copy2(str(DROPIN_FILE), str(backup))
        log_info(f"Backed up existing drop-in to {backup}")

    # Write drop-in
    try:
        DROPIN_FILE.write_text(DROPIN_CONTENT, encoding="utf-8")
        DROPIN_FILE.chmod(0o600)
        log_success(f"SSH hardening drop-in written to {DROPIN_FILE}")
    except PermissionError:
        log_error("Permission denied — run Aegis with sudo")
        return False
    except Exception as e:
        log_error(f"Failed to write SSH drop-in: {e}")
        return False

    # Validate combined config
    if not validate_sshd_config():
        log_error("sshd -t validation failed — reverting drop-in")
        DROPIN_FILE.unlink(missing_ok=True)
        return False

    # Reload daemon without dropping active connections
    log_info("Reloading SSH daemon (active connections preserved)...")
    result = subprocess.run(
        ["systemctl", "reload", "ssh"],
        capture_output=True,
        timeout=15,
    )
    if result.returncode != 0:
        # Try 'sshd' service name (varies by distro)
        result = subprocess.run(
            ["systemctl", "reload", "sshd"],
            capture_output=True,
            timeout=15,
        )
    if result.returncode != 0:
        log_warning("Could not reload SSH daemon — config will apply on next restart")
    else:
        log_success("SSH daemon reloaded — hardening active")

    if not unattended:
        print(SSH_KEY_GUIDE)

    return True


def status():
    """Show effective SSH security settings."""
    try:
        result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return "SSH status check failed (sshd -T returned non-zero)"

        watch = {
            "permitrootlogin", "pubkeyauthentication",
            "passwordauthentication", "permitemptypasswords",
            "x11forwarding", "allowtcpforwarding",
        }
        lines = ["SSH effective settings (from sshd -T):"]
        for line in result.stdout.splitlines():
            if line.split()[0].lower() in watch:
                lines.append(f"  {line}")

        dropin_status = "present" if DROPIN_FILE.exists() else "MISSING"
        lines.append(f"\nAegis drop-in ({DROPIN_FILE}): {dropin_status}")
        return "\n".join(lines)

    except Exception as e:
        return f"Unable to check SSH status: {e}"
