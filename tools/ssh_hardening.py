#!/usr/bin/env python3
"""
Aegis Layer 2 — ssh_hardening.py
SSH hardening with optional Tailscale integration.

Offers three access models:
  1. Native SSH only       — strong cipher drop-in, no VPN dependency
  2. Tailscale + native    — joins tailnet, locks SSH to Tailscale interface
  3. Tailscale only        — SSH unreachable on public interfaces (max security)

In unattended mode: option 1 (native only) is applied automatically.
Tailscale always requires a human auth step via browser.
"""

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

# Tailscale CGNAT range — all tailnet addresses live here
TAILSCALE_CIDR = "100.64.0.0/10"

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


# ---------------------------------------------------------------------------
# Tailscale helpers
# ---------------------------------------------------------------------------

def _install_tailscale() -> bool:
    """Install Tailscale via the official install script (runs as root)."""
    from utils.apt import update_package_list

    log_info("Installing Tailscale...")

    # Try apt first (some distros ship it)
    result = subprocess.run(
        ["apt-get", "install", "-y", "tailscale"],
        capture_output=True, timeout=60,
    )
    if result.returncode == 0:
        log_success("Tailscale installed from system repos")
        return True

    # Official install script — downloads and runs a shell script as root.
    # This is the method documented by Tailscale themselves.
    log_info("Adding Tailscale repository...")
    try:
        dl = subprocess.run(
            ["sh", "-c",
             "curl -fsSL https://tailscale.com/install.sh | sh"],
            capture_output=True, timeout=120,
        )
        if dl.returncode != 0:
            log_error(f"Tailscale install script failed: {dl.stderr.decode().strip()}")
            return False
        log_success("Tailscale installed")
        return True
    except subprocess.TimeoutExpired:
        log_error("Tailscale install timed out")
        return False
    except Exception as e:
        log_error(f"Tailscale installation failed: {e}")
        return False


def _start_tailscale() -> bool:
    """Enable and start the Tailscale daemon."""
    for action in ("enable", "start"):
        r = subprocess.run(
            ["systemctl", action, "tailscaled"],
            capture_output=True, timeout=15,
        )
        if r.returncode != 0:
            log_warning(f"systemctl {action} tailscaled: {r.stderr.decode().strip()}")
    return True


def _tailscale_up() -> bool:
    """
    Run `tailscale up` and print the auth URL for the user to open in a browser.
    Returns True once the user has confirmed they've authenticated.
    """
    log_info("Starting Tailscale authentication...")
    try:
        result = subprocess.run(
            ["tailscale", "up", "--accept-routes"],
            capture_output=True, text=True, timeout=10,
        )
        # tailscale up prints an auth URL to stderr when not yet authenticated
        output = result.stdout + result.stderr
        if "https://login.tailscale.com" in output:
            for line in output.splitlines():
                if "https://" in line:
                    print(f"\n  Open this URL in your browser to authenticate:")
                    print(f"  {line.strip()}\n")
            input("  Press Enter once you have authenticated in the browser... ")
            return True
        elif result.returncode == 0:
            log_success("Tailscale is already authenticated")
            return True
        else:
            log_warning(f"tailscale up output: {output.strip()}")
            return True  # May still work — let the user proceed
    except subprocess.TimeoutExpired:
        # tailscale up hangs waiting for auth — that's normal; print URL from daemon log
        log_info("Waiting for Tailscale auth URL...")
        import time; time.sleep(2)
        journal = subprocess.run(
            ["journalctl", "-u", "tailscaled", "-n", "20", "--no-pager"],
            capture_output=True, text=True, timeout=5,
        )
        for line in journal.stdout.splitlines():
            if "https://login.tailscale.com" in line:
                print(f"\n  Open this URL in your browser to authenticate:")
                print(f"  {line.strip()}\n")
                break
        input("  Press Enter once you have authenticated in the browser... ")
        return True
    except Exception as e:
        log_error(f"tailscale up failed: {e}")
        return False


def _get_tailscale_ip() -> str | None:
    """Return this machine's Tailscale IP address."""
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True, text=True, timeout=10,
        )
        ip = result.stdout.strip()
        return ip if ip else None
    except Exception:
        return None


def _lock_ssh_to_tailscale() -> bool:
    """
    Use UFW to restrict SSH access to the Tailscale CGNAT range only.
    Requires UFW to be installed (firewall.py should have run first).
    """
    if not command_exists("ufw"):
        log_warning("UFW not found — cannot restrict SSH to Tailscale interface automatically")
        log_info(f"Manually restrict SSH: sudo ufw allow in on tailscale0 to any port 22")
        return False

    log_info("Restricting SSH access to Tailscale interface...")

    # Allow SSH from tailnet
    r1 = subprocess.run(
        ["ufw", "allow", "in", "on", "tailscale0", "to", "any", "port", "22"],
        capture_output=True, timeout=10,
    )
    # Delete the broad SSH allow rule (added by firewall.py)
    r2 = subprocess.run(
        ["ufw", "delete", "allow", "ssh"],
        capture_output=True, timeout=10,
    )

    if r1.returncode == 0:
        log_success("SSH restricted to Tailscale interface (tailscale0)")
        ts_ip = _get_tailscale_ip()
        if ts_ip:
            log_info(f"Connect via: ssh <user>@{ts_ip}")
        return True
    else:
        log_warning("UFW rule for Tailscale SSH failed — SSH remains open on all interfaces")
        return False


# ---------------------------------------------------------------------------
# Public module interface
# ---------------------------------------------------------------------------

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


def _write_and_reload_dropin() -> bool:
    """Write the SSH hardening drop-in and reload the daemon. Used by configure()."""
    if not DROPIN_DIR.exists():
        log_warning(
            f"{DROPIN_DIR} not found — your OpenSSH may be too old for drop-in configs. "
            "Skipping SSH hardening."
        )
        return False

    if DROPIN_FILE.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = DROPIN_FILE.with_suffix(f".{timestamp}.aegis-backup")
        import shutil
        shutil.copy2(str(DROPIN_FILE), str(backup))
        log_info(f"Backed up existing drop-in to {backup}")

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

    if not validate_sshd_config():
        log_error("sshd -t validation failed — reverting drop-in")
        DROPIN_FILE.unlink(missing_ok=True)
        return False

    log_info("Reloading SSH daemon (active connections preserved)...")
    for svc in ("ssh", "sshd"):
        result = subprocess.run(
            ["systemctl", "reload", svc], capture_output=True, timeout=15
        )
        if result.returncode == 0:
            log_success("SSH daemon reloaded — hardening active")
            return True

    log_warning("Could not reload SSH daemon — config will apply on next restart")
    return True


def configure(unattended: bool = False):
    """
    Harden SSH and optionally set up Tailscale.

    Presents three access models (interactive) or defaults to native-only
    (unattended), since Tailscale always requires a human auth step.

    Options:
      1. Native SSH only       — drop-in hardening, SSH open on all interfaces
      2. Tailscale + native    — installs Tailscale, locks SSH to tailnet only
      3. Tailscale only        — same as 2, plus blocks public SSH via UFW
    """
    if not check():
        log_error("OpenSSH-server is not installed — skipping SSH hardening")
        return False

    if unattended:
        log_info("Unattended mode — applying native SSH hardening (Tailscale requires human auth)")
        _write_and_reload_dropin()
        return True

    # Interactive: present access model menu
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║              SSH Access Model                                ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                                                              ║")
    print("║  1. Native SSH only (recommended for most users)             ║")
    print("║     Strong cipher hardening. SSH reachable on all            ║")
    print("║     interfaces. No VPN dependency.                           ║")
    print("║                                                              ║")
    print("║  2. Tailscale + native hardening                             ║")
    print("║     Installs Tailscale. SSH locked to tailnet interface       ║")
    print("║     only — no public SSH exposure. Fallback via console.      ║")
    print("║                                                              ║")
    print("║  3. Tailscale only (max security)                            ║")
    print("║     Same as 2, but also removes the public SSH UFW rule.     ║")
    print("║     SSH is completely invisible on public interfaces.         ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    while True:
        choice = input("Select option (1, 2, or 3): ").strip()
        if choice in ("1", "2", "3"):
            break
        print("  Please enter 1, 2, or 3.")

    # Always apply native hardening drop-in
    if not _write_and_reload_dropin():
        return False

    if choice == "1":
        log_success("Native SSH hardening applied")
        print(SSH_KEY_GUIDE)
        return True

    # Options 2 and 3 — install and auth Tailscale
    log_info("Setting up Tailscale...")
    if not _install_tailscale():
        log_error("Tailscale installation failed — native SSH hardening still applied")
        return False

    _start_tailscale()

    if not _tailscale_up():
        log_error("Tailscale authentication failed — native SSH hardening still applied")
        return False

    # Lock SSH to tailnet
    _lock_ssh_to_tailscale()

    if choice == "3":
        # Delete broad public SSH rule entirely
        subprocess.run(
            ["ufw", "delete", "allow", "22/tcp"],
            capture_output=True, timeout=10,
        )
        log_success("SSH completely hidden from public interfaces — reachable only via Tailscale")
    else:
        log_success("Tailscale + native SSH hardening active")

    ts_ip = _get_tailscale_ip()
    if ts_ip:
        log_info(f"Your Tailscale IP: {ts_ip}")
        log_info(f"SSH via tailnet:   ssh <user>@{ts_ip}")

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
