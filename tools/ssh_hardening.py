#!/usr/bin/env python3
"""SSH hardening module - Security hardening with safe fallbacks."""

import subprocess
from pathlib import Path
from datetime import datetime
from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import package_installed
from utils.system import command_exists


def check():
    """Check if OpenSSH-server is installed."""
    return package_installed("openssh-server")


def backup_sshd_config():
    """Create backup of sshd_config before modifications."""
    ssh_config = Path("/etc/ssh/sshd_config")

    if not ssh_config.exists():
        log_error("sshd_config not found")
        return None

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = Path(f"/etc/ssh/sshd_config.aegis-{timestamp}")

        # Copy file preserving permissions
        with open(ssh_config, "r") as src:
            content = src.read()

        with open(backup_path, "w") as dst:
            dst.write(content)

        backup_path.chmod(0o600)
        log_success(f"SSH config backed up to {backup_path}")
        return backup_path

    except Exception as e:
        log_error(f"Failed to backup sshd_config: {e}")
        return None


def validate_sshd_config():
    """Validate SSH config syntax."""
    try:
        result = subprocess.run(
            ["sshd", "-t"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def harden_sshd_config():
    """Harden SSH configuration with strong security settings."""
    log_info("Hardening SSH configuration...")

    ssh_config = Path("/etc/ssh/sshd_config")

    try:
        # Read current config
        with open(ssh_config, "r") as f:
            lines = f.readlines()

        # Settings to apply (key -> value)
        hardened_settings = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "yes",  # Keep as fallback
            "PubkeyAuthentication": "yes",
            "PermitEmptyPasswords": "no",
            "PermitUserRC": "no",
            "X11Forwarding": "no",
            "X11UseLocalhost": "yes",
            "PrintMotd": "no",
            "TCPKeepAlive": "yes",
            "AcceptEnv": "LANG LC_*",
            "StrictModes": "yes",
            "IgnoreRhosts": "yes",
            "HostbasedAuthentication": "no",
            "RhostsRSAAuthentication": "no",
            "RSAAuthentication": "no",
            "ClientAliveInterval": "300",
            "ClientAliveCountMax": "2",
            "Compression": "delayed",
            "UseDNS": "no",
            "PermitTunnel": "no",
            "AllowTcpForwarding": "yes",  # May be needed by users
            "GatewayPorts": "no",
            "AllowAgentForwarding": "no",
            "PermitTTY": "yes",
            "KexAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256",
            "Ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr",
            "MACs": "umac-256-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-256@openssh.com,hmac-sha2-256,hmac-sha2-512",
        }

        # Parse existing config
        config_dict = {}
        new_lines = []

        for line in lines:
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue

            # Parse key-value pairs
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                key = parts[0]
                config_dict[key] = parts[1]
            elif len(parts) == 1:
                config_dict[parts[0]] = ""

        # Build new config
        output_lines = []

        # Add comments
        output_lines.append("# This file is managed by Aegis security hardening\n")
        output_lines.append("# Original config backed up before modifications\n")
        output_lines.append("# Review with: sshd -T\n\n")

        # Add hardened settings
        for key, value in hardened_settings.items():
            if key in config_dict:
                # Update existing setting
                output_lines.append(f"{key} {value}\n")
            else:
                # Add new setting
                output_lines.append(f"{key} {value}\n")

        # Write new config with safe permissions
        with open(ssh_config, "w") as f:
            f.writelines(output_lines)

        ssh_config.chmod(0o600)
        log_success("SSH config hardened")

        # Validate syntax
        if not validate_sshd_config():
            log_error("SSH config validation failed - invalid syntax")
            return False

        log_success("SSH config validated")
        return True

    except PermissionError:
        log_error("Permission denied - need sudo")
        return False
    except Exception as e:
        log_error(f"SSH hardening failed: {e}")
        return False


def reload_ssh():
    """Reload SSH configuration without dropping connections."""
    log_info("Reloading SSH daemon...")

    try:
        # Use reload (not restart) to preserve existing connections
        result = subprocess.run(
            ["systemctl", "reload", "ssh"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to reload SSH")
            return False

        log_success("SSH daemon reloaded")
        return True

    except Exception as e:
        log_error(f"SSH reload failed: {e}")
        return False


def show_key_setup_guide():
    """Print instructions for SSH key setup."""
    guide = """
╔═══════════════════════════════════════════════════════════════╗
║              SSH Key Setup Guide (Optional)                   ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  For improved security, set up SSH key authentication:        ║
║                                                               ║
║  1. Generate key pair (if not already done):                  ║
║     $ ssh-keygen -t ed25519 -C "your-email@example.com"       ║
║     (or use: ssh-keygen -t rsa -b 4096)                       ║
║                                                               ║
║  2. Copy public key to remote server:                         ║
║     $ ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host          ║
║                                                               ║
║  3. Test connection:                                          ║
║     $ ssh user@host                                           ║
║                                                               ║
║  4. Once confirmed working, disable password auth:            ║
║     (Edit /etc/ssh/sshd_config and set)                       ║
║     PasswordAuthentication no                                 ║
║     PermitEmptyPasswords no                                   ║
║                                                               ║
║  Current setting: PasswordAuthentication is still ENABLED     ║
║  (for recovery access and gradual migration)                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(guide)


def configure():
    """Harden SSH configuration."""
    if not check():
        log_error("OpenSSH-server not installed")
        return False

    # Backup first
    backup = backup_sshd_config()
    if not backup:
        log_error("Cannot proceed without backup")
        return False

    # Harden config
    if not harden_sshd_config():
        log_error("SSH hardening failed")
        return False

    # Reload SSH
    if not reload_ssh():
        log_error("SSH reload failed")
        return False

    # Show guide
    show_key_setup_guide()

    return True


def status():
    """Show SSH security status."""
    try:
        result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            output = result.stdout
            important_settings = [
                "permitrootlogin",
                "pubkeyauthentication",
                "passwordauthentication",
                "permitusersrc",
                "permitusersrcfile",
            ]

            status_lines = ["SSH Security Settings:"]
            for line in output.split('\n'):
                for setting in important_settings:
                    if line.lower().startswith(setting):
                        status_lines.append(f"  {line}")
                        break

            return "\n".join(status_lines)
        else:
            return "SSH status check failed"

    except Exception as e:
        return f"Unable to check SSH status: {e}"
