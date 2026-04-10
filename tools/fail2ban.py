#!/usr/bin/env python3
"""Fail2ban intrusion prevention module - Secure configuration."""

import subprocess
from pathlib import Path
from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package, package_installed
from utils.system import command_exists


def install():
    """Install fail2ban."""
    log_info("Installing fail2ban...")

    if not install_package("fail2ban"):
        return False

    log_success("fail2ban installed")
    return True


def configure_jail():
    """Configure fail2ban jails safely."""
    log_info("Configuring fail2ban jails...")

    try:
        # Create jail.local with safe defaults (never modify package files)
        jail_config = """# Aegis-managed fail2ban configuration
# This file is NOT auto-generated and will be preserved on updates

[DEFAULT]
# Ban duration in seconds (15 minutes)
bantime = 900
findtime = 600
maxretry = 5

# Increase ban time for repeat offenders (recidivism)
recidivism_action = %(banaction)s[name=%(__name__)s-recidivism, bantime="%(recidivism_bantime)d"]
recidivism_bantime = 604800

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 900
findtime = 600

# Optional: Uncomment to enable additional jails if services installed
# [apache-auth]
# enabled = true
# port = http,https
# logpath = /var/log/apache2/*error.log
#
# [nginx-http-auth]
# enabled = true
# port = http,https
# logpath = /var/log/nginx/error.log
"""

        jail_path = Path("/etc/fail2ban/jail.local")

        # Write with secure permissions (0644)
        with open(jail_path, "w") as f:
            f.write(jail_config)
        jail_path.chmod(0o644)

        log_success("fail2ban jail.local created")

        # Enable and restart fail2ban
        result = subprocess.run(
            ["systemctl", "enable", "fail2ban"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to enable fail2ban")
            return False

        result = subprocess.run(
            ["systemctl", "restart", "fail2ban"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to restart fail2ban")
            return False

        log_success("fail2ban enabled and restarted")
        return True

    except PermissionError:
        log_error("Permission denied - need sudo")
        return False
    except Exception as e:
        log_error(f"fail2ban configuration failed: {e}")
        return False


def configure():
    """Configure fail2ban with safe defaults."""
    return configure_jail()


def check():
    """Check if fail2ban is installed."""
    return command_exists("fail2ban-client")


def status():
    """Show fail2ban status."""
    try:
        result = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            # Parse output to show jails
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                status_line = f"fail2ban is running: {lines[0]}"
                jails_line = f"{lines[1]}" if len(lines) > 1 else ""
                return f"{status_line}\n{jails_line}"
            return "fail2ban is running"
        else:
            return "fail2ban status check failed"

    except Exception as e:
        return f"Unable to check fail2ban status: {e}"
