#!/usr/bin/env python3
"""Auditd system audit daemon module - Conservative, security-focused rules."""

import subprocess
from pathlib import Path
from utils.logger import log_info, log_success, log_error
from utils.apt import install_package
from utils.system import command_exists


def install():
    """Install auditd."""
    log_info("Installing auditd...")

    if not install_package("auditd audispd-plugins"):
        return False

    log_success("auditd installed")
    return True


def configure_rules():
    """Configure conservative audit rules - won't fill disk or overwhelm logging."""
    log_info("Configuring audit rules...")

    try:
        rules_dir = Path("/etc/audit/rules.d")
        rules_dir.mkdir(parents=True, exist_ok=True)

        # Conservative rules - focus on important events without excessive logging
        rules = """# Aegis-managed audit rules - security monitoring
# Rules are conservative to avoid overwhelming disk usage

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (audit=2 prevents boot if audit daemon crashes)
-f 2

# Audit the audit logs
-w /var/log/audit/ -k auditlog

# Auditd configuration
-w /etc/audit/ -p wa -k audit_config

# System configuration monitoring
-w /etc/security/ -p wa -k system_security
-w /etc/group -p wa -k system_group
-w /etc/passwd -p wa -k system_passwd
-w /etc/shadow -p wa -k system_shadow
-w /etc/sudo.conf -p wa -k system_sudoers
-w /etc/sudoers -p wa -k system_sudoers
-w /etc/sudoers.d/ -p wa -k system_sudoers

# Privilege escalation
-a always,exit -F arch=b64 -S execve -F uid=0 -k privileged-exec
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S setsid -k privileged-networkmod

# User/group modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_hostname
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

# SSH key modifications
-w /home -p wa -k home_files
-w /root -p wa -k root_files

# System calls - keep to important ones only (avoid /proc, /sys)
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

# Make configuration immutable
-e 2
"""

        rules_file = rules_dir / "aegis.rules"

        with open(rules_file, "w") as f:
            f.write(rules)
        rules_file.chmod(0o640)

        log_success("Audit rules configured")

        # Load rules
        result = subprocess.run(
            ["augenrules", "--load"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error(f"Failed to load audit rules: {result.stderr.decode()}")
            return False

        log_success("Audit rules loaded")
        return True

    except PermissionError:
        log_error("Permission denied - need sudo")
        return False
    except Exception as e:
        log_error(f"Audit rule configuration failed: {e}")
        return False


def enable():
    """Enable auditd service."""
    log_info("Enabling auditd...")

    try:
        # Enable service
        result = subprocess.run(
            ["systemctl", "enable", "auditd"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to enable auditd")
            return False

        # Start service
        result = subprocess.run(
            ["systemctl", "start", "auditd"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            log_error("Failed to start auditd")
            return False

        log_success("auditd enabled and started")
        return True

    except Exception as e:
        log_error(f"Failed to enable auditd: {e}")
        return False


def configure():
    """Configure and enable auditd."""
    if not configure_rules():
        return False
    return enable()


def check():
    """Check if auditd is installed."""
    return command_exists("auditd")


def status():
    """Show auditd status."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True,
            text=True,
            timeout=5
        )

        status_text = result.stdout.strip()

        if result.returncode == 0:
            # Get number of rules loaded
            rules_result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True,
                text=True,
                timeout=5
            )

            num_rules = len([l for l in rules_result.stdout.split('\n') if l.strip() and not l.startswith('No rules')])

            return f"auditd is {status_text} with {num_rules} rules loaded"
        else:
            return f"auditd is {status_text}"

    except Exception as e:
        return f"Unable to check auditd status: {e}"
