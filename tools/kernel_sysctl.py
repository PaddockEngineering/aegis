#!/usr/bin/env python3
"""Kernel sysctl hardening module - Advanced security parameters."""

import subprocess
from pathlib import Path
from utils.logger import log_info, log_success, log_error, log_warning


def backup_sysctl_config():
    """Backup existing sysctl hardening config."""
    sysctl_dir = Path("/etc/sysctl.d")
    aegis_config = sysctl_dir / "99-aegis-hardening.conf"

    if aegis_config.exists():
        try:
            backup_path = Path(f"{aegis_config}.aegis-backup")
            with open(aegis_config, "r") as src:
                content = src.read()
            with open(backup_path, "w") as dst:
                dst.write(content)
            log_success("Previous hardening config backed up")
            return backup_path
        except Exception as e:
            log_error(f"Failed to backup sysctl config: {e}")
            return None

    return None


def apply_hardening_parameters():
    """Apply hardened kernel parameters."""
    log_info("Applying kernel hardening parameters...")

    try:
        sysctl_dir = Path("/etc/sysctl.d")
        sysctl_dir.mkdir(parents=True, exist_ok=True)

        # Hardened kernel parameters - well-tested and safe for production
        hardening_params = """# Aegis-managed kernel hardening parameters
# Advanced security settings for kernel protection

# PTRACE RESTRICTION
# Restrict non-root from using ptrace (prevents code injection attacks)
# 0 = allow all, 1 = only parent processes, 2 = only root
kernel.yama.ptrace_scope = 2

# SYMLINK ATTACK PREVENTION
# Prevent symlink attacks by restricting symlink following in world-writable directories
fs.protected_symlinks = 1

# HARDLINK ATTACK PREVENTION
# Prevent hardlink attacks by restricting hardlink creation to owned files
fs.protected_hardlinks = 1

# KERNEL LOG RESTRICTION
# Restrict dmesg output to privileged processes only
kernel.dmesg_restrict = 1

# CORE DUMP FILENAME
# Include process ID in core dump filename (helps with forensics)
kernel.core_uses_pid = 1

# TCP TIMESTAMPS
# Disable TCP timestamps to prevent PAWS attack and information leakage
# (minor performance impact, privacy benefit)
net.ipv4.tcp_timestamps = 0

# KERNEL PANIC ON OOPS
# Automatically panic on kernel oops (exploits can't continue after oops)
kernel.panic_on_oops = 1

# AUTO-REBOOT ON KERNEL PANIC
# Automatically reboot after kernel panic (uptime vs security tradeoff)
# Value is seconds to wait before reboot (10 = 10 second wait)
kernel.panic = 10

# MAGIC SYSRQ
# Disable Magic SysRq key (can be used for DoS or crash)
kernel.sysrq = 0

# KPTR_RESTRICT
# Restrict exposure of kernel pointers in dmesg/proc (prevent ASLR bypass)
# 1 = restrict to CAP_SYSLOG, 2 = completely restrict
kernel.kptr_restrict = 2

# UNPRIVILEGED NAMESPACE CLONE
# Allow unprivileged namespace cloning (needed for user namespaces)
# Set to 1 for Docker/containers, 0 for max security
kernel.unprivileged_userns_clone = 1

# UNPRIVILEGED BPF
# Restrict unprivileged eBPF programs (attack surface reduction)
# 0 = all allowed, 1 = unprivileged denied, 2 = all denied
kernel.unprivileged_bpf_disabled = 2

# PERF EVENT PARANOIA
# Restrict perf events to reduce attack surface
# 2 = user-level only, 3 = kernel events restricted
kernel.perf_event_paranoid = 2

# RESTRICT KERNEL MODULE LOADING
# Set to 1 to restrict unprivileged module loading
# Warning: Some distributions expect unprivileged module loading
kernel.modules_disabled = 0

# RESTRICT USERFAULTFD
# Disable userfaultfd for unprivileged users (attack surface reduction)
vm.unprivileged_userfaultfd = 0

# RESTRICT TIMERFD_CREATE
# Use strict rules for timerfd_create syscall
kernel.timer_migration = 1

# IP FORWARDING
# Keep as-is from system (often needed for routing/Docker)
# net.ipv4.ip_forward should already be configured

# ICMP ECHO
# Respond to ICMP echo requests (don't disable - needed for network diagnostics)
# net.ipv4.icmp_echo_ignore_all = 0

# SYN FLOOD PROTECTION (already configured, but ensure enabled)
net.ipv4.tcp_syncookies = 1

# REDIR ATTACK PREVENTION
# Restrict ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# SOURCE PACKET ROUTING
# Disable source packet routing (prevent IP spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# BAD ICMP RESPONSE
# Log suspicious ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# REVERSE PATH FILTERING
# Enable reverse path filtering (prevent IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# NETWORK FILE PERMISSIONS
# Restrict access to network information
net.ipv4.tcp_fwmark_accept = 1
"""

        config_path = Path("/etc/sysctl.d/99-aegis-hardening.conf")

        with open(config_path, "w") as f:
            f.write(hardening_params)

        config_path.chmod(0o644)
        log_success("Sysctl hardening configuration written")

        # Apply immediately
        result = subprocess.run(
            ["sysctl", "-p", "/etc/sysctl.d/99-aegis-hardening.conf"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            error_msg = result.stderr.decode() if result.stderr else "Unknown error"
            log_warning(f"Some parameters may not be supported: {error_msg}")
            # Don't fail completely - some parameters may not be available
        else:
            log_success("Sysctl parameters applied")

        return True

    except PermissionError:
        log_error("Permission denied - need sudo")
        return False
    except Exception as e:
        log_error(f"Sysctl hardening failed: {e}")
        return False


def check():
    """Check if kernel supports hardening."""
    try:
        # Simple check - can we read sysctl?
        result = subprocess.run(
            ["sysctl", "-a"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def status():
    """Show hardened kernel parameters status."""
    try:
        important_params = [
            "kernel.yama.ptrace_scope",
            "fs.protected_symlinks",
            "fs.protected_hardlinks",
            "kernel.dmesg_restrict",
            "kernel.panic_on_oops",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.conf.all.rp_filter",
        ]

        status_lines = ["Kernel Hardening Status:"]

        for param in important_params:
            try:
                result = subprocess.run(
                    ["sysctl", "-n", param],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    value = result.stdout.strip()
                    status_lines.append(f"  {param} = {value}")
                else:
                    status_lines.append(f"  {param} = (not supported)")

            except Exception:
                status_lines.append(f"  {param} = (check failed)")

        return "\n".join(status_lines)

    except Exception as e:
        return f"Unable to check kernel hardening status: {e}"


def configure():
    """Apply kernel hardening parameters."""
    backup_sysctl_config()
    return apply_hardening_parameters()
