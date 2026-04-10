#!/usr/bin/env python3
"""
Aegis Layer 4 — syslog.py
Centralized log management via rsyslog and logrotate.

Ensures all security-relevant logs are:
  - collected in one place (/var/log/aegis/)
  - rotated so they never fill the disk
  - retained for 90 days for forensic use
  - readable only by root
"""

import subprocess
from pathlib import Path

from utils.logger import log_info, log_success, log_error, log_warning
from utils.apt import install_package
from utils.system import command_exists


RSYSLOG_DROP_IN = Path("/etc/rsyslog.d/40-aegis.conf")
LOGROTATE_CONF = Path("/etc/logrotate.d/aegis")
AEGIS_LOG_DIR = Path("/var/log/aegis")

# Collects auth, kernel, audit, and cron into /var/log/aegis/
RSYSLOG_CONF = """\
# /etc/rsyslog.d/40-aegis.conf — managed by Aegis
# Centralizes security-relevant logs into /var/log/aegis/

# Auth and sudo events
auth,authpriv.*                  /var/log/aegis/auth.log

# Kernel messages (includes firewall drops, OOM killer, USB events)
kern.*                           /var/log/aegis/kernel.log

# Cron jobs
cron.*                           /var/log/aegis/cron.log

# All emergency and alert messages regardless of facility
*.emerg                          :omusrmsg:*
*.alert                          /var/log/aegis/alerts.log
"""

LOGROTATE_CONF_CONTENT = """\
# /etc/logrotate.d/aegis — managed by Aegis
/var/log/aegis/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
"""


def _run(args: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def install() -> bool:
    """Install rsyslog and logrotate (usually pre-installed, but ensure they're present)."""
    log_info("Ensuring rsyslog and logrotate are installed...")

    ok = True
    if not command_exists("rsyslogd"):
        if not install_package("rsyslog"):
            log_error("Failed to install rsyslog")
            ok = False
        else:
            log_success("rsyslog installed")
    else:
        log_info("rsyslog already present")

    if not command_exists("logrotate"):
        if not install_package("logrotate"):
            log_warning("Failed to install logrotate")
        else:
            log_success("logrotate installed")

    return ok


def configure() -> bool:
    """
    Write rsyslog drop-in and logrotate config, create log directory,
    and restart rsyslog.
    Idempotent: backs up existing Aegis configs before overwriting.
    """
    import shutil, datetime

    try:
        # Create log directory with tight permissions
        AEGIS_LOG_DIR.mkdir(parents=True, exist_ok=True)
        AEGIS_LOG_DIR.chmod(0o750)
        log_info(f"Log directory ready: {AEGIS_LOG_DIR}")

        # Backup and write rsyslog drop-in
        if RSYSLOG_DROP_IN.exists():
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = RSYSLOG_DROP_IN.with_suffix(f".{ts}.aegis-backup")
            shutil.copy2(str(RSYSLOG_DROP_IN), str(backup))
            log_info(f"Backed up rsyslog config to {backup}")

        RSYSLOG_DROP_IN.write_text(RSYSLOG_CONF, encoding="utf-8")
        RSYSLOG_DROP_IN.chmod(0o644)
        log_success(f"rsyslog drop-in written to {RSYSLOG_DROP_IN}")

        # Validate rsyslog config syntax
        validate = _run(["rsyslogd", "-N1"], timeout=10)
        if validate.returncode != 0:
            log_warning(f"rsyslogd config validation warning: {validate.stderr.strip()}")

        # Backup and write logrotate config
        if LOGROTATE_CONF.exists():
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = LOGROTATE_CONF.with_suffix(f".{ts}.aegis-backup")
            shutil.copy2(str(LOGROTATE_CONF), str(backup))

        LOGROTATE_CONF.write_text(LOGROTATE_CONF_CONTENT, encoding="utf-8")
        LOGROTATE_CONF.chmod(0o644)
        log_success(f"logrotate config written to {LOGROTATE_CONF} (90-day retention, daily rotation)")

        # Restart rsyslog to apply new config
        restart = _run(["systemctl", "restart", "rsyslog"], timeout=15)
        if restart.returncode != 0:
            log_warning(f"rsyslog restart failed: {restart.stderr.strip()}")
        else:
            log_success("rsyslog restarted — centralized logging active")

        log_info(f"Security logs collecting to {AEGIS_LOG_DIR}/")
        log_info("  auth.log   — auth events, sudo, SSH logins")
        log_info("  kernel.log — kernel messages, firewall drops")
        log_info("  cron.log   — scheduled job activity")
        log_info("  alerts.log — emergency and alert messages")

        return True

    except PermissionError:
        log_error("Permission denied — run Aegis with sudo")
        return False
    except Exception as e:
        log_error(f"Log management configuration failed: {e}")
        return False


def check() -> bool:
    """Return True if rsyslog is installed and running."""
    if not command_exists("rsyslogd"):
        return False
    result = _run(["systemctl", "is-active", "rsyslog"], timeout=5)
    return result.returncode == 0


def status() -> str:
    """Return rsyslog and logrotate status with log file sizes."""
    parts = []

    active = _run(["systemctl", "is-active", "rsyslog"], timeout=5)
    parts.append(f"rsyslog: {active.stdout.strip() or 'unknown'}")

    drop_in = "present" if RSYSLOG_DROP_IN.exists() else "missing"
    rotate = "present" if LOGROTATE_CONF.exists() else "missing"
    parts.append(f"Aegis rsyslog config ({RSYSLOG_DROP_IN}): {drop_in}")
    parts.append(f"Aegis logrotate config ({LOGROTATE_CONF}): {rotate}")

    if AEGIS_LOG_DIR.exists():
        logs = list(AEGIS_LOG_DIR.glob("*.log"))
        if logs:
            parts.append(f"Log files in {AEGIS_LOG_DIR}/:")
            for log in sorted(logs):
                size = log.stat().st_size
                parts.append(f"  {log.name}: {size // 1024} KB")
        else:
            parts.append(f"No log files yet in {AEGIS_LOG_DIR}/ (will populate on next event)")
    else:
        parts.append(f"Log directory not created yet — run configure")

    return "\n".join(parts)
