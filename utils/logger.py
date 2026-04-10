#!/usr/bin/env python3
"""Colored terminal + file logging for Aegis."""

import sys
from datetime import datetime
from pathlib import Path


class Color:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


_log_file = None


def get_log_path():
    """Get the current log file path."""
    return _log_file


def init_logging():
    """Initialize file logging."""
    global _log_file
    log_dir = Path.home() / ".aegis" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_file = log_dir / f"aegis_{timestamp}.log"


def _log(message, color="", prefix=""):
    """Write to both terminal and log file."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    plain = f"[{timestamp}] {prefix}{message}"
    colored = f"{color}[{timestamp}] {prefix}{message}{Color.RESET}"

    print(colored)

    if _log_file:
        with open(_log_file, "a") as f:
            f.write(plain + "\n")


def log_info(message):
    _log(message, Color.BLUE, "INFO: ")


def log_success(message):
    _log(message, Color.GREEN, "▲ ")


def log_error(message):
    _log(message, Color.RED, "▼ ")


def log_warning(message):
    _log(message, Color.YELLOW, "⚠ ")


def log_section(title):
    sep = "=" * (len(title) + 4)
    _log(sep, Color.BOLD)
    _log(f"  {title}", Color.BOLD)
    _log(sep, Color.BOLD)
