#!/usr/bin/env python3
"""System monitoring module - hardware and GPU monitoring tools."""

from utils.logger import log_info, log_success, log_error
from utils.apt import install_package, package_installed
from utils.system import command_exists


MONITORING_TOOLS = [
    ("lm-sensors", "lm-sensors", "Hardware temperature/voltage sensors"),
    ("psensor", "psensor", "GUI for hardware monitoring"),
    ("glances", "glances", "System monitoring dashboard"),
    ("hardinfo", "hardinfo", "System hardware info tool"),
    ("corectrl", "corectrl", "AMD GPU monitoring and control GUI"),
    ("rocm-smi", "rocm-smi", "AMD GPU CLI monitoring tool"),
]


def install_tool(package_name, description=None):
    """Install a single monitoring tool."""
    if description:
        log_info(f"Installing {description}...")
    else:
        log_info(f"Installing {package_name}...")

    if install_package(package_name):
        log_success(f"{package_name} installed")
        return True
    return False


def install():
    """Install all monitoring tools."""
    success = True

    for package, name, desc in MONITORING_TOOLS:
        if not install_tool(package, desc):
            success = False

    return success


def install_selective(tools):
    """Install selected monitoring tools.

    Args:
        tools: List of tool names to install (e.g., ["lm-sensors", "glances"])
    """
    success = True

    for package, name, desc in MONITORING_TOOLS:
        if package in tools or name in tools:
            if not install_tool(package, desc):
                success = False

    return success


def check():
    """Check if any monitoring tools are installed."""
    return any(command_exists(tool[0]) for tool in MONITORING_TOOLS)


def status():
    """Show monitoring tools status."""
    status_msgs = []

    for package, name, desc in MONITORING_TOOLS:
        if command_exists(package):
            status_msgs.append(f"✓ {package} installed - {desc}")
        else:
            status_msgs.append(f"✗ {package} not installed")

    return "\n".join(status_msgs)


def list_tools():
    """List available monitoring tools."""
    return MONITORING_TOOLS
