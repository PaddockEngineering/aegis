#!/usr/bin/env python3
"""
Aegis — Automated Linux Shield Defense

Raises every layer of defense on a Debian-based system in a single pass:
  Layer 1: Perimeter Shield (Firewall, VPN, Intrusion Prevention)
  Layer 2: Hull Plating (Kernel Hardening, SSH, Auto-Patch)
  Layer 3: Structural Integrity (AppArmor, Firejail, Bluetooth)
  Layer 4: Internal Sensors (ClamAV, rkhunter, Auditd, Monitoring)
  Layer 5: Integrity Monitoring (AIDE, Smartmontools, Trivy)
  Layer 6: Compliance Verification (OpenSCAP CIS Benchmarks)
"""

import sys
import argparse
import json
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils.system import is_root, is_debian_based, require_root, get_log_dir
from utils.logger import init_logging, log_section, log_info, log_success, log_error, log_warning, get_log_path

import tools.firewall as firewall
import tools.vpn as vpn
import tools.malware as malware
import tools.isolation as isolation
import tools.monitoring as monitoring
import tools.fail2ban as fail2ban
import tools.auditd as auditd
import tools.ssh_hardening as ssh_hardening
import tools.unattended_upgrades as unattended_upgrades
import tools.smartmontools as smartmontools
import tools.apparmor as apparmor
import tools.kernel_sysctl as kernel_sysctl
import tools.bluetooth as bluetooth
import tools.aide as aide
import tools.docker_security as docker_security
import tools.openscap as openscap


class AegisSetup:
    """Main Aegis shield defense orchestrator."""

    def __init__(self, unattended: bool = False):
        """Initialize setup."""
        self.config = self.load_config()
        self.unattended = unattended
        self.installed_count = 0
        self.skipped_count = 0
        self.failed_count = 0

    def load_config(self):
        """Load tool configuration."""
        config_file = Path(__file__).parent / "config" / "tools.json"
        try:
            with open(config_file) as f:
                return json.load(f)
        except Exception as e:
            log_error(f"Failed to load config: {e}")
            return {"tools": []}

    def show_banner(self):
        """Show welcome banner."""
        banner = """
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║              AEGIS — Shield Defense                   ║
║         Automated Linux Defense Hardening             ║
║                                                       ║
║   Layer 1  Perimeter Shield     Firewall · VPN · IPS  ║
║   Layer 2  Hull Plating         Kernel · SSH · Patch  ║
║   Layer 3  Structural Integrity AppArmor · Isolation  ║
║   Layer 4  Internal Sensors     AV · Rootkit · Audit  ║
║   Layer 5  Integrity Monitoring AIDE · SMART · Trivy  ║
║   Layer 6  Compliance           OpenSCAP · CIS        ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
        """
        print(banner)

    def check_system(self):
        """Check system compatibility."""
        log_section("System Check")

        if not is_debian_based():
            log_error("This tool requires Debian/Ubuntu-based system")
            return False

        if not is_root():
            log_error("This tool requires root privileges (sudo)")
            return False

        log_success("System check passed (Debian-based, running as root)")
        return True

    def prompt_yn(self, question, default: bool = True):
        """Prompt user for yes/no. In unattended mode returns *default* immediately."""
        if self.unattended:
            return default
        while True:
            response = input(f"{question} (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            print("  Please enter 'y' or 'n'")

    def interactive_mode(self):
        """Run interactive installation mode."""
        log_section("Interactive Shield Configuration")

        # Group tools by category
        categories = {}
        for tool in self.config["tools"]:
            cat = tool["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool)

        # Prompt per category
        selections = {}
        for category, tools in categories.items():
            cat_title = category.upper()
            print(f"\n{cat_title}:")

            for tool in tools:
                if self.prompt_yn(f"  Enable {tool['name']}?"):
                    selections.setdefault(category, []).append(tool["name"])

        return selections

    def install_category(self, category, tool_names=None):
        """Install tools from a category."""
        if category == "firewall":
            if self._install_tool("firewall", firewall):
                self.installed_count += 1
            else:
                self.failed_count += 1

        elif category == "vpn":
            if self._install_tool("vpn", vpn):
                self.installed_count += 1
            else:
                self.failed_count += 1

        elif category == "malware":
            if self._install_tool("malware", malware):
                self.installed_count += 1
            else:
                self.failed_count += 1

        elif category == "isolation":
            if self._install_tool("isolation", isolation):
                self.installed_count += 1
            else:
                self.failed_count += 1

        elif category == "monitoring":
            if tool_names:
                if monitoring.install_selective(tool_names):
                    self.installed_count += 1
                else:
                    self.failed_count += 1
            else:
                if self._install_tool("monitoring", monitoring):
                    self.installed_count += 1
                else:
                    self.failed_count += 1

        elif category == "hardening":
            # Layer 1-2: Perimeter + Hull Plating
            hardening_tools = [
                ("Fail2ban", fail2ban),
                ("Auditd", auditd),
                ("SSH Hardening", ssh_hardening),
                ("Unattended-upgrades", unattended_upgrades),
            ]

            for name, module in hardening_tools:
                try:
                    if module.install():
                        log_info(f"Configuring {name}...")
                        # Pass unattended flag to modules that support it
                        from tools import get_function
                        configure_fn = get_function(module, "configure")
                        if configure_fn:
                            import inspect
                            sig = inspect.signature(configure_fn)
                            if "unattended" in sig.parameters:
                                ok = configure_fn(unattended=self.unattended)
                            else:
                                ok = configure_fn()
                        else:
                            ok = True  # No configure() — skip silently
                        if ok:
                            self.installed_count += 1
                            log_success(f"{name} — shield active")
                        else:
                            self.failed_count += 1
                            log_error(f"{name} — configuration failed")
                    else:
                        self.failed_count += 1
                except Exception as e:
                    self.failed_count += 1
                    log_error(f"Error with {name}: {e}")

        elif category == "hardening-medium":
            # Layer 3: Structural Integrity
            medium_tools = [
                ("Smartmontools", smartmontools),
                ("AppArmor", apparmor),
                ("Kernel Sysctl Hardening", kernel_sysctl),
                ("Bluetooth Security", bluetooth),
            ]

            for name, module in medium_tools:
                try:
                    if module.install():
                        log_info(f"Configuring {name}...")
                        from tools import get_function
                        import inspect
                        configure_fn = get_function(module, "configure")
                        if configure_fn:
                            sig = inspect.signature(configure_fn)
                            if "unattended" in sig.parameters:
                                ok = configure_fn(unattended=self.unattended)
                            else:
                                ok = configure_fn()
                        else:
                            ok = True
                        if ok:
                            self.installed_count += 1
                            log_success(f"{name} — shield active")
                        else:
                            self.failed_count += 1
                            log_error(f"{name} — configuration failed")
                    else:
                        self.failed_count += 1
                except Exception as e:
                    self.failed_count += 1
                    log_error(f"Error with {name}: {e}")

        elif category == "hardening-low":
            # Layer 5-6: Integrity Monitoring + Compliance
            low_tools = [
                ("AIDE", aide),
                ("Docker Security (Trivy)", docker_security),
                ("OpenSCAP", openscap),
            ]

            for name, module in low_tools:
                try:
                    if module.install():
                        log_info(f"Configuring {name}...")
                        if module.configure():
                            self.installed_count += 1
                            log_success(f"{name} — shield active")
                        else:
                            self.failed_count += 1
                            log_error(f"{name} — configuration failed")
                    else:
                        self.failed_count += 1
                except Exception as e:
                    self.failed_count += 1
                    log_error(f"Error with {name}: {e}")

    def _install_tool(self, name, module):
        """Install a tool module."""
        try:
            return module.install()
        except Exception as e:
            log_error(f"Failed to install {name}: {e}")
            return False

    def skip_tool(self, tool_name):
        """Skip a tool installation."""
        self.skipped_count += 1

    def install_all(self):
        """Raise all shields."""
        log_section("Raising All Shields")

        # Install each category
        categories = set(tool["category"] for tool in self.config["tools"])

        for category in sorted(categories):
            log_info(f"Activating {category.upper()} shields...")
            self.install_category(category)

    def install_category_arg(self, categories):
        """Install specific categories."""
        log_section(f"Activating Shields: {', '.join(categories)}")

        for category in categories:
            if category in ["firewall", "vpn", "malware", "isolation", "monitoring", "hardening", "hardening-medium", "hardening-low"]:
                log_info(f"Activating {category}...")
                self.install_category(category)
            else:
                log_warning(f"Unknown shield layer: {category}")

    def show_status(self):
        """Show shield status across all layers."""
        log_section("Shield Status Report")

        categories = {}
        for tool in self.config["tools"]:
            cat = tool["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool)

        for category in sorted(categories.keys()):
            print(f"\n{category.upper()}:")
            module = self._get_module(category)
            if module:
                try:
                    print(f"  {module.status()}")
                except Exception as e:
                    log_error(f"  Failed to check status: {e}")

    def _get_module(self, category):
        """Get module for category."""
        if category == "firewall":
            return firewall
        elif category == "vpn":
            return vpn
        elif category == "malware":
            return malware
        elif category == "isolation":
            return isolation
        elif category == "monitoring":
            return monitoring
        elif category == "hardening":
            # Return wrapper for hardening tools
            class HardeningModule:
                def status(self):
                    statuses = []
                    for name, module in [
                        ("Fail2ban", fail2ban),
                        ("Auditd", auditd),
                        ("SSH Hardening", ssh_hardening),
                        ("Unattended-upgrades", unattended_upgrades),
                    ]:
                        try:
                            statuses.append(f"{name}: {module.status()}")
                        except Exception as e:
                            statuses.append(f"{name}: Error - {str(e)}")
                    return "\n  ".join(statuses)
            return HardeningModule()
        elif category == "hardening-medium":
            # Return wrapper for medium priority hardening tools
            class HardeningMediumModule:
                def status(self):
                    statuses = []
                    for name, module in [
                        ("Smartmontools", smartmontools),
                        ("AppArmor", apparmor),
                        ("Kernel Sysctl", kernel_sysctl),
                        ("Bluetooth", bluetooth),
                    ]:
                        try:
                            statuses.append(f"{name}: {module.status()}")
                        except Exception as e:
                            statuses.append(f"{name}: Error - {str(e)}")
                    return "\n  ".join(statuses)
            return HardeningMediumModule()
        elif category == "hardening-low":
            # Return wrapper for low priority hardening tools
            class HardeningLowModule:
                def status(self):
                    statuses = []
                    for name, module in [
                        ("AIDE", aide),
                        ("Docker Security", docker_security),
                        ("OpenSCAP", openscap),
                    ]:
                        try:
                            statuses.append(f"{name}: {module.status()}")
                        except Exception as e:
                            statuses.append(f"{name}: Error - {str(e)}")
                    return "\n  ".join(statuses)
            return HardeningLowModule()
        return None

    def show_summary(self):
        """Show defense activation summary."""
        log_section("Shield Activation Summary")
        print(f"▲ Active:   {self.installed_count}")
        print(f"○ Skipped:  {self.skipped_count}")
        print(f"▼ Failed:   {self.failed_count}")
        if get_log_path():
            print(f"\nLog file: {get_log_path()}")

    def run(self, args):
        """Run setup based on arguments."""
        self.show_banner()

        if not self.check_system():
            sys.exit(1)

        init_logging()

        # Route based on arguments
        if args.all:
            self.install_all()
        elif args.firewall:
            self.install_category_arg(["firewall"])
        elif args.vpn:
            self.install_category_arg(["vpn"])
        elif args.malware:
            self.install_category_arg(["malware"])
        elif args.isolation:
            self.install_category_arg(["isolation"])
        elif args.monitoring:
            self.install_category_arg(["monitoring"])
        elif args.hardening:
            self.install_category_arg(["hardening"])
        elif args.hardening_medium:
            self.install_category_arg(["hardening-medium"])
        elif args.hardening_low:
            self.install_category_arg(["hardening-low"])
        elif args.status:
            self.show_status()
            return
        else:
            # Interactive mode
            selections = self.interactive_mode()
            if selections:
                log_section("Activating Selected Shields")
                for category, tool_names in selections.items():
                    self.install_category(category, tool_names)
            else:
                log_info("No shields selected")
                return

        self.show_summary()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Aegis — Automated Linux Shield Defense",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo ./setup.py              # Interactive — choose your shields
  sudo ./setup.py --all        # Raise all shields
  sudo ./setup.py --firewall   # Perimeter shield only
  sudo ./setup.py --hardening  # Hull plating (Fail2ban, Auditd, SSH, Auto-patch)
  sudo ./setup.py --status     # Shield status report
        """
    )

    parser.add_argument("--all", action="store_true", help="Raise all shields")
    parser.add_argument("--firewall", action="store_true", help="Perimeter: UFW firewall")
    parser.add_argument("--vpn", action="store_true", help="Perimeter: AirVPN Eddie")
    parser.add_argument("--malware", action="store_true", help="Sensors: ClamAV + rkhunter")
    parser.add_argument("--isolation", action="store_true", help="Integrity: Firejail sandboxing")
    parser.add_argument("--monitoring", action="store_true", help="Sensors: Hardware monitoring")
    parser.add_argument("--hardening", action="store_true", help="Hull: Fail2ban, Auditd, SSH, Auto-patch")
    parser.add_argument("--hardening-medium", dest="hardening_medium", action="store_true", help="Integrity: Smartmontools, AppArmor, Kernel, Bluetooth")
    parser.add_argument("--hardening-low", dest="hardening_low", action="store_true", help="Monitoring: AIDE, Docker security, OpenSCAP")
    parser.add_argument("--status", action="store_true", help="Shield status report")
    parser.add_argument(
        "--unattended",
        action="store_true",
        help="Non-interactive mode: skip all prompts, pick secure defaults (ideal for fresh installs)",
    )

    args = parser.parse_args()

    require_root()

    setup = AegisSetup(unattended=args.unattended)
    setup.run(args)


if __name__ == "__main__":
    main()
