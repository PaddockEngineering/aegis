<p align="center">
  <img src="https://img.shields.io/badge/Aegis-Shield_Defense-0a0a0a?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTIgMjJzOC00IDgtMTBWNWwtOC0zLTggM3Y3YzAgNiA4IDEwIDggMTB6Ii8+PC9zdmc+" alt="Aegis Shield Defense"/>
</p>

<h1 align="center">Aegis</h1>
<p align="center"><strong>Automated Linux Shield Defense</strong></p>
<p align="center">
  One command. Every layer of defense. Production-hardened.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/platform-Debian%20|%20Ubuntu%20|%20Mint-orange?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/modules-16+-green?style=flat-square" alt="Modules"/>
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="MIT License"/>
</p>

---

**Aegis** is a modular, automated defense hardening framework for Linux. Named after the legendary shield of the gods, it raises every layer of protection on a Debian-based system — firewall, intrusion prevention, kernel hardening, malware scanning, file integrity monitoring, compliance auditing — in a single pass.

Run it on a fresh install or an existing machine. Aegis detects what's missing, installs it, configures it to battle-tested defaults, and verifies the result.

```bash
sudo ./setup.py --all
```

That's it. Shields up.

---

## Defense Layers

Aegis implements **defense-in-depth** — 16 modules across 6 shield layers, each independent, each reinforcing the others.

### Layer 1 — Perimeter Shield
Blocks threats before they reach the system.

| Module | Tool | What It Does |
|--------|------|-------------|
| **Firewall** | UFW | Drop-all-incoming policy with explicit allowlist |
| **VPN** | AirVPN Eddie | Encrypted tunnel for all outbound traffic |
| **Intrusion Prevention** | Fail2ban | Auto-bans IPs after repeated failed auth (SSH, web) with escalating penalties |

### Layer 2 — Hull Plating
Hardens the operating system kernel and network stack against exploitation.

| Module | Tool | What It Does |
|--------|------|-------------|
| **Kernel Hardening** | sysctl | 20+ parameters: ASLR, ptrace restriction, ICMP lockdown, SYN flood protection |
| **SSH Hardening** | OpenSSH | Strong ciphers (ChaCha20, AES-256-GCM), modern KEX, root login disabled |
| **Auto-Patch** | unattended-upgrades | Security patches applied daily, unused kernels cleaned automatically |

### Layer 3 — Structural Integrity
Isolates processes and enforces mandatory access control.

| Module | Tool | What It Does |
|--------|------|-------------|
| **Access Control** | AppArmor | Mandatory access control profiles for system services |
| **Process Isolation** | Firejail | Namespace sandboxing for untrusted applications |
| **Wireless Security** | Bluetooth controls | Disable or harden Bluetooth (non-discoverable, restricted pairing) |

### Layer 4 — Internal Sensors
Detects threats that have already breached the perimeter.

| Module | Tool | What It Does |
|--------|------|-------------|
| **Antivirus** | ClamAV | Automated daily scans of /home, /root, /tmp with freshclam updates |
| **Rootkit Scanner** | rkhunter | Daily rootkit and backdoor detection |
| **System Auditing** | auditd | Logs privilege escalation, file access, config changes, SSH key modifications |

### Layer 5 — Integrity Monitoring
Verifies the system hasn't been tampered with.

| Module | Tool | What It Does |
|--------|------|-------------|
| **File Integrity** | AIDE | SHA-512 checksums of critical paths, daily change detection |
| **Disk Health** | smartmontools | S.M.A.R.T. monitoring with daily health checks and alerts |
| **Container Scanning** | Trivy | Vulnerability scanning for Docker images (on-demand) |

### Layer 6 — Compliance Verification
Proves the defenses work against recognized standards.

| Module | Tool | What It Does |
|--------|------|-------------|
| **CIS Benchmarks** | OpenSCAP | Weekly automated compliance audits against CIS Level 2 profiles with HTML reports |

---

## Quick Start

### One Command — Full Defense

```bash
git clone https://github.com/PaddockEngineering/aegis.git
cd aegis
sudo ./setup.py --all
```

### Interactive Mode

Choose which shields to raise:

```bash
sudo ./setup.py
```

```
FIREWALL:
  Install UFW Firewall? (y/n): y
MALWARE:
  Install ClamAV? (y/n): y
  Install rkhunter? (y/n): y
...
```

### By Shield Layer

```bash
sudo ./setup.py --firewall            # Perimeter shield only
sudo ./setup.py --malware             # Internal sensors only
sudo ./setup.py --hardening           # Hull plating (Fail2ban, Auditd, SSH, Auto-patch)
sudo ./setup.py --hardening-medium    # Structural integrity (AppArmor, Kernel, Bluetooth)
sudo ./setup.py --hardening-low       # Integrity monitoring (AIDE, Trivy, OpenSCAP)
sudo ./setup.py --monitoring          # Hardware sensors and dashboards
```

### Check Shield Status

```bash
sudo ./setup.py --status
```

### Install as System Command

```bash
sudo ln -s $(pwd)/aegis /usr/local/bin/aegis
sudo aegis --status
```

---

## What Aegis Configures

Every module installs its tool, applies hardened defaults, and starts the service. No manual post-install required.

### Automated Cron Jobs

Aegis creates these scheduled defenses in `/etc/cron.daily/`:

| Job | Schedule | What It Does |
|-----|----------|-------------|
| `aegis-clamav-scan` | Daily | Updates virus DB, scans /home /root /tmp |
| `aegis-rkhunter-scan` | Daily | Updates definitions, runs rootkit check |
| `aegis-aide-check` | Daily | File integrity verification (background priority) |
| `aegis-openscap-scan` | Weekly | CIS compliance audit with HTML report |

### Key Configuration Defaults

| Setting | Value | Why |
|---------|-------|-----|
| Fail2ban ban time | 15 min (7 days for repeat offenders) | Escalating response to persistent attackers |
| SSH ciphers | ChaCha20-Poly1305, AES-256-GCM/CTR | Only modern, audited algorithms |
| Kernel ptrace | Scope 2 (root only) | Prevents code injection via process tracing |
| Auto-reboot | Disabled | Security patches applied, but you control reboots |
| Audit rules | Immutable after load (`-e 2`) | Attacker can't disable audit logging |
| AIDE scans | `nice -19 ionice -c3` | Integrity checks never impact system performance |

---

## Supported Systems

| Distribution | Versions | Status |
|-------------|----------|--------|
| Ubuntu | 20.04, 22.04, 24.04 | Fully tested |
| Debian | 10, 11, 12 | Supported |
| Linux Mint | 20+, 21+ | Supported |
| Pop!_OS | 22.04+ | Supported |
| Other Debian-based | — | Should work (APT + systemd required) |

### Requirements

- Root or sudo access
- APT package manager
- systemd
- Internet connection (for package downloads)

---

## Design Philosophy

### What's Included — And Why

Every module in Aegis is here because it provides **measurable defense** with **zero interference** on a single-machine system. No bloat, no theory-only tools, no enterprise overhead.

### What's NOT Included — And Why

**Network IDS (Suricata/Snort)** — Designed for network perimeters and multi-host environments. On a single machine, it consumes 5-15% CPU constantly, requires weeks of tuning, and monitors only your own traffic. UFW + AppArmor provide equivalent host-level protection at zero cost.

Aegis is opinionated about scope: it defends the machine it runs on. Network-wide defense is a different problem.

### How Aegis Compares

| Tool | Approach | Aegis Advantage |
|------|----------|----------------|
| **Lynis** | Audits and reports problems | Aegis *fixes* them — then you can run Lynis to verify |
| **Bastille** (discontinued) | Legacy Perl-based hardening | Aegis is modern Python 3, systemd-native, actively maintained |
| **Ansible hardening roles** | Infrastructure-scale automation | Aegis is purpose-built for single machines — simpler, faster, no YAML |
| **Manual CIS hardening** | Follow a 300-page PDF | Aegis automates the guidance, OpenSCAP verifies the result |

---

## Logs and Data

| Path | Contents |
|------|----------|
| `~/.aegis/logs/aegis_*.log` | Setup and configuration logs |
| `/var/log/aegis-clamav.log` | Daily antivirus scan results |
| `/var/log/aegis-rkhunter.log` | Daily rootkit scan results |
| `/var/log/aide/check.log` | File integrity check results |
| `/var/log/openscap/reports/` | Weekly CIS compliance reports (HTML) |
| `/var/log/audit/` | System audit trail (auditd) |

---

## Project Structure

```
aegis/
├── setup.py                    # Main orchestrator
├── aegis                       # System command wrapper
├── config/
│   └── tools.json              # Tool registry and metadata
├── tools/
│   ├── firewall.py             # Layer 1 — UFW
│   ├── vpn.py                  # Layer 1 — AirVPN Eddie
│   ├── fail2ban.py             # Layer 1 — Intrusion prevention
│   ├── kernel_sysctl.py        # Layer 2 — Kernel hardening (20+ params)
│   ├── ssh_hardening.py        # Layer 2 — SSH configuration
│   ├── unattended_upgrades.py  # Layer 2 — Auto security patches
│   ├── apparmor.py             # Layer 3 — Mandatory access control
│   ├── isolation.py            # Layer 3 — Firejail sandboxing
│   ├── bluetooth.py            # Layer 3 — Wireless security
│   ├── malware.py              # Layer 4 — ClamAV + rkhunter
│   ├── auditd.py               # Layer 4 — System audit daemon
│   ├── monitoring.py           # Layer 4 — Hardware sensors
│   ├── aide.py                 # Layer 5 — File integrity
│   ├── smartmontools.py        # Layer 5 — Disk health
│   ├── docker_security.py      # Layer 5 — Container scanning
│   └── openscap.py             # Layer 6 — CIS compliance
├── utils/
│   ├── system.py               # OS detection, privilege checks
│   ├── apt.py                  # Package management
│   └── logger.py               # Colored terminal + file logging
├── tests/                      # Test suite
├── SECURITY_AUDIT.md           # Current system audit report
├── CONTRIBUTING.md             # Contribution guidelines
└── LICENSE                     # MIT
```

---

## Adding New Modules

```python
# tools/my_shield.py
def install():
    """Install the tool."""
    from utils.apt import install_package
    return install_package("package-name")

def configure():
    """Apply hardened configuration."""
    # Write config, enable service, verify
    return True

def check():
    """Check if installed."""
    from utils.system import command_exists
    return command_exists("tool")

def status():
    """Report shield status."""
    return "Shield active" if check() else "Shield offline"
```

Add to `config/tools.json`, import in `setup.py`, add CLI flag. See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## License

MIT — See [LICENSE](LICENSE)

---

<p align="center"><strong>Aegis</strong> — Shields up.</p>
