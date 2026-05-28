# WP Attack Detector

<p align="center">
  <img src="docs/banner.png" alt="WP Attack Detector" width="720">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-red?style=flat-square">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue?style=flat-square">
  <img src="https://img.shields.io/badge/platform-cPanel%2FWHM-orange?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/root-required-critical?style=flat-square">
</p>

> Lightweight security monitoring framework for shared Linux hosting environments.
> Identifies compromised WordPress accounts generating outbound attacks via iptables LOG + UID correlation.

---

## Overview

WP Attack Detector monitors outbound traffic on shared hosting servers and correlates suspicious HTTP requests back to the responsible cPanel account. It uses `iptables LOG` rules with `--log-uid` to capture which system UID is generating attack traffic — no proxies, no agents, no performance impact.

**Designed for:**
- cPanel / WHM servers
- LiteSpeed / Apache shared hosting
- Incident response and abuse handling workflows
- Hosting provider SOC teams

---

## Detected Attack Patterns

| Pattern | Description | Severity |
|---|---|---|
| `xmlrpc.php` | XML-RPC brute force / DDoS amplification | CRITICAL |
| `wp-login.php` | WordPress login abuse / credential stuffing | HIGH |
| `/administrator/` | Joomla administrator panel probing | HIGH |
| `wp-content/plugins/` | WordPress enumeration / WPScan probing | MEDIUM |
| Outbound PHP connections | Webshell-driven or malware C2 traffic | HIGH |
| Suspicious lsphp processes | High-CPU PHP processes under hosting UIDs | HIGH |
| Webshell indicators | `eval(base64_decode`, `assert($_`, `preg_replace /e` and more | CRITICAL |
| Recently modified files | PHP/JS/PL files changed within the lookback window | HIGH |

---

## Requirements

- Python 3.6+
- Root access
- `iptables` with `string` match module (`xt_string`)
- `ss` (iproute2)
- `getent` (glibc-utils)
- cPanel / WHM environment (optional but recommended)

---

## Installation

```bash
# Clone
git clone https://github.com/BlackRainSentinel/wp-attack-detector.git
cd wp-attack-detector

# Install
cp wp-attack-detector.py /usr/local/bin/wp-attack-detector
chmod +x /usr/local/bin/wp-attack-detector

# First run
wp-attack-detector --setup-iptables
wp-attack-detector --scan --report
```

---

## Usage

```
usage: wp-attack-detector [-h] (--scan | --watch | --setup-iptables |
                                --remove-iptables | --install-systemd | --version)
                          [--report] [--quiet] [--lookback MIN]
                          [--interval SEC] [--apache-lines N]
```

### Modes

| Flag | Description |
|---|---|
| `--scan` | One-shot full scan across all detection layers |
| `--watch` | Real-time daemon mode with polling loop |
| `--setup-iptables` | Install iptables LOG rules and exit |
| `--remove-iptables` | Remove all WP-Attack-Detector iptables rules |
| `--install-systemd` | Generate and install systemd service + timer |
| `--version` | Print version |

### Options

| Flag | Default | Description |
|---|---|---|
| `--report` | off | Generate HTML forensic report after scan |
| `--quiet` | off | Suppress terminal output (log only) |
| `--lookback MIN` | 60 | How far back to look in logs (minutes) |
| `--interval SEC` | 30 | Polling interval for watch mode (seconds) |
| `--apache-lines N` | 5000 | Lines to tail from each Apache/domlog file |

### Examples

```bash
# Full scan with HTML report
wp-attack-detector --scan --report

# Real-time watch, 60-second interval
wp-attack-detector --watch --interval 60

# Scan last 2 hours silently, save report
wp-attack-detector --scan --lookback 120 --quiet --report

# Install iptables rules only
wp-attack-detector --setup-iptables

# Install systemd timer for automatic scheduled scans
wp-attack-detector --install-systemd
systemctl enable --now wp-attack-detector.timer
```

---

## Detection Architecture

```
Outbound HTTP Request (from PHP/lsphp)
          │
          ▼
  iptables OUTPUT chain
  └─ LOG rule (--log-uid --log-prefix "WP-ATK-DETECT")
          │
          ▼
  /var/log/messages  ←── kernel logs UID=XXXX
          │
          ▼
  wp-attack-detector
  ├─ UID → cPanel username (getent passwd)
  ├─ Scan Apache / domlogs for pattern hits
  ├─ Analyze lsphp processes (PID → /proc/PID/status → UID)
  ├─ Check outbound connections via ss (public IPs only)
  ├─ Scan user homedir for recently modified files
  └─ Detect webshell indicators in PHP files
          │
          ▼
  Terminal output + /var/log/wp-attack-detector/audit.log
  + HTML forensic report (optional)
```

---

## Output

### Terminal
Color-coded output with severity levels:

```
  ✔  OK        Rule already present → xmlrpc.php:80
  ⚠  WARN      High-CPU PHP process: PID=18432 USER=client42 CPU=87.3%
  ✘  CRITICAL  NEW ATTACK DETECTED → UID=1045 USER=client42 (12 events)
  →  INFO      Investigating user: client42 (home: /home/client42)
```

### Log File
Persistent structured log at `/var/log/wp-attack-detector/audit.log`

### HTML Report
Full dark-themed forensic report saved to `/var/log/wp-attack-detector/reports/`.
Includes: stat cards, kernel log hit table, compromised user investigation,
suspicious PHP processes, outbound connections, Apache/domlog pattern hits.

---

## systemd Integration

After running `--install-systemd`, two units are created:

| Unit | Description |
|---|---|
| `wp-attack-detector.service` | One-shot scan + report |
| `wp-attack-detector.timer` | Runs every 15 minutes after boot |

```bash
systemctl enable --now wp-attack-detector.timer
systemctl status wp-attack-detector.timer
journalctl -u wp-attack-detector.service -f
```

---

## File Structure

```
wp-attack-detector/
├── wp-attack-detector.py           Main script
├── systemd/
│   ├── wp-attack-detector.service  systemd service unit
│   └── wp-attack-detector.timer    systemd timer unit
├── docs/
│   └── banner.png
├── README.md
└── LICENSE
```

---

## Log Locations

| Path | Description |
|---|---|
| `/var/log/wp-attack-detector/audit.log` | Main persistent log |
| `/var/log/wp-attack-detector/reports/` | HTML forensic reports |

---

## Security Notes

- This tool **does not block traffic** — it only logs and identifies.
- iptables rules are scoped to the `OUTPUT` chain only.
- No data is sent off-server. Everything stays local.
- Webshell detection is heuristic-based — always manually verify flagged files before taking action.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**BlackRainSentinel** — Linux Security Specialist & Systems Administrator
Focused on shared hosting security, abuse incident response, and automated forensic workflows.
