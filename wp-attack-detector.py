#!/usr/bin/env python3
"""
██╗    ██╗██████╗      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██║    ██║██╔══██╗    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║ █╗ ██║██████╔╝    ███████║   ██║      ██║   ███████║██║     █████╔╝
██║███╗██║██╔═══╝     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗
╚███╔███╔╝██║         ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚══╝╚══╝ ╚═╝         ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

WP Attack Detector v1.0.0
Lightweight security monitoring framework for shared Linux hosting.
Detects compromised WordPress accounts generating outbound attacks.

Author  : BlackRainSentinel
License : MIT
Target  : cPanel/WHM + LiteSpeed/Apache shared hosting
"""

import os
import re
import sys
import json
import time
import signal
import argparse
import subprocess
import ipaddress
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ============================================================
# Version
# ============================================================
VERSION = "1.0.0"
RELEASE_DATE = "2025"

# ============================================================
# ANSI Colors & Styles
# ============================================================
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"

    BG_RED    = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN  = "\033[42m"
    BG_BLUE   = "\033[44m"

# ============================================================
# Configuration
# ============================================================
LOG_DIR          = Path("/var/log/wp-attack-detector")
LOG_FILE         = LOG_DIR / "audit.log"
REPORT_DIR       = LOG_DIR / "reports"
IPTABLES_COMMENT = "WP-Attack-Detector"
LOG_PREFIX       = "WP-ATK-DETECT"

SYSTEM_LOGS = [
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/kern.log",
]

APACHE_LOGS = [
    "/var/log/apache2/access_log",
    "/usr/local/apache/logs/access_log",
    "/var/log/httpd/access_log",
]

DOMLOGS_DIR  = "/usr/local/apache/domlogs"
CPANEL_USERS = "/var/cpanel/users"
ETC_PASSWD   = "/etc/passwd"

# Detection patterns
ATTACK_PATTERNS = {
    "xmlrpc_bruteforce": {
        "strings":     ["xmlrpc.php"],
        "description": "XML-RPC brute force / DDoS amplification",
        "severity":    "CRITICAL",
        "ports":       [80, 443],
    },
    "wplogin_abuse": {
        "strings":     ["wp-login.php"],
        "description": "WordPress login page abuse / credential stuffing",
        "severity":    "HIGH",
        "ports":       [80, 443],
    },
    "joomla_probe": {
        "strings":     ["/administrator/index.php", "/administrator/"],
        "description": "Joomla administrator panel probing",
        "severity":    "HIGH",
        "ports":       [80, 443],
    },
    "wp_scan_probe": {
        "strings":     ["wp-content/plugins/", "wp-includes/", "?author="],
        "description": "WordPress enumeration / WPScan probing",
        "severity":    "MEDIUM",
        "ports":       [80, 443],
    },
    "malicious_outbound": {
        "strings":     [],
        "description": "Suspicious outbound HTTP/S connection from PHP process",
        "severity":    "HIGH",
        "ports":       [80, 443, 8080, 8443],
    },
}

SUSPICIOUS_PHP_FUNCTIONS = [
    "eval", "base64_decode", "str_rot13", "gzinflate", "gzuncompress",
    "gzdecode", "str_replace", "preg_replace", "assert", "system",
    "exec", "shell_exec", "passthru", "popen", "proc_open",
    "curl_exec", "file_get_contents", "fsockopen", "mail",
]

WEBSHELL_INDICATORS = [
    r"eval\s*\(\s*base64_decode",
    r"eval\s*\(\s*gzinflate",
    r"eval\s*\(\s*str_rot13",
    r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(",
    r"preg_replace\s*\(.*\/e[\"']",
    r"assert\s*\(\s*\$",
    r"passthru\s*\(\s*\$",
    r"system\s*\(\s*\$",
]

# ============================================================
# Logging Helpers
# ============================================================
_quiet_mode = False
_log_handle = None

def log_init():
    global _log_handle
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _log_handle = open(LOG_FILE, "a")
    _log_handle.write(f"\n{'='*70}\n")
    _log_handle.write(f"Session started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    _log_handle.write(f"{'='*70}\n\n")

def log_write(msg: str):
    if _log_handle:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        _log_handle.write(f"[{ts}] {msg}\n")
        _log_handle.flush()

def log_close():
    if _log_handle:
        _log_handle.write(f"\n{'='*70}\n")
        _log_handle.write(f"Session ended: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        _log_handle.close()

def _print(msg: str):
    if not _quiet_mode:
        print(msg)

def print_status(icon: str, color: str, label: str, msg: str):
    _print(f"  {color}{icon}{C.RESET}  {C.BOLD}{label}{C.RESET}  {msg}")
    log_write(f"[{label}] {msg}")

def print_ok(msg: str):
    print_status("✔", C.BGREEN, "OK      ", msg)

def print_warn(msg: str):
    print_status("⚠", C.BYELLOW, "WARN    ", msg)

def print_critical(msg: str):
    print_status("✘", C.BRED, "CRITICAL", msg)

def print_info(msg: str):
    print_status("→", C.BCYAN, "INFO    ", msg)

def print_section(title: str):
    width = 60
    _print(f"\n{C.BBLUE}{'─'*width}{C.RESET}")
    _print(f"{C.BOLD}{C.BWHITE}  {title}{C.RESET}")
    _print(f"{C.BBLUE}{'─'*width}{C.RESET}\n")
    log_write(f"--- {title} ---")

def print_finding(label: str, value: str, severity: str = "INFO"):
    colors = {
        "CRITICAL": C.BRED,
        "HIGH":     C.BYELLOW,
        "MEDIUM":   C.BCYAN,
        "LOW":      C.BGREEN,
        "INFO":     C.BWHITE,
    }
    col = colors.get(severity, C.BWHITE)
    _print(f"    {C.DIM}┌─{C.RESET} {C.BOLD}{label}{C.RESET}")
    _print(f"    {C.DIM}└─{C.RESET} {col}{value}{C.RESET}")
    log_write(f"  [{severity}] {label}: {value}")

# ============================================================
# Banner
# ============================================================
def print_banner():
    banner = f"""
{C.BRED}{C.BOLD}
  ██╗    ██╗██████╗      █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
  ██║    ██║██╔══██╗    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
  ██║ █╗ ██║██████╔╝    ███████║   ██║      ██║   ███████║██║     █████╔╝
  ██║███╗██║██╔═══╝     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗
  ╚███╔███╔╝██║         ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
   ╚══╝╚══╝ ╚═╝         ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{C.RESET}
{C.BYELLOW}{C.BOLD}
  ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
  ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
  ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
  ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝{C.RESET}

  {C.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
  {C.BWHITE}Shared Hosting Attack Detection Framework{C.RESET} {C.DIM}| v{VERSION} | {RELEASE_DATE}{C.RESET}
  {C.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
  {C.DIM}Target: cPanel/WHM + LiteSpeed/Apache | Author: BlackRainSentinel{C.RESET}
"""
    _print(banner)

# ============================================================
# iptables Management
# ============================================================
def get_existing_rules() -> str:
    result = subprocess.run(
        ["iptables", "-S", "OUTPUT"],
        capture_output=True, text=True
    )
    return result.stdout

def build_iptables_rules() -> list:
    rules = []
    for pattern_name, pattern in ATTACK_PATTERNS.items():
        for string in pattern["strings"]:
            for port in pattern["ports"]:
                proto = "tcp"
                rule = (
                    f'-p {proto} --dport {port} '
                    f'-m string --string "{string}" --algo kmp --to 1024 '
                    f'-j LOG --log-prefix "{LOG_PREFIX} " --log-level 4 --log-uid '
                    f'-m comment --comment "{IPTABLES_COMMENT}/{pattern_name}"'
                )
                rules.append((pattern_name, string, port, rule))
    return rules

def ensure_iptables_rules(verbose: bool = True) -> dict:
    existing = get_existing_rules()
    results  = {"added": 0, "exists": 0, "failed": 0}

    if verbose:
        print_section("Setting Up iptables LOG Rules")

    rules = build_iptables_rules()
    for pattern_name, string, port, rule in rules:
        label = f"{string}:{port}"
        if f"{IPTABLES_COMMENT}/{pattern_name}" in existing:
            results["exists"] += 1
            if verbose:
                print_ok(f"Rule already present → {label}")
            continue

        ret = subprocess.run(
            ["iptables", "-I", "OUTPUT", "1"] + rule.split(),
            capture_output=True, text=True
        )
        if ret.returncode == 0:
            results["added"] += 1
            if verbose:
                print_ok(f"Rule inserted → {label}")
        else:
            results["failed"] += 1
            if verbose:
                print_warn(f"Failed to insert rule → {label} ({ret.stderr.strip()})")

    log_write(f"iptables: added={results['added']} exists={results['exists']} failed={results['failed']}")
    return results

def remove_iptables_rules():
    print_section("Removing iptables LOG Rules")
    existing_lines = get_existing_rules().splitlines()
    removed = 0
    for line in existing_lines:
        if IPTABLES_COMMENT in line:
            rule_body = line.lstrip("-A OUTPUT").strip()
            ret = subprocess.run(
                ["iptables", "-D", "OUTPUT"] + rule_body.split(),
                capture_output=True, text=True
            )
            if ret.returncode == 0:
                removed += 1

    if removed:
        print_ok(f"Removed {removed} iptables rules")
    else:
        print_warn("No WP-Attack-Detector rules found to remove")
    log_write(f"iptables cleanup: removed {removed} rules")

# ============================================================
# UID → cPanel User Mapping
# ============================================================
_uid_cache: dict = {}

def uid_to_user(uid: str) -> str:
    if uid in _uid_cache:
        return _uid_cache[uid]

    try:
        result = subprocess.run(
            ["getent", "passwd", uid],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            username = result.stdout.split(":")[0]
            _uid_cache[uid] = username
            return username
    except Exception:
        pass

    _uid_cache[uid] = f"UID:{uid}"
    return f"UID:{uid}"

def get_cpanel_users() -> list:
    users = []
    if os.path.isdir(CPANEL_USERS):
        try:
            users = [f for f in os.listdir(CPANEL_USERS)]
        except PermissionError:
            pass
    return users

def get_user_homedir(username: str) -> str:
    try:
        result = subprocess.run(
            ["getent", "passwd", username],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(":")
            if len(parts) >= 6:
                return parts[5]
    except Exception:
        pass
    return f"/home/{username}"

# ============================================================
# Log Scanning
# ============================================================
UID_PATTERN = re.compile(r"UID=(\d+)")
SRC_PATTERN = re.compile(r"SRC=(\S+)")
DST_PATTERN = re.compile(r"DST=(\S+)")
DPT_PATTERN = re.compile(r"DPT=(\d+)")

def scan_kernel_logs(lookback_minutes: int = 60) -> dict:
    hits = defaultdict(list)
    cutoff_ts = time.time() - (lookback_minutes * 60)

    for logfile in SYSTEM_LOGS:
        if not os.path.isfile(logfile):
            continue
        try:
            with open(logfile, "r", errors="ignore") as f:
                for line in f:
                    if LOG_PREFIX not in line:
                        continue
                    uid_m = UID_PATTERN.search(line)
                    if not uid_m:
                        continue
                    uid = uid_m.group(1)
                    src = SRC_PATTERN.search(line)
                    dst = DST_PATTERN.search(line)
                    dpt = DPT_PATTERN.search(line)
                    hits[uid].append({
                        "uid":      uid,
                        "src":      src.group(1)  if src else "?",
                        "dst":      dst.group(1)  if dst else "?",
                        "dport":    dpt.group(1)  if dpt else "?",
                        "raw":      line.strip(),
                        "logfile":  logfile,
                    })
        except PermissionError:
            pass

    return dict(hits)

# ============================================================
# Process Analysis
# ============================================================
def get_lsphp_processes() -> list:
    procs = []
    try:
        result = subprocess.run(
            ["ps", "auxww"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "lsphp" in line or ("php" in line.lower() and "cgi" in line.lower()):
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({
                        "user":    parts[0],
                        "pid":     parts[1],
                        "cpu":     parts[2],
                        "mem":     parts[3],
                        "cmd":     parts[10] if len(parts) > 10 else parts[-1],
                    })
    except Exception:
        pass
    return procs

def get_outbound_connections() -> list:
    conns = []
    try:
        result = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local   = parts[3] if len(parts) > 3 else ""
            remote  = parts[4] if len(parts) > 4 else ""
            process = parts[5] if len(parts) > 5 else ""

            if "php" not in process.lower() and "lsphp" not in process.lower():
                continue

            try:
                remote_ip   = remote.rsplit(":", 1)[0]
                remote_port = remote.rsplit(":", 1)[1] if ":" in remote else "?"
                ip_obj      = ipaddress.ip_address(remote_ip.strip("[]"))
                if ip_obj.is_private:
                    continue
            except Exception:
                continue

            conns.append({
                "local":   local,
                "remote":  remote,
                "process": process,
            })
    except Exception:
        pass
    return conns

def get_php_pid_uid(pid: str) -> str:
    try:
        status_file = f"/proc/{pid}/status"
        with open(status_file, "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = line.split()[1]
                    return uid
    except Exception:
        pass
    return "?"

# ============================================================
# Apache / Domlog Analysis
# ============================================================
def scan_apache_logs(pattern: str, lookback_lines: int = 5000) -> list:
    hits = []
    compiled = re.compile(re.escape(pattern), re.IGNORECASE)

    for logfile in APACHE_LOGS:
        if not os.path.isfile(logfile):
            continue
        try:
            result = subprocess.run(
                ["tail", "-n", str(lookback_lines), logfile],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if compiled.search(line):
                    hits.append({"line": line.strip(), "source": logfile})
        except Exception:
            pass

    if os.path.isdir(DOMLOGS_DIR):
        try:
            for entry in os.scandir(DOMLOGS_DIR):
                if not entry.is_file():
                    continue
                if entry.name.endswith("-bytes_log") or entry.name.endswith(".offset"):
                    continue
                try:
                    result = subprocess.run(
                        ["tail", "-n", "2000", entry.path],
                        capture_output=True, text=True
                    )
                    for line in result.stdout.splitlines():
                        if compiled.search(line):
                            hits.append({"line": line.strip(), "source": entry.path})
                except Exception:
                    pass
        except PermissionError:
            pass

    return hits

# ============================================================
# File System Analysis
# ============================================================
def find_recent_modifications(homedir: str, minutes: int = 60) -> list:
    modified = []
    try:
        result = subprocess.run(
            [
                "find", homedir,
                "-type", "f",
                "-newer", f"/proc/uptime",
                "-mmin", f"-{minutes}",
                "(", "-name", "*.php", "-o", "-name", "*.js",
                "-o", "-name", "*.pl", "-o", "-name", "*.py", ")",
                "-not", "-path", "*/.*",
            ],
            capture_output=True, text=True, timeout=15
        )
        modified = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    return modified

def find_suspicious_php_files(homedir: str) -> list:
    suspicious = []
    webshell_re = [re.compile(p, re.IGNORECASE) for p in WEBSHELL_INDICATORS]

    try:
        result = subprocess.run(
            ["find", homedir, "-name", "*.php", "-type", "f",
             "-not", "-path", "*/.*"],
            capture_output=True, text=True, timeout=20
        )
        files = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return suspicious

    for filepath in files[:500]:
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read(8192)
            for pattern in webshell_re:
                if pattern.search(content):
                    suspicious.append({
                        "file":    filepath,
                        "pattern": pattern.pattern,
                    })
                    break
        except Exception:
            pass

    return suspicious

# ============================================================
# One-Shot Scan Mode
# ============================================================
def run_scan(args) -> dict:
    report_data = {
        "scan_time":         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "mode":              "scan",
        "kernel_log_hits":   {},
        "php_processes":     [],
        "outbound_conns":    [],
        "apache_hits":       {},
        "compromised_users": [],
        "summary": {
            "total_uids":            0,
            "total_php_procs":       0,
            "total_outbound_conns":  0,
            "total_apache_hits":     0,
            "total_suspicious_files":0,
        }
    }

    # ---- Kernel log hits ----
    print_section("Kernel Log Analysis (iptables hits)")
    kernel_hits = scan_kernel_logs(lookback_minutes=getattr(args, "lookback", 60))

    if not kernel_hits:
        print_ok("No attack-related kernel log entries found")
    else:
        print_critical(f"Detected {len(kernel_hits)} unique UID(s) in kernel logs")

    uid_user_map = {}
    for uid, events in kernel_hits.items():
        username = uid_to_user(uid)
        uid_user_map[uid] = username
        print_finding(
            f"UID {uid} → {username}",
            f"{len(events)} event(s) logged",
            "CRITICAL"
        )
        for evt in events[:3]:
            print_finding("  SRC→DST", f"{evt['src']} → {evt['dst']}:{evt['dport']}", "HIGH")
        report_data["kernel_log_hits"][uid] = {
            "username": username,
            "events":   events,
        }

    report_data["summary"]["total_uids"] = len(kernel_hits)

    # ---- PHP process analysis ----
    print_section("PHP / lsphp Process Analysis")
    php_procs = get_lsphp_processes()
    suspicious_procs = []

    if not php_procs:
        print_ok("No active PHP/lsphp processes found")
    else:
        print_info(f"Found {len(php_procs)} PHP process(es)")
        for proc in php_procs:
            uid = get_php_pid_uid(proc["pid"])
            username = uid_to_user(uid) if uid != "?" else proc["user"]
            if username not in ("nobody", "?") and uid != "0":
                cpu = float(proc["cpu"]) if proc["cpu"] not in ("?", "") else 0
                if cpu > 5.0:
                    print_warn(f"High-CPU PHP process: PID={proc['pid']} USER={username} CPU={proc['cpu']}%")
                    suspicious_procs.append({**proc, "uid": uid, "username": username})
                else:
                    print_info(f"PHP process: PID={proc['pid']} USER={username} CPU={proc['cpu']}%")

    report_data["php_processes"] = suspicious_procs
    report_data["summary"]["total_php_procs"] = len(suspicious_procs)

    # ---- Outbound connections ----
    print_section("Outbound Connection Analysis (PHP Processes)")
    outbound = get_outbound_connections()

    if not outbound:
        print_ok("No suspicious outbound PHP connections detected")
    else:
        print_critical(f"Found {len(outbound)} suspicious outbound PHP connection(s)")
        for conn in outbound:
            print_finding("Connection", f"{conn['local']} → {conn['remote']}", "HIGH")
            print_finding("Process",    conn["process"], "INFO")

    report_data["outbound_conns"] = outbound
    report_data["summary"]["total_outbound_conns"] = len(outbound)

    # ---- Apache / Domlog analysis ----
    print_section("Apache / Domlog Analysis")
    all_apache_hits = {}
    total_apache = 0
    for pattern_name, pattern in ATTACK_PATTERNS.items():
        for string in pattern["strings"]:
            hits = scan_apache_logs(string, lookback_lines=getattr(args, "apache_lines", 5000))
            if hits:
                print_warn(f"Pattern '{string}': {len(hits)} hit(s) in web logs")
                all_apache_hits[string] = hits
                total_apache += len(hits)
            else:
                print_ok(f"Pattern '{string}': no hits in web logs")

    report_data["apache_hits"] = all_apache_hits
    report_data["summary"]["total_apache_hits"] = total_apache

    # ---- Per-user deep investigation (if compromised users found) ----
    compromised_users = list(uid_user_map.values())
    if compromised_users:
        print_section("Deep User Investigation")
        for username in compromised_users:
            if username.startswith("UID:"):
                continue
            homedir = get_user_homedir(username)
            print_info(f"Investigating user: {username} (home: {homedir})")

            # Recent file modifications
            modified = find_recent_modifications(homedir, minutes=getattr(args, "lookback", 60))
            if modified:
                print_warn(f"  {len(modified)} recently modified file(s)")
                for f in modified[:5]:
                    print_finding("  Modified", f, "HIGH")
            else:
                print_ok(f"  No recently modified PHP/JS/PL files")

            # Suspicious PHP files
            suspicious_php = find_suspicious_php_files(homedir)
            if suspicious_php:
                print_critical(f"  {len(suspicious_php)} suspicious PHP file(s) detected")
                for s in suspicious_php[:5]:
                    print_finding("  Webshell indicator", s["file"], "CRITICAL")
                    print_finding("  Matched pattern",    s["pattern"], "INFO")
                report_data["summary"]["total_suspicious_files"] += len(suspicious_php)
            else:
                print_ok(f"  No webshell indicators found")

            report_data["compromised_users"].append({
                "username":       username,
                "homedir":        homedir,
                "modified_files": modified,
                "suspicious_php": suspicious_php,
            })

    # ---- Summary ----
    print_section("Scan Summary")
    s = report_data["summary"]
    print_finding("UIDs in kernel logs",       str(s["total_uids"]),             "CRITICAL" if s["total_uids"] > 0 else "INFO")
    print_finding("Suspicious PHP processes",  str(s["total_php_procs"]),        "HIGH"     if s["total_php_procs"] > 0 else "INFO")
    print_finding("Outbound PHP connections",  str(s["total_outbound_conns"]),   "HIGH"     if s["total_outbound_conns"] > 0 else "INFO")
    print_finding("Web log attack hits",       str(s["total_apache_hits"]),      "MEDIUM"   if s["total_apache_hits"] > 0 else "INFO")
    print_finding("Suspicious PHP files",      str(s["total_suspicious_files"]), "CRITICAL" if s["total_suspicious_files"] > 0 else "INFO")

    return report_data

# ============================================================
# Watch / Daemon Mode
# ============================================================
_stop_watch = False

def signal_handler(sig, frame):
    global _stop_watch
    _stop_watch = True
    _print(f"\n\n{C.BYELLOW}  ⚡ Interrupt received. Stopping watch mode...{C.RESET}\n")

def run_watch(args):
    global _stop_watch
    interval = getattr(args, "interval", 30)

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print_section("Watch Mode — Real-Time Detection")
    print_info(f"Polling interval: {interval}s | Press Ctrl+C to stop")
    print_info(f"Log file: {LOG_FILE}")

    ensure_iptables_rules(verbose=True)

    seen_uids: set = set()
    cycle = 0

    while not _stop_watch:
        cycle += 1
        ts = datetime.utcnow().strftime("%H:%M:%S")
        _print(f"\n  {C.DIM}[{ts}] Cycle #{cycle} — scanning...{C.RESET}")

        hits = scan_kernel_logs(lookback_minutes=max(1, interval // 30))

        new_hits = {uid: evts for uid, evts in hits.items() if uid not in seen_uids}
        if new_hits:
            for uid, events in new_hits.items():
                username = uid_to_user(uid)
                seen_uids.add(uid)
                print_critical(f"NEW ATTACK DETECTED → UID={uid} USER={username} ({len(events)} events)")
                for evt in events[:2]:
                    print_finding("  SRC→DST", f"{evt['src']} → {evt['dst']}:{evt['dport']}", "HIGH")
                log_write(f"WATCH-HIT uid={uid} user={username} events={len(events)}")
        else:
            _print(f"  {C.BGREEN}  ✔{C.RESET}  {C.DIM}No new UIDs detected{C.RESET}")

        outbound = get_outbound_connections()
        if outbound:
            print_warn(f"Active outbound PHP connections: {len(outbound)}")
            for conn in outbound:
                print_finding("  Connection", f"{conn['local']} → {conn['remote']}", "HIGH")

        for _ in range(interval):
            if _stop_watch:
                break
            time.sleep(1)

    print_info("Watch mode stopped.")
    log_write("Watch mode terminated.")

# ============================================================
# HTML Report Generator
# ============================================================
def generate_html_report(data: dict) -> Path:
    ts_safe   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outpath   = REPORT_DIR / f"wp-attack-detector_{ts_safe}.html"
    scan_time = data.get("scan_time", "N/A")
    s         = data.get("summary", {})

    def severity_badge(sev: str) -> str:
        colors = {
            "CRITICAL": ("#ff4757", "#fff"),
            "HIGH":     ("#ffa502", "#000"),
            "MEDIUM":   ("#1e90ff", "#fff"),
            "LOW":      ("#2ed573", "#000"),
            "INFO":     ("#747d8c", "#fff"),
        }
        bg, fg = colors.get(sev, ("#747d8c", "#fff"))
        return f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700">{sev}</span>'

    def stat_card(label: str, value, sev: str) -> str:
        colors = {
            "CRITICAL": "#ff4757",
            "HIGH":     "#ffa502",
            "MEDIUM":   "#1e90ff",
            "INFO":     "#2ed573",
        }
        col = colors.get(sev, "#2ed573")
        return f"""
        <div style="background:#1a1a2e;border:1px solid #2d2d44;border-left:4px solid {col};
                    border-radius:8px;padding:20px;flex:1;min-width:160px">
          <div style="font-size:2rem;font-weight:700;color:{col}">{value}</div>
          <div style="color:#aaa;font-size:0.85rem;margin-top:4px">{label}</div>
        </div>"""

    kernel_rows = ""
    for uid, info in data.get("kernel_log_hits", {}).items():
        username = info.get("username", f"UID:{uid}")
        count    = len(info.get("events", []))
        sample   = info["events"][0] if info.get("events") else {}
        src      = sample.get("src", "?")
        dst      = sample.get("dst", "?")
        dport    = sample.get("dport", "?")
        kernel_rows += f"""
        <tr>
          <td><code style="color:#1e90ff">{uid}</code></td>
          <td><code style="color:#ff6b81">{username}</code></td>
          <td>{count}</td>
          <td><code>{src}</code></td>
          <td><code>{dst}:{dport}</code></td>
          <td>{severity_badge("CRITICAL")}</td>
        </tr>"""

    user_rows = ""
    for u in data.get("compromised_users", []):
        uname  = u.get("username", "?")
        home   = u.get("homedir", "?")
        mfiles = len(u.get("modified_files", []))
        sphp   = len(u.get("suspicious_php", []))

        mfiles_html = ""
        for f in u.get("modified_files", [])[:5]:
            mfiles_html += f'<li><code style="color:#ffa502">{f}</code></li>'

        sphp_html = ""
        for sp in u.get("suspicious_php", [])[:5]:
            sphp_html += f'<li><code style="color:#ff4757">{sp["file"]}</code><br><small style="color:#aaa">{sp["pattern"]}</small></li>'

        user_rows += f"""
        <tr>
          <td><code style="color:#ff6b81">{uname}</code></td>
          <td><code style="color:#aaa">{home}</code></td>
          <td>{"<ul style='margin:0;padding-left:1rem'>" + mfiles_html + "</ul>" if mfiles_html else '<span style="color:#2ed573">✔ Clean</span>'}</td>
          <td>{"<ul style='margin:0;padding-left:1rem'>" + sphp_html + "</ul>" if sphp_html else '<span style="color:#2ed573">✔ Clean</span>'}</td>
        </tr>"""

    apache_rows = ""
    for pattern_str, hits in data.get("apache_hits", {}).items():
        for hit in hits[:5]:
            source = hit.get("source", "?")
            line   = hit.get("line", "")[:200]
            apache_rows += f"""
            <tr>
              <td><code style="color:#1e90ff">{pattern_str}</code></td>
              <td><code style="color:#aaa;font-size:0.75rem">{source}</code></td>
              <td><code style="color:#fff;font-size:0.72rem;word-break:break-all">{line}</code></td>
            </tr>"""

    php_rows = ""
    for proc in data.get("php_processes", []):
        php_rows += f"""
        <tr>
          <td><code style="color:#ffa502">{proc.get("pid","?")}</code></td>
          <td><code style="color:#ff6b81">{proc.get("username","?")}</code></td>
          <td>{proc.get("cpu","?")}%</td>
          <td>{proc.get("mem","?")}%</td>
          <td><code style="font-size:0.72rem;color:#aaa">{proc.get("cmd","")[:120]}</code></td>
        </tr>"""

    outbound_rows = ""
    for conn in data.get("outbound_conns", []):
        outbound_rows += f"""
        <tr>
          <td><code>{conn.get("local","?")}</code></td>
          <td><code style="color:#ff4757">{conn.get("remote","?")}</code></td>
          <td><code style="font-size:0.72rem;color:#aaa">{conn.get("process","?")[:80]}</code></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WP Attack Detector — Forensic Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Courier New', Consolas, monospace;
    background: #0d0d1a;
    color: #e0e0e0;
    min-height: 100vh;
    padding: 0;
  }}
  .header {{
    background: linear-gradient(135deg, #0d0d1a 0%, #1a0a2e 50%, #0d0d1a 100%);
    border-bottom: 1px solid #2d2d44;
    padding: 40px 48px 32px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(255,71,87,0.03) 2px,
      rgba(255,71,87,0.03) 4px
    );
    pointer-events: none;
  }}
  .header-title {{
    font-size: 1.8rem;
    font-weight: 700;
    color: #ff4757;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 6px;
  }}
  .header-sub {{
    color: #aaa;
    font-size: 0.85rem;
    letter-spacing: 2px;
  }}
  .header-meta {{
    margin-top: 20px;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
  }}
  .meta-item {{
    background: rgba(255,255,255,0.04);
    border: 1px solid #2d2d44;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 0.8rem;
    color: #aaa;
  }}
  .meta-item span {{ color: #1e90ff; }}
  .content {{ padding: 32px 48px; max-width: 1400px; margin: 0 auto; }}
  .stats-grid {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin: 32px 0;
  }}
  .section {{
    margin: 32px 0;
    background: #11111f;
    border: 1px solid #2d2d44;
    border-radius: 10px;
    overflow: hidden;
  }}
  .section-header {{
    background: #161628;
    padding: 14px 20px;
    border-bottom: 1px solid #2d2d44;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .section-title {{
    font-weight: 700;
    color: #e0e0e0;
    font-size: 0.9rem;
    letter-spacing: 1px;
    text-transform: uppercase;
  }}
  .section-count {{
    background: #1e90ff;
    color: #fff;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.72rem;
    margin-left: auto;
  }}
  .section-body {{ padding: 0; overflow-x: auto; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }}
  thead th {{
    background: #1a1a2e;
    color: #aaa;
    padding: 10px 16px;
    text-align: left;
    font-weight: 600;
    border-bottom: 1px solid #2d2d44;
    white-space: nowrap;
  }}
  tbody tr {{ border-bottom: 1px solid #1a1a2e; }}
  tbody tr:hover {{ background: rgba(30,144,255,0.04); }}
  tbody td {{ padding: 10px 16px; vertical-align: top; }}
  .empty-row td {{
    text-align: center;
    color: #2ed573;
    padding: 24px;
  }}
  .footer {{
    border-top: 1px solid #2d2d44;
    padding: 24px 48px;
    text-align: center;
    color: #555;
    font-size: 0.78rem;
    letter-spacing: 1px;
  }}
  code {{ font-family: inherit; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-title">⚡ WP Attack Detector</div>
  <div class="header-sub">Forensic Security Report — Shared Hosting</div>
  <div class="header-meta">
    <div class="meta-item">Scan Time: <span>{scan_time}</span></div>
    <div class="meta-item">Mode: <span>{data.get("mode","scan").upper()}</span></div>
    <div class="meta-item">Version: <span>v{VERSION}</span></div>
    <div class="meta-item">Log: <span>{LOG_FILE}</span></div>
  </div>
</div>

<div class="content">

  <div class="stats-grid">
    {stat_card("UIDs in Kernel Logs",      s.get("total_uids",0),             "CRITICAL" if s.get("total_uids",0) > 0 else "INFO")}
    {stat_card("Suspicious PHP Procs",     s.get("total_php_procs",0),        "HIGH"     if s.get("total_php_procs",0) > 0 else "INFO")}
    {stat_card("Outbound PHP Connections", s.get("total_outbound_conns",0),   "HIGH"     if s.get("total_outbound_conns",0) > 0 else "INFO")}
    {stat_card("Web Log Attack Hits",      s.get("total_apache_hits",0),      "MEDIUM"   if s.get("total_apache_hits",0) > 0 else "INFO")}
    {stat_card("Suspicious PHP Files",     s.get("total_suspicious_files",0), "CRITICAL" if s.get("total_suspicious_files",0) > 0 else "INFO")}
  </div>

  <!-- Kernel Log Hits -->
  <div class="section">
    <div class="section-header">
      <span style="color:#ff4757">⬛</span>
      <span class="section-title">Kernel Log Hits (iptables → UID Correlation)</span>
      <span class="section-count">{len(data.get("kernel_log_hits",{}))}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr>
          <th>UID</th><th>Username</th><th>Events</th>
          <th>Source IP</th><th>Destination</th><th>Severity</th>
        </tr></thead>
        <tbody>
          {"<tr class='empty-row'><td colspan='6'>✔ No kernel log hits detected</td></tr>" if not kernel_rows else kernel_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Compromised Users -->
  <div class="section">
    <div class="section-header">
      <span style="color:#ffa502">⬛</span>
      <span class="section-title">Compromised User Investigation</span>
      <span class="section-count">{len(data.get("compromised_users",[]))}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr>
          <th>Username</th><th>Home Directory</th>
          <th>Recently Modified Files</th><th>Suspicious PHP Files</th>
        </tr></thead>
        <tbody>
          {"<tr class='empty-row'><td colspan='4'>✔ No compromised users identified</td></tr>" if not user_rows else user_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- PHP Processes -->
  <div class="section">
    <div class="section-header">
      <span style="color:#1e90ff">⬛</span>
      <span class="section-title">Suspicious PHP / lsphp Processes</span>
      <span class="section-count">{len(data.get("php_processes",[]))}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr>
          <th>PID</th><th>User</th><th>CPU%</th><th>MEM%</th><th>Command</th>
        </tr></thead>
        <tbody>
          {"<tr class='empty-row'><td colspan='5'>✔ No suspicious PHP processes</td></tr>" if not php_rows else php_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Outbound Connections -->
  <div class="section">
    <div class="section-header">
      <span style="color:#ff4757">⬛</span>
      <span class="section-title">Outbound PHP Connections (Public IPs)</span>
      <span class="section-count">{len(data.get("outbound_conns",[]))}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Local</th><th>Remote</th><th>Process</th></tr></thead>
        <tbody>
          {"<tr class='empty-row'><td colspan='3'>✔ No suspicious outbound connections</td></tr>" if not outbound_rows else outbound_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Apache / Domlog Hits -->
  <div class="section">
    <div class="section-header">
      <span style="color:#ffa502">⬛</span>
      <span class="section-title">Apache / Domlog Pattern Hits</span>
      <span class="section-count">{s.get("total_apache_hits",0)}</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Pattern</th><th>Log Source</th><th>Log Line</th></tr></thead>
        <tbody>
          {"<tr class='empty-row'><td colspan='3'>✔ No attack patterns in web logs</td></tr>" if not apache_rows else apache_rows}
        </tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  WP Attack Detector v{VERSION} — BlackRainSentinel — Generated {scan_time}
</div>

</body>
</html>"""

    with open(outpath, "w") as f:
        f.write(html)

    return outpath

# ============================================================
# systemd Unit Generator
# ============================================================
def generate_systemd_units():
    service_content = f"""[Unit]
Description=WP Attack Detector - WordPress Attack Monitoring
After=network.target iptables.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wp-attack-detector --scan --report
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

    timer_content = """[Unit]
Description=WP Attack Detector Timer
Requires=wp-attack-detector.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
"""

    print_section("systemd Unit Generation")
    try:
        service_path = Path("/etc/systemd/system/wp-attack-detector.service")
        timer_path   = Path("/etc/systemd/system/wp-attack-detector.timer")
        with open(service_path, "w") as f:
            f.write(service_content)
        with open(timer_path, "w") as f:
            f.write(timer_content)
        print_ok(f"Service unit: {service_path}")
        print_ok(f"Timer unit:   {timer_path}")
        print_info("Enable with: systemctl enable --now wp-attack-detector.timer")
        log_write("systemd units generated")
    except PermissionError:
        print_warn("Permission denied. Run as root to install systemd units.")

# ============================================================
# Argument Parser
# ============================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-attack-detector",
        description="WP Attack Detector — Shared hosting security monitoring framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  wp-attack-detector --scan                      One-shot scan + terminal output
  wp-attack-detector --scan --report             Scan + generate HTML report
  wp-attack-detector --watch                     Real-time daemon mode
  wp-attack-detector --watch --interval 60       Watch mode, 60s interval
  wp-attack-detector --scan --lookback 120       Scan last 120 minutes of logs
  wp-attack-detector --setup-iptables            Install iptables LOG rules only
  wp-attack-detector --remove-iptables           Remove all iptables LOG rules
  wp-attack-detector --install-systemd           Install systemd service + timer
  wp-attack-detector --quiet --scan --report     Quiet mode, HTML only
        """
    )

    mode = parser.add_argument_group("Mode")
    mode_ex = mode.add_mutually_exclusive_group(required=True)
    mode_ex.add_argument("--scan",             action="store_true",  help="One-shot scan mode")
    mode_ex.add_argument("--watch",            action="store_true",  help="Real-time watch/daemon mode")
    mode_ex.add_argument("--setup-iptables",   action="store_true",  help="Install iptables LOG rules and exit")
    mode_ex.add_argument("--remove-iptables",  action="store_true",  help="Remove all iptables LOG rules")
    mode_ex.add_argument("--install-systemd",  action="store_true",  help="Generate and install systemd units")
    mode_ex.add_argument("--version",          action="store_true",  help="Print version and exit")

    opts = parser.add_argument_group("Options")
    opts.add_argument("--report",        action="store_true",  help="Generate HTML report after scan")
    opts.add_argument("--quiet",         action="store_true",  help="Suppress terminal output (log file only)")
    opts.add_argument("--lookback",      type=int, default=60, metavar="MIN",
                      help="Lookback window in minutes for log analysis (default: 60)")
    opts.add_argument("--interval",      type=int, default=30, metavar="SEC",
                      help="Polling interval for watch mode in seconds (default: 30)")
    opts.add_argument("--apache-lines",  type=int, default=5000, metavar="N",
                      help="Lines to tail from each Apache log file (default: 5000)")

    return parser

# ============================================================
# Entry Point
# ============================================================
def main():
    global _quiet_mode

    if os.geteuid() != 0:
        print(f"\n{C.BRED}  [ERROR]{C.RESET} This tool must be run as root.\n")
        sys.exit(1)

    parser = build_parser()
    args   = parser.parse_args()

    _quiet_mode = args.quiet

    if args.version:
        print(f"WP Attack Detector v{VERSION}")
        sys.exit(0)

    print_banner()
    log_init()
    log_write(f"Started: mode={'scan' if args.scan else 'watch' if args.watch else 'other'}")

    try:
        if args.setup_iptables:
            ensure_iptables_rules(verbose=True)

        elif args.remove_iptables:
            remove_iptables_rules()

        elif args.install_systemd:
            generate_systemd_units()

        elif args.scan:
            ensure_iptables_rules(verbose=False)
            report_data = run_scan(args)

            if args.report:
                print_section("Generating HTML Report")
                report_path = generate_html_report(report_data)
                print_ok(f"HTML report saved → {report_path}")
                log_write(f"HTML report: {report_path}")

        elif args.watch:
            run_watch(args)

    except KeyboardInterrupt:
        _print(f"\n{C.BYELLOW}  Aborted by user.{C.RESET}\n")
    except Exception as exc:
        print_critical(f"Unhandled exception: {exc}")
        log_write(f"EXCEPTION: {exc}")
        raise
    finally:
        log_close()


if __name__ == "__main__":
    main()
