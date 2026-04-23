#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log-Watcher
Author: Decryptious_ on Discord / Punchborn on IG
A cross-platform real-time log monitor with regex-based alerting for suspicious patterns.
For authorized security testing and system administration only.
"""

import sys
import os
import re
import json
import argparse
import threading
import time
import platform
import glob
import subprocess
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class DummyFore:
        def __getattr__(self, name): return ''
    class DummyStyle:
        def __getattr__(self, name): return ''
    Fore = DummyFore()
    Style = DummyStyle()

# ── TITLE BLOCK ──
def print_title():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Log-Watcher':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Real-Time Log Monitor & Threat Detector':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Author: Decryptious_ on Discord / Punchborn on IG{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Platforms: Linux | Windows | macOS{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Modes: SSH | Web | Auth | Firewall | Custom{Style.RESET_ALL}")
    print(f"{Fore.RED}  For authorized security testing only{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print()

# ── DEFAULT PATTERNS ──
DEFAULT_PATTERNS = {
    "ssh_bruteforce": {
        "regex": r"(?i)(failed password|authentication failure|invalid user).*from\s+(\d+\.\d+\.\d+\.\d+)",
        "severity": "HIGH",
        "description": "SSH brute force attempt"
    },
    "privilege_escalation": {
        "regex": r"(?i)(sudo:.*user NOT in sudoers|su:.*authentication failure|pkexec)",
        "severity": "CRITICAL",
        "description": "Possible privilege escalation attempt"
    },
    "web_sql_injection": {
        "regex": r"(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table|1=1|sleep\(|benchmark\()",
        "severity": "HIGH",
        "description": "Potential SQL injection in web logs"
    },
    "web_xss": {
        "regex": r"(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        "severity": "MEDIUM",
        "description": "Potential XSS attempt in web logs"
    },
    "web_path_traversal": {
        "regex": r"(?i)(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|/proc/self)",
        "severity": "HIGH",
        "description": "Path traversal attempt"
    },
    "malware_indicator": {
        "regex": r"(?i)(base64_decode|eval\(|exec\(|system\(|shell_exec|passthru)",
        "severity": "CRITICAL",
        "description": "Possible malware/webshell activity"
    },
    "scan_detection": {
        "regex": r"(?i)(nmap|nikto|sqlmap|dirbuster|gobuster|masscan)",
        "severity": "MEDIUM",
        "description": "Security scanner detected"
    },
    "login_success": {
        "regex": r"(?i)(accepted password|session opened|login successful)",
        "severity": "INFO",
        "description": "Successful login"
    },
    "firewall_block": {
        "regex": r"(?i)(dropped|blocked|denied|rejected).*from\s+(\d+\.\d+\.\d+\.\d+)",
        "severity": "LOW",
        "description": "Firewall blocked connection"
    },
    "suspicious_user_agent": {
        "regex": r"(?i)(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|python-requests|curl|wget)",
        "severity": "MEDIUM",
        "description": "Suspicious user agent detected"
    }
}

# ── LOG PATHS BY PLATFORM ──
LOG_PATHS = {
    "linux": {
        "auth": "/var/log/auth.log",
        "syslog": "/var/log/syslog",
        "secure": "/var/log/secure",
        "apache": "/var/log/apache2/access.log",
        "nginx": "/var/log/nginx/access.log",
        "ufw": "/var/log/ufw.log",
        "fail2ban": "/var/log/fail2ban.log"
    },
    "darwin": {
        "system": "/var/log/system.log",
        "auth": "/var/log/secure.log",
        "apache": "/var/log/apache2/access_log",
        "nginx": "/usr/local/var/log/nginx/access.log"
    },
    "windows": {
        "system": "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
        "security": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        "application": "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
        "iis": "C:\\inetpub\\logs\\LogFiles"
    }
}

class LogWatcher:
    def __init__(self, log_file=None, patterns=None, output=None, threshold=5, 
                 window=300, follow=True, tail_lines=50, stats_interval=60):
        self.log_file = log_file
        self.patterns = patterns or DEFAULT_PATTERNS
        self.output_file = output
        self.threshold = threshold  # alerts before triggering high-volume alert
        self.window = window  # time window in seconds
        self.follow = follow
        self.tail_lines = tail_lines
        self.stats_interval = stats_interval
        
        self.alerts = []
        self.alert_counts = defaultdict(lambda: deque(maxlen=1000))
        self.total_lines = 0
        self.matched_lines = 0
        self.start_time = time.time()
        self.running = True
        self.lock = threading.Lock()
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for name, config in self.patterns.items():
            try:
                self.compiled_patterns[name] = {
                    "regex": re.compile(config["regex"]),
                    "severity": config.get("severity", "INFO"),
                    "description": config.get("description", name)
                }
            except re.error as e:
                print(f"{Fore.YELLOW}[!] Invalid regex for pattern '{name}': {e}{Style.RESET_ALL}")
    
    def _get_log_path(self, preset=None):
        """Auto-detect log file based on platform and preset"""
        system = platform.system().lower()
        
        if self.log_file:
            return self.log_file
            
        if preset and system in LOG_PATHS:
            paths = LOG_PATHS[system]
            if preset in paths:
                path = paths[preset]
                if os.path.exists(path):
                    return path
                else:
                    # Try glob patterns
                    matches = glob.glob(path + "*")
                    if matches:
                        return matches[0]
        
        # Auto-detect common logs
        if system == "linux":
            for candidate in ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure"]:
                if os.path.exists(candidate):
                    return candidate
        elif system == "darwin":
            for candidate in ["/var/log/system.log", "/var/log/secure.log"]:
                if os.path.exists(candidate):
                    return candidate
        
        return None
    
    def _check_threshold(self, pattern_name, ip=None):
        """Check if alert threshold is exceeded"""
        now = time.time()
        key = f"{pattern_name}:{ip}" if ip else pattern_name
        
        with self.lock:
            self.alert_counts[key].append(now)
            # Remove old entries outside window
            while self.alert_counts[key] and self.alert_counts[key][0] < now - self.window:
                self.alert_counts[key].popleft()
            
            count = len(self.alert_counts[key])
            if count >= self.threshold:
                return count
        return 0
    
    def _process_line(self, line, source="unknown"):
        """Process a single log line against all patterns"""
        self.total_lines += 1
        line = line.strip()
        if not line:
            return
        
        for pattern_name, config in self.compiled_patterns.items():
            match = config["regex"].search(line)
            if match:
                self.matched_lines += 1
                
                # Extract IP if present
                ip = None
                if len(match.groups()) > 1:
                    ip = match.group(2)
                elif re.search(r'\d+\.\d+\.\d+\.\d+', line):
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    ip = ip_match.group()
                
                # Check threshold
                count = self._check_threshold(pattern_name, ip)
                
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "pattern": pattern_name,
                    "severity": config["severity"],
                    "description": config["description"],
                    "source": source,
                    "line": line[:200],  # truncate long lines
                    "ip": ip,
                    "match": match.group(0),
                    "count_in_window": count
                }
                
                with self.lock:
                    self.alerts.append(alert)
                
                # Print alert
                severity_color = {
                    "CRITICAL": Fore.MAGENTA,
                    "HIGH": Fore.RED,
                    "MEDIUM": Fore.YELLOW,
                    "LOW": Fore.GREEN,
                    "INFO": Fore.CYAN
                }.get(config["severity"], Fore.WHITE)
                
                print(f"\n{severity_color}[{config['severity']}] {config['description']}{Style.RESET_ALL}")
                print(f"    {Fore.CYAN}Pattern: {pattern_name}{Style.RESET_ALL}")
                if ip:
                    print(f"    {Fore.CYAN}IP: {ip}{Style.RESET_ALL}")
                if count >= self.threshold:
                    print(f"    {Fore.MAGENTA}THRESHOLD EXCEEDED: {count} occurrences in {self.window}s{Style.RESET_ALL}")
                print(f"    {Fore.WHITE}{line[:150]}{Style.RESET_ALL}")
                
                # Auto-save on critical/high alerts
                if config["severity"] in ["CRITICAL", "HIGH"]:
                    self._auto_save()
                
                break  # Only match first pattern per line
    
    def _tail_file(self, filepath):
        """Tail a file and follow new lines"""
        print(f"{Fore.CYAN}[*] Monitoring: {filepath}{Style.RESET_ALL}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to end if following, or read last N lines
                if self.follow:
                    f.seek(0, 2)  # Seek to end
                    if self.tail_lines > 0:
                        # Read last N lines first
                        f.seek(0, 0)
                        lines = deque(f, maxlen=self.tail_lines)
                        for line in lines:
                            self._process_line(line, filepath)
                        f.seek(0, 2)  # Back to end
                else:
                    lines = deque(f, maxlen=self.tail_lines)
                    for line in lines:
                        self._process_line(line, filepath)
                    return
                
                # Follow new lines
                while self.running:
                    line = f.readline()
                    if line:
                        self._process_line(line, filepath)
                    else:
                        time.sleep(0.1)
                        
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Log file not found: {filepath}{Style.RESET_ALL}")
        except PermissionError:
            print(f"{Fore.RED}[-] Permission denied: {filepath}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Try running with sudo/administrator privileges{Style.RESET_ALL}")
        except KeyboardInterrupt:
            self.running = False
    
    def _tail_command(self, command):
        """Follow output from a command (e.g., journalctl)"""
        print(f"{Fore.CYAN}[*] Executing: {command}{Style.RESET_ALL}")
        
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            for line in iter(process.stdout.readline, ''):
                if not self.running:
                    break
                self._process_line(line, f"cmd:{command}")
                
            process.terminate()
            
        except Exception as e:
            print(f"{Fore.RED}[-] Command failed: {e}{Style.RESET_ALL}")
    
    def _stats_reporter(self):
        """Background thread for periodic statistics"""
        while self.running:
            time.sleep(self.stats_interval)
            if not self.running:
                break
            
            elapsed = time.time() - self.start_time
            rate = self.total_lines / elapsed if elapsed > 0 else 0
            
            print(f"\n{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Statistics ({int(elapsed)}s){Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Lines processed: {self.total_lines}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Matches found: {self.matched_lines}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Rate: {rate:.1f} lines/sec{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Total alerts: {len(self.alerts)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}\n")
    
    def _auto_save(self):
        """Auto-save alerts to file"""
        if self.output_file:
            self._save_report(force=True)
    
    def _save_report(self, force=False):
        """Save alerts to output file"""
        if not self.output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"logwatcher_report_{timestamp}.json"
        
        report = {
            "tool": "Log-Watcher",
            "author": "Decryptious_ on Discord / Punchborn on IG",
            "timestamp": datetime.now().isoformat(),
            "platform": f"{platform.system()} {platform.release()}",
            "config": {
                "threshold": self.threshold,
                "window": self.window,
                "log_file": self.log_file
            },
            "statistics": {
                "total_lines": self.total_lines,
                "matched_lines": self.matched_lines,
                "total_alerts": len(self.alerts),
                "duration_seconds": round(time.time() - self.start_time, 2)
            },
            "alerts": self.alerts
        }
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        if force:
            print(f"{Fore.GREEN}[+] Auto-saved report: {self.output_file}{Style.RESET_ALL}")
    
    def watch(self, preset=None, command=None):
        """Start watching logs"""
        print(f"\n{Fore.CYAN}[*] Starting Log-Watcher{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threshold: {self.threshold} alerts per {self.window}s window{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Active patterns: {len(self.compiled_patterns)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        # Start stats reporter
        stats_thread = threading.Thread(target=self._stats_reporter, daemon=True)
        stats_thread.start()
        
        try:
            if command:
                self._tail_command(command)
            else:
                log_path = self._get_log_path(preset)
                if log_path:
                    self._tail_file(log_path)
                else:
                    print(f"{Fore.RED}[-] No log file found. Specify with -f or use --preset{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[!] Available presets: auth, syslog, apache, nginx, ufw, system{Style.RESET_ALL}")
                    
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopping Log-Watcher{Style.RESET_ALL}")
        finally:
            self.running = False
            self._save_report()
            self._print_summary()
    
    def _print_summary(self):
        """Print final summary"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Scan Summary':^60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Duration: {elapsed:.1f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Lines processed: {self.total_lines}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Matches found: {self.matched_lines}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Total alerts: {len(self.alerts)}{Style.RESET_ALL}")
        
        # Severity breakdown
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
        
        if severity_counts:
            print(f"\n{Fore.CYAN}  Alerts by severity:{Style.RESET_ALL}")
            for sev, count in sorted(severity_counts.items(), 
                                     key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x[0], 5)):
                color = {"CRITICAL": Fore.MAGENTA, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, 
                        "LOW": Fore.GREEN, "INFO": Fore.CYAN}.get(sev, Fore.WHITE)
                print(f"    {color}{sev}: {count}{Style.RESET_ALL}")
        
        # Top attacking IPs
        ip_counts = defaultdict(int)
        for alert in self.alerts:
            if alert.get('ip'):
                ip_counts[alert['ip']] += 1
        
        if ip_counts:
            print(f"\n{Fore.CYAN}  Top source IPs:{Style.RESET_ALL}")
            for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {Fore.YELLOW}{ip}: {count} alerts{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Report saved: {self.output_file}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")


def load_custom_patterns(filepath):
    """Load custom patterns from JSON file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to load patterns: {e}{Style.RESET_ALL}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Log-Watcher - Real-time log monitor and threat detector",
        epilog="Example: sudo python3 logwatcher.py -f /var/log/auth.log -t 10"
    )
    parser.add_argument("-f", "--file", help="Log file to monitor")
    parser.add_argument("-p", "--preset", choices=["auth", "syslog", "apache", "nginx", "ufw", "system"],
                       help="Use preset log path for your platform")
    parser.add_argument("-c", "--command", help="Command to pipe and monitor (e.g., 'journalctl -f')")
    parser.add_argument("--patterns", help="Custom patterns JSON file")
    parser.add_argument("-t", "--threshold", type=int, default=5, 
                       help="Alert threshold per time window (default: 5)")
    parser.add_argument("-w", "--window", type=int, default=300,
                       help="Time window in seconds (default: 300)")
    parser.add_argument("-n", "--tail", type=int, default=50,
                       help="Number of lines to tail on start (default: 50)")
    parser.add_argument("--no-follow", action="store_true", help="Don't follow, just process existing lines")
    parser.add_argument("--stats", type=int, default=60, help="Stats interval in seconds (default: 60)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all lines, not just matches")
    parser.add_argument("--no-banner", action="store_true", help="Hide startup banner")
    parser.add_argument("--list-patterns", action="store_true", help="List built-in patterns and exit")
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_title()
    
    if args.list_patterns:
        print(f"{Fore.CYAN}[*] Built-in Patterns:{Style.RESET_ALL}\n")
        for name, config in DEFAULT_PATTERNS.items():
            color = {"CRITICAL": Fore.MAGENTA, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, 
                    "LOW": Fore.GREEN, "INFO": Fore.CYAN}.get(config["severity"], Fore.WHITE)
            print(f"  {color}[{config['severity']}] {name}{Style.RESET_ALL}")
            print(f"    Description: {config['description']}")
            print(f"    Regex: {config['regex'][:60]}...")
            print()
        return
    
    # Load patterns
    patterns = DEFAULT_PATTERNS
    if args.patterns:
        custom = load_custom_patterns(args.patterns)
        if custom:
            patterns = custom
            print(f"{Fore.GREEN}[+] Loaded {len(patterns)} custom patterns{Style.RESET_ALL}")
    
    watcher = LogWatcher(
        log_file=args.file,
        patterns=patterns,
        output=args.output,
        threshold=args.threshold,
        window=args.window,
        follow=not args.no_follow,
        tail_lines=args.tail,
        stats_interval=args.stats
    )
    
    watcher.watch(preset=args.preset, command=args.command)


if __name__ == "__main__":
    main()