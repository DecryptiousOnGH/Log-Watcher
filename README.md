# Log-Watcher

**Author:** Decryptious_ on Discord / Punchborn on IG  
**License:** MIT  
**Platforms:** Linux, Windows, macOS

A cross-platform real-time log monitor with regex-based alerting for suspicious patterns. Designed for security analysts, system administrators, and blue team operations.

---

## Features

- **Real-Time Monitoring:** Tails log files live or processes command output
- **Pattern Matching:** 10 built-in detection patterns + custom JSON pattern support
- **Threshold Alerting:** Configurable rate limits to detect brute-force and scanning
- **Severity Levels:** CRITICAL, HIGH, MEDIUM, LOW, INFO classification
- **Auto-Save:** Automatically exports high-severity alerts to JSON
- **Statistics:** Periodic stats reporting with top attacking IPs
- **Cross-Platform:** Works with Linux auth logs, Windows Event logs, macOS system logs
- **Command Pipe:** Monitor `journalctl -f`, `tail -f`, or any streaming command

---

# Installation

**Method 1: Clone and Run**
git clone https://github.com/DecryptiousOnGH/Log-Watcher
cd Log-Watcher
pip install -r requirements.txt

**Method 2: Direct Download**
# Linux/macOS
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/Log-Watcher/main/logwatcher.py
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/Log-Watcher/main/requirements.txt
pip install -r requirements.txt

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/Log-Watcher/main/logwatcher.py" -OutFile "logwatcher.py"
pip install colorama

**Method 3: System Install**
pip install .
logwatcher --list-patterns

# Usage

**Monitor SSH Auth Logs (Linux)**
sudo python3 logwatcher.py -p auth -t 5

**Monitor Web Server Logs**
sudo python3 logwatcher.py -p apache -t 10

**Monitor Custom Log File**
python3 logwatcher.py -f /path/to/your.log

**Pipe from journalctl**
sudo journalctl -f -u ssh | python3 logwatcher.py -c "cat"

**Use Custom Patterns**
python3 logwatcher.py -f access.log --patterns my_patterns.json

**List Built-in Patterns**
python3 logwatcher.py --list-patterns

**Adjust Threshold and Window**
-Trigger after 10 matches within 60 seconds

python3 logwatcher.py -f auth.log -t 10 -w 60

# Options

Flag	           Description
-f, --file	       Log file path to monitor
-p, --preset	   Auto-detect log: auth, syslog, apache, nginx, ufw, system
-c, --command	   Pipe command output (e.g., journalctl -f)
--patterns	       Custom JSON patterns file
-t, --threshold	   Alert threshold per window (default: 5)
-w, --window	   Time window in seconds (default: 300)
-n, --tail	       Lines to read on startup (default: 50)
--no-follow	       Process existing lines only, don't tail
--stats	Stats      report interval in seconds (default: 60)
-o, --output	   Output JSON file
--list-patterns	   Show all built-in patterns and exit
--no-banner	Hide   startup banner

# Built-in Patterns

Pattern	              Severity	           Description
ssh_bruteforce	        HIGH	         SSH brute force attempt
privilege_escalation	CRITICAL	     Possible privilege escalation
web_sql_injection	    HIGH	         SQL injection in web logs
web_xss	MEDIUM	                         XSS attempt in web logs
web_path_traversal	    HIGH	         Path traversal attempt
malware_indicator	    CRITICAL	     Malware/webshell activity
scan_detection	        MEDIUM	         Security scanner detected
login_success	        INFO	         Successful login
firewall_block	        LOW	             Firewall blocked connection
suspicious_user_agent	MEDIUM	         Suspicious user agent

# Custom Patterns Format

Create a JSON file with your own patterns: 

{
    "my_custom_alert": {
        "regex": "(?i)error.*database",
        "severity": "HIGH",
        "description": "Database error detected"
    },
    "api_abuse": {
        "regex": "(?i)rate limit exceeded.*from\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)",
        "severity": "MEDIUM",
        "description": "API rate limit exceeded"
    }
}

**Run with:**
python3 logwatcher.py -f app.log --patterns custom.json


# Platform Notes

Platform	Preset	Log Path
Linux	     auth	/var/log/auth.log
Linux	    syslog	/var/log/syslog
Linux	    apache	/var/log/apache2/access.log
Linux	    nginx	/var/log/nginx/access.log
Linux	     ufw	/var/log/ufw.log
macOS	    system	/var/log/system.log
macOS	     auth	/var/log/secure.log

Windows: Use -f with full path to .evtx files or pipe wevtutil output.