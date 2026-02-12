import os
import time
import click
import psutil
import threading
import yaml
import subprocess
import json
import requests
import random
import statistics
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta

# Global variables
alerts = []
processes = []
logs = []
vulnerabilities = []
command_output = ""  # To store the output of CLI commands

# Path to the rules configuration file
RULES_FILE = "log_rules.yaml"

# Path to the vulnerabilities storage file
VULNERABILITIES_FILE = "vulnerabilities.json"

# Vulnerability thresholds
VULNERABILITY_THRESHOLDS = {
    # Number of failed login attempts to trigger brute force alert
    "brute_force_attempts": 5,
    "file_permissions": 0o600,  # Expected file permissions for sensitive files
    "password_min_length": 8,  # Minimum password length
}

# LOLBAS API endpoint
LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"

# Plugin-related variables
PLUGINS_DIR = "plugins"
plugin_handlers = {}

# Threat Hunter Plugin Variables
simulation_artifacts = []

# Anomaly Detection Plugin Variables
baseline_metrics = {}
anomalies_detected = []

# Auto-Remediation Plugin Variables
remediation_actions = []

# Threat Intel Plugin Variables
threat_intel_matches = []

# CVE/LOLBAS Plugin Variables
cve_alerts = []

# Gamification Plugin Variables

# Known vulnerable ports
VULNERABLE_PORTS = {
    '21': 'FTP (often insecure)',
    '22': 'SSH (brute force target)',
    '23': 'Telnet (unencrypted)',
    '137': 'NetBIOS (often targeted)',
    '139': 'NetBIOS (often targeted)',
    '445': 'SMB (often attacked)',
    '3389': 'RDP (often targeted)'
}

# Load vulnerabilities from file


def load_vulnerabilities():
    """Load previously captured vulnerabilities from the JSON file."""
    if os.path.exists(VULNERABILITIES_FILE):
        with open(VULNERABILITIES_FILE, "r") as f:
            return json.load(f)
    else:
        return []

# Save vulnerabilities to file


def save_vulnerabilities():
    """Save captured vulnerabilities to the JSON file."""
    with open(VULNERABILITIES_FILE, "w") as f:
        json.dump(vulnerabilities, f, indent=4)

# Detect package manager


def detect_package_manager():
    """Detect the package manager used by the system."""
    if os.path.exists("/usr/bin/apt"):
        return "apt"
    elif os.path.exists("/usr/bin/yum"):
        return "yum"
    elif os.path.exists("/usr/bin/dnf"):
        return "dnf"
    elif os.path.exists("/usr/bin/pacman"):
        return "pacman"
    elif os.path.exists("/usr/bin/zypper"):
        return "zypper"
    else:
        return None

# Load log file rules from YAML configuration


def load_rules():
    """Load log file rules from the YAML configuration file."""
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            return yaml.safe_load(f)
    else:
        # Default rules if the file doesn't exist
        return {
            "rules": [
                {"pattern": "ERROR", "description": "Error detected"},
                {"pattern": "Failed", "description": "Failure detected"},
                {"pattern": "Unauthorized",
                    "description": "Unauthorized access detected"},
                {"pattern": "Critical", "description": "Critical issue detected"},
                {"pattern": "segmentation fault",
                    "description": "Segmentation fault detected"},
                {"pattern": "permission denied", "description": "Permission denied"},
                {"pattern": "Failed password",
                    "description": "Failed login attempt detected"},
                {"pattern": "authentication failure",
                    "description": "Authentication failure detected"},
            ]
        }

# Log File Handler


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file):
        self.log_file = log_file
        self.last_position = 0
        self.rules = load_rules()["rules"]
        self.failed_login_attempts = {}  # Track failed login attempts by IP

    def on_modified(self, event):
        if event.src_path == self.log_file:
            with open(self.log_file, "r") as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                for line in new_lines:
                    self.process_log_line(line)

    def process_log_line(self, line):
        """Process a single log line and check against rules."""
        line = line.strip()
        logs.append({"message": line, "timestamp": time.ctime()})

        # Extract key-value pairs from the log line
        log_data = {}
        for part in line.split():
            if "=" in part:
                key, value = part.split("=", 1)
                log_data[key] = value.strip('"')

        # Build a clean log message dynamically
        event_type = log_data.get("type", "UNKNOWN")
        user = log_data.get("UID", log_data.get("auid", "UNKNOWN_USER"))
        command = log_data.get("cmd", "")
        details = log_data.get("acct", log_data.get("msg", ""))

        # Decode hex-encoded command (if applicable)
        if command.startswith("707974686F6E"):  # Hex for "python"
            try:
                command = bytes.fromhex(command).decode("utf-8")
            except ValueError:
                pass  # Keep the original command if decoding fails

        # Handle wpa_supplicant logs
        if "wpa_supplicant[" in line:
            event_type = "wpa_supplicant"
            details = line.split("CTRL-EVENT-SIGNAL-CHANGE ")[1].strip()

        # Build the clean log message
        log_msg = f"[{event_type}]"
        if user and user != "UNKNOWN_USER":
            log_msg += f" {user}"
        if command:
            log_msg += f" executed: {command}"
        if details:
            log_msg += f" {details}"
        log_msg += f" ({time.ctime()})"

        # Add the log to the logs list
        logs.append({"message": log_msg, "timestamp": time.ctime()})

        # Check the log line against all rules
        for rule in self.rules:
            if rule["pattern"] in line:
                alert_msg = f"Suspicious log entry in {os.path.basename(self.log_file)}: {
                    rule['description']} - {log_msg}"
                alerts.append(
                    {"message": alert_msg, "timestamp": time.ctime()})
                print(f"[ALERT]: {alert_msg}")

                # Detect brute force attempts
                if rule["pattern"] == "Failed password":
                    self.detect_brute_force(line)

    def detect_brute_force(self, line):
        """Detect brute force attempts by tracking failed login attempts."""
        # Extract the IP address from the log line
        if "from" in line:
            ip = line.split("from ")[1].split(" ")[0]
            if ip in self.failed_login_attempts:
                self.failed_login_attempts[ip] += 1
            else:
                self.failed_login_attempts[ip] = 1

            # Alert if there are too many failed attempts from the same IP
            if self.failed_login_attempts[ip] > VULNERABILITY_THRESHOLDS["brute_force_attempts"]:
                alert_msg = f"Brute force attempt detected from {
                    ip} ({self.failed_login_attempts[ip]} failed attempts)"
                alerts.append(
                    {"message": alert_msg, "timestamp": time.ctime()})
                print(f"[ALERT]: {alert_msg}")

# Process Monitoring


def monitor_processes():
    """Monitor all running processes and alert if CPU usage exceeds 85%."""
    while True:
        processes.clear()
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
            try:
                process_info = {
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "username": proc.info['username'],
                    "cpu_percent": proc.info['cpu_percent']
                }
                processes.append(process_info)

                # Alert if CPU usage exceeds 85%
                if proc.info['cpu_percent'] > 85:
                    alert_msg = f"High CPU usage by {proc.info['name']} (PID: {proc.info['pid']}, CPU: {
                        proc.info['cpu_percent']}%)"
                    alerts.append(
                        {"message": alert_msg, "timestamp": time.ctime()})
                    print(f"[ALERT]: {alert_msg}")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        time.sleep(5)  # Refresh process list every 5 seconds

# Get open ports information


def get_open_ports():
    """Get a list of open ports and listening services."""
    try:
        # Using 'ss' command for socket statistics (more reliable than netstat)
        result = subprocess.check_output(
            ['ss', '-tulnp'],
            stderr=subprocess.DEVNULL,
            text=True
        )
        # Parse the output
        ports = []
        for line in result.splitlines()[1:]:  # Skip header line
            parts = line.split()
            if len(parts) >= 6:
                proto = parts[0]
                state = parts[1]
                local_addr_port = parts[4]
                process = ' '.join(parts[5:]) if len(parts) > 5 else 'unknown'

                # Extract port number
                if ':' in local_addr_port:
                    port = local_addr_port.split(':')[-1]
                else:
                    port = local_addr_port

                # Check if port is vulnerable
                vulnerability = VULNERABLE_PORTS.get(port, '')

                ports.append({
                    'protocol': proto,
                    'port': port,
                    'state': state,
                    'process': process,
                    'vulnerability': vulnerability,
                    'timestamp': time.ctime()
                })
        return ports
    except subprocess.CalledProcessError:
        return []

# Get service version


def get_service_version(service_name):
    """Get the version of a specific service."""
    try:
        if service_name == "ssh":
            output = subprocess.check_output(
                ["ssh", "-V"], stderr=subprocess.STDOUT, text=True)
            return output.split()[0].split("_")[1]
        elif service_name == "apache":
            output = subprocess.check_output(
                ["apache2", "-v"], stderr=subprocess.STDOUT, text=True)
            return output.splitlines()[0].split("/")[1].split(" ")[0]
        elif service_name == "nginx":
            output = subprocess.check_output(
                ["nginx", "-v"], stderr=subprocess.STDOUT, text=True)
            return output.split("/")[1].split(" ")[0]
        elif service_name == "ftp":
            output = subprocess.check_output(
                ["vsftpd", "-v"], stderr=subprocess.STDOUT, text=True)
            return output.splitlines()[0].split(" ")[1]
        # Add more services as needed
    except subprocess.CalledProcessError:
        return None

# Fetch CVE data


def get_cve_data(service_name, version):
    """Fetch CVE data for a specific service and version."""
    url = f"https://cve.circl.lu/api/search/{service_name}/{version}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Get SetUID binaries


def get_setuid_binaries():
    """Find all SetUID binaries on the system."""
    try:
        output = subprocess.check_output(
            ["find", "/", "-perm", "-4000", "-type", "f"], stderr=subprocess.DEVNULL, text=True)
        return output.splitlines()
    except subprocess.CalledProcessError:
        return []

# Fetch LOLBAS data


def fetch_lolbas_data():
    """Fetch the LOLBAS data from the API."""
    try:
        response = requests.get(LOLBAS_API_URL)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch LOLBAS data: {e}")
        return []

# Check SetUID binaries vulnerabilities


def check_setuid_vulnerabilities():
    """Check SetUID binaries against LOLBAS data."""
    lolbas_data = fetch_lolbas_data()
    if not lolbas_data:
        return []

    setuid_binaries = get_setuid_binaries()
    vulnerabilities = []

    for binary in setuid_binaries:
        binary_name = os.path.basename(binary)
        for entry in lolbas_data:
            if entry["Name"].lower() == binary_name.lower():
                vulnerabilities.append({
                    "type": "setuid_binary",
                    "details": f"SetUID binary {binary} is flagged by LOLBAS: {entry['Description']}",
                    "binary": binary,
                    "lolbas_info": entry
                })
                break

    return vulnerabilities

# Vulnerability Identification


def identify_vulnerabilities():
    """Identify vulnerabilities in the system."""
    package_manager = detect_package_manager()
    while True:
        vulnerabilities.clear()

        # Check for outdated packages
        if package_manager == "apt":
            try:
                outdated_packages = subprocess.check_output(
                    ["apt", "list", "--upgradable"], text=True).splitlines()
                if len(outdated_packages) > 1:  # First line is a header
                    for package in outdated_packages[1:]:
                        vulnerabilities.append(
                            {"type": "outdated_package", "details": package.strip()})
            except subprocess.CalledProcessError:
                pass
        elif package_manager == "yum":
            try:
                outdated_packages = subprocess.check_output(
                    ["yum", "list", "updates"], text=True).splitlines()
                if len(outdated_packages) > 1:  # First line is a header
                    for package in outdated_packages[1:]:
                        vulnerabilities.append(
                            {"type": "outdated_package", "details": package.strip()})
            except subprocess.CalledProcessError:
                pass
        elif package_manager == "dnf":
            try:
                outdated_packages = subprocess.check_output(
                    ["dnf", "list", "updates"], text=True).splitlines()
                if len(outdated_packages) > 1:  # First line is a header
                    for package in outdated_packages[1:]:
                        vulnerabilities.append(
                            {"type": "outdated_package", "details": package.strip()})
            except subprocess.CalledProcessError:
                pass
        elif package_manager == "pacman":
            try:
                outdated_packages = subprocess.check_output(
                    ["pacman", "-Qu"], text=True).splitlines()
                if outdated_packages:
                    for package in outdated_packages:
                        vulnerabilities.append(
                            {"type": "outdated_package", "details": package.strip()})
            except subprocess.CalledProcessError:
                pass
        elif package_manager == "zypper":
            try:
                outdated_packages = subprocess.check_output(
                    ["zypper", "list-updates"], text=True).splitlines()
                if len(outdated_packages) > 1:  # First line is a header
                    for package in outdated_packages[1:]:
                        vulnerabilities.append(
                            {"type": "outdated_package", "details": package.strip()})
            except subprocess.CalledProcessError:
                pass

        # Check for open ports using `ss -tlnp`
        try:
            open_ports = subprocess.check_output(
                ["ss", "-tlnp"], text=True).splitlines()
            for port in open_ports[1:]:  # Skip header line
                vulnerabilities.append(
                    {"type": "open_port", "details": port.strip()})
        except subprocess.CalledProcessError:
            pass

        # Check for weak file permissions
        sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
        for file in sensitive_files:
            if os.path.exists(file):
                mode = os.stat(file).st_mode
                if mode & 0o777 != VULNERABILITY_THRESHOLDS["file_permissions"]:
                    vulnerabilities.append({"type": "weak_permission", "details": f"{
                                           file} has weak permissions: {oct(mode)}"})

        # Check for world-writable files
        try:
            world_writable_files = subprocess.check_output(
                ["find", "/", "-perm", "-o+w", "-type", "f"], text=True).splitlines()
            for file in world_writable_files:
                vulnerabilities.append(
                    {"type": "world_writable_file", "details": file.strip()})
        except subprocess.CalledProcessError:
            pass

        # Check for SUID/SGID files
        try:
            suid_sgid_files = subprocess.check_output(
                ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000", "-type", "f"], text=True).splitlines()
            for file in suid_sgid_files:
                vulnerabilities.append(
                    {"type": "suid_sgid_file", "details": file.strip()})
        except subprocess.CalledProcessError:
            pass

        # Check for unattended upgrades
        if package_manager == "apt":
            try:
                unattended_upgrades = subprocess.check_output(
                    ["dpkg-query", "-l", "unattended-upgrades"], text=True)
                if "unattended-upgrades" not in unattended_upgrades:
                    vulnerabilities.append(
                        {"type": "unattended_upgrades", "details": "Automatic security updates are not enabled"})
            except subprocess.CalledProcessError:
                pass

        # Check for root login via SSH
        try:
            sshd_config = subprocess.check_output(
                ["grep", "^PermitRootLogin", "/etc/ssh/sshd_config"], text=True)
            if "PermitRootLogin yes" in sshd_config:
                vulnerabilities.append(
                    {"type": "root_login_ssh", "details": "Root login via SSH is enabled"})
        except subprocess.CalledProcessError:
            pass

        # Check for weak password policies
        try:
            password_policies = subprocess.check_output(
                ["grep", "^PASS", "/etc/login.defs"], text=True)
            if f"PASS_MIN_LEN {VULNERABILITY_THRESHOLDS['password_min_length']}" not in password_policies:
                vulnerabilities.append({"type": "weak_password_policy", "details": f"Password minimum length is less than {
                                       VULNERABILITY_THRESHOLDS['password_min_length']}"})
        except subprocess.CalledProcessError:
            pass

        # Check for unnecessary services
        unnecessary_services = ["telnet", "rsh", "rlogin", "rexec", "ypbind"]
        for service in unnecessary_services:
            try:
                status = subprocess.check_output(
                    ["systemctl", "is-active", service], text=True).strip()
                if status == "active":
                    vulnerabilities.append(
                        {"type": "unnecessary_service", "details": f"Unnecessary service {service} is running"})
            except subprocess.CalledProcessError:
                pass

        # Check for missing security patches using lynis
        try:
            lynis_report = subprocess.check_output(
                ["lynis", "audit", "system", "--quick"], text=True)
            if "Warnings" in lynis_report or "Suggestions" in lynis_report:
                vulnerabilities.append(
                    {"type": "lynis_scan", "details": "Lynis scan detected warnings or suggestions"})
        except subprocess.CalledProcessError:
            pass

        # Check for rootkits using rkhunter
        try:
            rkhunter_report = subprocess.check_output(
                ["rkhunter", "--check", "--sk"], text=True)
            if "Warning:" in rkhunter_report:
                vulnerabilities.append(
                    {"type": "rkhunter_scan", "details": "rkhunter scan detected warnings"})
        except subprocess.CalledProcessError:
            pass

        # Check for SetUID binaries vulnerabilities
        setuid_vulnerabilities = check_setuid_vulnerabilities()
        vulnerabilities.extend(setuid_vulnerabilities)

        # Save vulnerabilities to file
        save_vulnerabilities()

        time.sleep(5)  # Check for vulnerabilities every 60 seconds

# Log File Monitoring


def monitor_logs():
    """Monitor common log files for changes."""
    observers = []
    for log_file in get_log_files():  # Use dynamic log file detection
        event_handler = LogFileHandler(log_file)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(
            log_file), recursive=False)
        observer.start()
        observers.append(observer)
        print(f"[Watching log file]: {log_file}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()

# CLI Dashboard


def generate_dashboard():
    """Generate a real-time CLI dashboard."""
    while True:
        os.system("clear")  # Clear the screen for a clean dashboard
        print("\n=== Real-Time Monitoring Dashboard ===")

        # Alerts
        print("\n--- Alerts ---")
        for idx, alert in enumerate(alerts[-30:], start=1):
            print(f"{idx}. {alert['message']} ({alert['timestamp']})")

        # Processes
        print("\n--- Processes ---")
        for proc in processes[-30:]:  # Show the last 20 processes
            print(f"{proc['name']} (PID: {
                  proc['pid']}, User: {proc['username']})")

        # Logs
        print("\n--- Logs ---")
        for log in logs[-30:]:  # Show the last 10 log entries
            print(f"{log['timestamp']}: {log['message']}")

        # Vulnerabilities
        print("\n--- Vulnerabilities ---")
        for idx, vuln in enumerate(vulnerabilities[-30:], start=1):
            print(f"{idx}. {vuln['type']}: {vuln['details']}")

        # Ports (New Section)
        print("\n--- Open Ports ---")
        ports = get_open_ports()
        for port in ports[-15:]:  # Show last 15 open ports
            port_str = f"{port['protocol']} {port['port']} {
                port['state']} - {port['process']}"
            if port['vulnerability']:
                # Red color for vulnerable ports
                port_str += f" \033[91m(Vulnerable: {
                    port['vulnerability']})\033[0m"
            print(port_str)

        # Plugins status
        print("\n--- Plugins ---")
        for plugin, info in plugin_handlers.items():
            print(f"{plugin.upper()}: {info['description']}")

        # Command Output
        if command_output:
            print("\n--- Command Output ---")
            print(command_output)

        time.sleep(10)  # Refresh dashboard every 10 seconds

# ====================== PLUGIN FUNCTIONS ======================

# Threat Hunter Plugin


def threat_hunt_command(command):
    if command == 'scan_memory':
        return scan_memory()
    elif command == 'check_persistence':
        return check_persistence()
    elif command == 'hunt_artifacts':
        return hunt_artifacts()
    return "Unknown threat hunting command"


def scan_memory():
    try:
        result = subprocess.check_output(['ps', 'aux'], text=True)
        suspicious = []
        for line in result.splitlines():
            if any(keyword in line.lower() for keyword in ['meterpreter', 'beacon', 'cobalt', 'payload']):
                suspicious.append(line)
        return "\n".join(suspicious) if suspicious else "No suspicious memory patterns found"
    except Exception as e:
        return f"Error scanning memory: {str(e)}"


def check_persistence():
    checks = [
        ('crontab', ['crontab', '-l']),
        ('systemd', ['ls', '-la', '/etc/systemd/system/']),
        ('bashrc', ['grep', '-i', 'malicious',
         '/home/*/.bashrc', '/root/.bashrc']),
        ('profile', ['grep', '-i', 'malicious',
         '/home/*/.profile', '/root/.profile'])
    ]

    results = []
    for name, cmd in checks:
        try:
            output = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True)
            if output.strip():
                results.append(f"{name}:\n{output}")
        except:
            continue

    return "\n\n".join(results) if results else "No obvious persistence mechanisms found"


def hunt_artifacts():
    artifacts = [
        ('/tmp/', 'Common temp directory'),
        ('/dev/shm/', 'Shared memory directory'),
        ('/var/tmp/', 'Persistent temp directory')
    ]

    results = []
    for path, desc in artifacts:
        try:
            files = subprocess.check_output(['ls', '-la', path], text=True)
            results.append(f"{desc} ({path}):\n{files}")
        except:
            continue

    return "\n\n".join(results) if results else "No suspicious artifacts found in common locations"

# Red Team Simulator Plugin


def red_team_command(command):
    if command == 'simulate_attack':
        return simulate_attack()
    elif command == 'clear_artifacts':
        return clear_artifacts()
    elif command == 'list_artifacts':
        return list_artifacts()
    return "Unknown red team command"


def simulate_attack():
    scenarios = [
        ("Creating fake suspicious process", "nohup sleep 3600 &"),
        ("Adding cron job",
         "(crontab -l 2>/dev/null; echo '* * * * * /bin/echo hello') | crontab -"),
        ("Creating world-writable file",
         "touch /tmp/.malicious && chmod 777 /tmp/.malicious"),
        ("Adding test user", "useradd -M -s /bin/false testattacker"),
        ("Creating SSH key", "ssh-keygen -f /tmp/id_rsa -N ''")
    ]

    results = []
    for desc, cmd in random.sample(scenarios, 3):
        try:
            subprocess.run(cmd, shell=True, check=True)
            results.append(f"Simulated: {desc}")
            simulation_artifacts.append((desc, datetime.now()))
        except Exception as e:
            results.append(f"Failed to simulate {desc}: {str(e)}")

    return "\n".join(results)


def clear_artifacts():
    cleanup_commands = [
        "pkill -f 'sleep 3600'",
        "crontab -r",
        "rm -f /tmp/.malicious",
        "userdel testattacker",
        "rm -f /tmp/id_rsa*"
    ]

    results = []
    for cmd in cleanup_commands:
        try:
            subprocess.run(cmd, shell=True)
            results.append(f"Cleaned: {cmd.split()[0]}")
        except:
            continue

    simulation_artifacts.clear()
    return "\n".join(results) if results else "No artifacts to clean"


def list_artifacts():
    if not simulation_artifacts:
        return "No active simulation artifacts"
    return "\n".join(f"{desc} at {time}" for desc, time in simulation_artifacts)

# Anomaly Detection Plugin


def anomaly_command(command):
    if command == 'establish_baseline':
        return establish_baseline()
    elif command == 'detect_anomalies':
        return detect_anomalies()
    elif command == 'list_anomalies':
        return list_anomalies()
    return "Unknown anomaly command"


def establish_baseline():
    global baseline_metrics

    # Get process count baseline
    process_count = len(psutil.process_iter())

    # Get CPU baseline
    cpu_percent = psutil.cpu_percent(interval=1)

    # Get memory baseline
    memory_percent = psutil.virtual_memory().percent

    baseline_metrics = {
        'process_count': {
            'mean': process_count,
            'stddev': process_count * 0.1,  # Assume 10% variation is normal
            'last_updated': datetime.now()
        },
        'cpu_percent': {
            'mean': cpu_percent,
            'stddev': cpu_percent * 0.15,  # Assume 15% variation is normal
            'last_updated': datetime.now()
        },
        'memory_percent': {
            'mean': memory_percent,
            'stddev': memory_percent * 0.1,  # Assume 10% variation is normal
            'last_updated': datetime.now()
        }
    }

    return "Baseline metrics established:\n" + "\n".join(
        f"{k}: {v['mean']} ± {v['stddev']}"
        for k, v in baseline_metrics.items()
    )


def detect_anomalies():
    if not baseline_metrics:
        return "Baseline not established. Run 'establish_baseline' first."

    anomalies = []

    # Check process count
    current_process_count = len(psutil.process_iter())
    baseline = baseline_metrics['process_count']
    if abs(current_process_count - baseline['mean']) > 2 * baseline['stddev']:
        anomaly = f"Process count anomaly: {
            current_process_count} (expected {baseline['mean']} ± {baseline['stddev']})"
        anomalies.append(anomaly)
        anomalies_detected.append((datetime.now(), anomaly))

    # Check CPU
    current_cpu = psutil.cpu_percent(interval=1)
    baseline = baseline_metrics['cpu_percent']
    if abs(current_cpu - baseline['mean']) > 2 * baseline['stddev']:
        anomaly = f"CPU usage anomaly: {current_cpu}% (expected {baseline['mean']} ± {
            baseline['stddev']}%)"
        anomalies.append(anomaly)
        anomalies_detected.append((datetime.now(), anomaly))

    # Check memory
    current_memory = psutil.virtual_memory().percent
    baseline = baseline_metrics['memory_percent']
    if abs(current_memory - baseline['mean']) > 2 * baseline['stddev']:
        anomaly = f"Memory usage anomaly: {
            current_memory}% (expected {baseline['mean']} ± {baseline['stddev']}%)"
        anomalies.append(anomaly)
        anomalies_detected.append((datetime.now(), anomaly))

    return "\n".join(anomalies) if anomalies else "No anomalies detected"


def list_anomalies():
    if not anomalies_detected:
        return "No anomalies detected"
    return "\n".join(f"{time}: {anomaly}" for time, anomaly in anomalies_detected[-10:])

# Auto-Remediation Plugin


def remediate_command(command):
    if command == 'kill_high_cpu':
        return kill_high_cpu()
    elif command == 'block_brute_force':
        return block_brute_force()
    elif command == 'fix_permissions':
        return fix_permissions()
    elif command == 'list_actions':
        return list_actions()
    return "Unknown remediation command"


def kill_high_cpu(threshold=90):
    killed = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if proc.info['cpu_percent'] > threshold:
                psutil.Process(proc.info['pid']).kill()
                action = f"Killed {proc.info['name']} (PID: {proc.info['pid']}) using {
                    proc.info['cpu_percent']}% CPU"
                killed.append(action)
                remediation_actions.append((datetime.now(), action))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return "\n".join(killed) if killed else f"No processes using >{threshold}% CPU"


def block_brute_force(threshold=5):
    # This would depend on your LogFileHandler implementation
    # Here's a simple version that just looks at auth logs
    try:
        output = subprocess.check_output(
            ['grep', 'Failed password', '/var/log/auth.log'], text=True)
        ip_counts = {}
        for line in output.splitlines():
            if 'from' in line:
                ip = line.split('from ')[1].split()[0]
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        blocked = []
        for ip, count in ip_counts.items():
            if count >= threshold:
                try:
                    subprocess.run(['iptables', '-A', 'INPUT',
                                   '-s', ip, '-j', 'DROP'], check=True)
                    action = f"Blocked {ip} ({count} failed attempts)"
                    blocked.append(action)
                    remediation_actions.append((datetime.now(), action))
                except subprocess.CalledProcessError:
                    continue
        return "\n".join(blocked) if blocked else f"No IPs with >={threshold} failed attempts"
    except subprocess.CalledProcessError:
        return "Could not check auth logs"


def fix_permissions():
    sensitive_files = [
        ('/etc/passwd', 0o644),
        ('/etc/shadow', 0o600),
        ('/etc/sudoers', 0o440)
    ]

    fixed = []
    for file, mode in sensitive_files:
        try:
            current_mode = os.stat(file).st_mode & 0o777
            if current_mode != mode:
                os.chmod(file, mode)
                action = f"Fixed {file} permissions from {
                    oct(current_mode)} to {oct(mode)}"
                fixed.append(action)
                remediation_actions.append((datetime.now(), action))
        except Exception as e:
            continue

    return "\n".join(fixed) if fixed else "No permission issues found"


def list_actions():
    if not remediation_actions:
        return "No remediation actions taken"
    return "\n".join(f"{time}: {action}" for time, action in remediation_actions[-10:])

# Threat Intel Plugin


def threat_intel_command(command):
    if command == 'check_iocs':
        return check_iocs()
    elif command == 'list_matches':
        return list_matches()
    return "Unknown threat intel command"


def check_iocs():
    # Sample threat feeds (in a real implementation, these would be configurable)
    threat_feeds = {
        'malicious_ips': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'malicious_domains': 'https://mirror1.malwaredomains.com/files/domains.txt',
        'malware_hashes': 'https://virusshare.com/hashfiles/VirusShare_00000.md5'
    }

    # Get local indicators to check
    local_ips = set()
    local_domains = set()

    # Check active connections
    for conn in psutil.net_connections():
        if conn.raddr:
            ip = conn.raddr.ip
            try:
                ipaddress.ip_address(ip)  # Validate it's a real IP
                local_ips.add(ip)
            except ValueError:
                local_domains.add(ip)

    # Check threat feeds
    matches = []

    # Check IPs
    try:
        response = requests.get(threat_feeds['malicious_ips'], timeout=10)
        malicious_ips = set(response.text.splitlines())
        for ip in local_ips:
            if ip in malicious_ips:
                match = f"Malicious IP connected: {ip}"
                matches.append(match)
                threat_intel_matches.append((datetime.now(), match))
    except requests.RequestException:
        pass

    # Check domains (simplified)
    try:
        response = requests.get(threat_feeds['malicious_domains'], timeout=10)
        malicious_domains = set(line.split(
            '\t')[1] for line in response.text.splitlines() if not line.startswith('#'))
        for domain in local_domains:
            if any(mal_domain in domain for mal_domain in malicious_domains):
                match = f"Malicious domain contacted: {domain}"
                matches.append(match)
                threat_intel_matches.append((datetime.now(), match))
    except requests.RequestException:
        pass

    return "\n".join(matches) if matches else "No threat intel matches found"


def list_matches():
    if not threat_intel_matches:
        return "No threat intel matches"
    return "\n".join(f"{time}: {match}" for time, match in threat_intel_matches[-10:])

# CVE/LOLBAS Plugin


def cve_command(command):
    if command == 'check_cves':
        return check_cves()
    elif command == 'check_lolbas':
        return check_lolbas()
    elif command == 'list_alerts':
        return list_alerts()
    return "Unknown CVE command"


def check_cves(min_cvss=7.0):
    # Get installed packages (Debian/Ubuntu example)
    try:
        packages = subprocess.check_output(
            ['dpkg-query', '-W'], text=True).splitlines()
        package_versions = {}
        for line in packages:
            parts = line.split()
            if len(parts) >= 2:
                package_versions[parts[0]] = parts[1]

        # Check each package for CVEs (simplified - in reality use a proper CVE DB)
        alerts = []
        for package, version in package_versions.items():
            try:
                response = requests.get(
                    f"https://cve.circl.lu/api/search/{package}", timeout=5)
                if response.status_code == 200:
                    for cve in response.json():
                        if float(cve.get('cvss', 0)) >= min_cvss:
                            alert = f"Critical CVE {cve['id']} (CVSS: {cve['cvss']}) in {
                                package}-{version}: {cve['summary']}"
                            alerts.append(alert)
                            cve_alerts.append((datetime.now(), alert))
            except requests.RequestException:
                continue

        return "\n".join(alerts) if alerts else f"No CVEs with CVSS >= {min_cvss} found"
    except subprocess.CalledProcessError:
        return "Could not get installed packages"


def check_lolbas():
    # Get LOLBAS data
    try:
        response = requests.get(
            "https://lolbas-project.github.io/api/lolbas.json", timeout=10)
        lolbas_binaries = {
            item['Name'].lower(): item for item in response.json()}

        # Check system binaries
        try:
            system_binaries = subprocess.check_output(
                ['ls', '/usr/bin'], text=True).splitlines()
            matches = []
            for binary in system_binaries:
                binary_lower = binary.lower()
                if binary_lower in lolbas_binaries:
                    alert = f"LOLBAS binary: {
                        binary} - {lolbas_binaries[binary_lower]['Description']}"
                    matches.append(alert)
                    cve_alerts.append((datetime.now(), alert))
            return "\n".join(matches) if matches else "No LOLBAS binaries found"
        except subprocess.CalledProcessError:
            return "Could not list system binaries"
    except requests.RequestException:
        return "Could not fetch LOLBAS data"


def list_alerts():
    if not cve_alerts:
        return "No CVE/LOLBAS alerts"
    return "\n".join(f"{time}: {alert}" for time, alert in cve_alerts[-10:])

# Initialize all plugins


def initialize_plugins():
    """Initialize all plugin handlers."""
    # Threat Hunter
    plugin_handlers['threat_hunt'] = {
        'description': 'Perform threat hunting activities',
        'commands': {
            'scan_memory': 'Scan memory for suspicious patterns',
            'check_persistence': 'Check for persistence mechanisms',
            'hunt_artifacts': 'Hunt for common attack artifacts'
        },
        'function': threat_hunt_command
    }

    # Red Team Simulator
    plugin_handlers['red_team'] = {
        'description': 'Red team simulation tools',
        'commands': {
            'simulate_attack': 'Simulate various attack scenarios',
            'clear_artifacts': 'Clear simulation artifacts',
            'list_artifacts': 'List created simulation artifacts'
        },
        'function': red_team_command
    }

    # Anomaly Detection
    plugin_handlers['anomaly'] = {
        'description': 'Anomaly detection tools',
        'commands': {
            'establish_baseline': 'Establish baseline metrics (run during normal operation)',
            'detect_anomalies': 'Detect deviations from baseline',
            'list_anomalies': 'List detected anomalies'
        },
        'function': anomaly_command
    }

    # Auto-Remediation
    plugin_handlers['remediate'] = {
        'description': 'Auto-remediation tools',
        'commands': {
            'kill_high_cpu': 'Kill processes using high CPU',
            'block_brute_force': 'Block IPs with too many failed logins',
            'fix_permissions': 'Fix weak file permissions',
            'list_actions': 'List recent remediation actions'
        },
        'function': remediate_command
    }

    # Threat Intel
    plugin_handlers['threat_intel'] = {
        'description': 'Threat intelligence tools',
        'commands': {
            'check_iocs': 'Check for known IOCs (IPs, domains, hashes)',
            'list_matches': 'List threat intel matches'
        },
        'function': threat_intel_command
    }

    # CVE/LOLBAS
    plugin_handlers['cve'] = {
        'description': 'Enhanced CVE/LOLBAS alerting',
        'commands': {
            'check_cves': 'Check for critical CVEs in installed packages',
            'check_lolbas': 'Check for LOLBAS binaries',
            'list_alerts': 'List CVE/LOLBAS alerts'
        },
        'function': cve_command
    }


# Get common log files


def get_log_files():
    """Get a list of common log files to monitor."""
    common_logs = [
        '/var/log/syslog',
        '/var/log/auth.log',
        '/var/log/kern.log',
        '/var/log/dmesg',
        '/var/log/secure',  # For RHEL/CentOS
        '/var/log/messages'  # For RHEL/CentOS
    ]
    return [log for log in common_logs if os.path.exists(log)]

# CLI Commands


@click.group()
def cli():
    """A real-time monitoring tool for processes, logs, and vulnerabilities."""
    pass


@cli.command()
def start():
    """Start the real-time monitoring dashboard."""
    # Load previously captured vulnerabilities
    global vulnerabilities
    vulnerabilities = load_vulnerabilities()

    # Initialize plugins
    initialize_plugins()

    # Start process monitoring in a separate thread
    process_thread = threading.Thread(target=monitor_processes, daemon=True)
    process_thread.start()

    # Start log file monitoring in a separate thread
    log_thread = threading.Thread(target=monitor_logs, daemon=True)
    log_thread.start()

    # Start vulnerability identification in a separate thread
    vuln_thread = threading.Thread(
        target=identify_vulnerabilities, daemon=True)
    vuln_thread.start()

    # Start the real-time dashboard
    generate_dashboard()


@cli.command()
def show_alerts():
    """Show all triggered alerts."""
    global command_output
    command_output = "\n=== Alerts ===\n"
    for idx, alert in enumerate(alerts, start=1):
        command_output += f"{idx}. {alert['message']} ({alert['timestamp']})\n"


@cli.command()
def show_processes():
    """Show all running processes."""
    global command_output
    command_output = "\n=== Processes ===\n"
    for proc in processes:
        command_output += f"{proc['name']
                             } (PID: {proc['pid']}, User: {proc['username']})\n"


@cli.command()
def show_logs():
    """Show the last 10 log entries."""
    global command_output
    command_output = "\n=== Logs ===\n"
    for log in logs[-30:]:
        command_output += f"{log['timestamp']}: {log['message']}\n"


@cli.command()
def show_vulnerabilities():
    """Show the last 10 vulnerabilities."""
    global command_output
    vulnerabilities = load_vulnerabilities()
    command_output = "\n=== Vulnerabilities ===\n"
    for idx, vuln in enumerate(vulnerabilities[-10:], start=1):
        command_output += f"{idx}. {vuln['type']}: {vuln['details']}\n"


@cli.command()
def show_service_versions():
    """Show versions of important services."""
    global command_output
    services_to_check = ["ssh", "apache", "nginx", "ftp"]
    command_output = "\n=== Service Versions ===\n"
    for service in services_to_check:
        version = get_service_version(service)
        if version:
            command_output += f"{service}: {version}\n"
        else:
            command_output += f"{service}: Not found or unable to determine version\n"


@cli.command()
def show_cves():
    """Show CVEs for important services."""
    global command_output
    services_to_check = ["ssh", "apache", "nginx", "ftp"]
    command_output = "\n=== CVEs ===\n"
    for service in services_to_check:
        version = get_service_version(service)
        if version:
            cve_data = get_cve_data(service, version)
            if cve_data:
                for cve in cve_data:
                    command_output += f"{service} {version}: {
                        cve['id']} - {cve['summary']}\n"
            else:
                command_output += f"{service} {version}: No CVEs found\n"
        else:
            command_output += f"{service}: Not found or unable to determine version\n"


@cli.command()
def show_ports():
    """Show currently open ports."""
    global command_output
    ports = get_open_ports()
    command_output = "\n=== Open Ports ===\n"
    for port in ports:
        port_str = f"{port['protocol']} {port['port']} {
            port['state']} - {port['process']}"
        if port['vulnerability']:
            port_str += f" \033[91m(Vulnerable: {
                port['vulnerability']})\033[0m"
        command_output += port_str + "\n"


@cli.command()
def show_plugins():
    """List all available plugins and their commands."""
    global command_output
    command_output = "\n=== Available Plugins ===\n"
    for plugin, info in plugin_handlers.items():
        command_output += f"\n{plugin.upper()}: {info['description']}\n"
        for cmd, desc in info['commands'].items():
            command_output += f"  {cmd}: {desc}\n"


@cli.command()
@click.argument('plugin')
@click.argument('command')
def run_plugin(plugin, command):
    """Run a plugin command."""
    global command_output
    if plugin in plugin_handlers:
        handler = plugin_handlers[plugin]['function']
        command_output = handler(command)
    else:
        command_output = f"Unknown plugin: {plugin}"


# Main Function
if __name__ == "__main__":
    # Create plugins directory if it doesn't exist
    if not os.path.exists(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR)
        print(f"Created plugins directory at {PLUGINS_DIR}")

    # Load vulnerabilities
    vulnerabilities = load_vulnerabilities()

    cli()
