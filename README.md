# Unified - Python Security Monitoring Tool

## Overview

Unified is a real-time security monitoring tool written in Python that provides:

- Process monitoring with CPU usage alerts
- Log file analysis with rule-based detection
- Vulnerability scanning
- Network port monitoring
- Plugin system for extended functionality

## Features

### Core Monitoring
- **Process Monitoring**: Track running processes with CPU usage alerts (>85%)
- **Log Analysis**: Monitor system logs with customizable detection rules
- **Vulnerability Scanning**: Detect security issues like:
  - Outdated packages
  - Weak file permissions
  - Open network ports
  - Unnecessary services
- **Port Monitoring**: Show all listening ports and associated services

### Alerting System
- Real-time alerts for suspicious activities
- Brute force attack detection
- High CPU usage notifications
- Custom rule matching in log files

### Plugin System
- **Threat Hunting**: Memory scanning, persistence checking
- **Red Team Simulation**: Attack simulation tools
- **Anomaly Detection**: Baseline system behavior monitoring
- **Auto-Remediation**: Automatic response to threats
- **Threat Intelligence**: IOC matching
- **CVE/LOLBAS**: Vulnerability checking
- **Gamification**: Security training with scoring

## Installation

1. **Requirements**:
   - Python 3.6+
   - Linux system (tested on Ubuntu/Debian)

2. **Install dependencies**:
   ```bash
   pip install click psutil pyyaml requests watchdog
   ```
