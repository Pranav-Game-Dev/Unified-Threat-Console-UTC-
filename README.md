# Unified Threat Console (UTC)

Unified Threat Console (UTC) is a Mini Security Operations Center (SOC) platform that integrates multiple cybersecurity functionalities into a centralized system. It provides real-time network monitoring, threat detection, vulnerability scanning, and secure file handling through a unified web-based dashboard.

---

## Overview

Modern cybersecurity systems often rely on multiple independent tools, leading to fragmented monitoring and delayed response. UTC addresses this by combining essential security modules into a single, cohesive platform that offers visibility, control, and real-time insights.

---

## Key Features

### Network Traffic Monitoring

* Captures live network packets
* Extracts IP addresses, ports, and protocols
* Supports TCP, UDP, DNS, and ICMP
* Detects traffic anomalies and spikes

### Intrusion Detection System (IDS)

* Rule-based detection engine
* Detects:

  * Port scanning
  * Brute force attempts
  * DoS/DDoS patterns
  * Suspicious ports
* Uses time-window and stateful tracking
* Generates real-time alerts

### Web Vulnerability Scanner

* Scans web applications for:

  * SQL Injection
  * Cross-Site Scripting (XSS)
  * Missing security headers
  * Open redirect
  * Directory traversal
* Classifies findings:

  * Informational
  * Potential
  * Confirmed

### Log Monitoring & Alert System

* Collects logs from all modules
* Stores structured data
* Detects anomalies
* Displays logs in real-time

### Secure File Transfer

* AES-256 encryption
* Token-based access
* Optional password protection
* File expiry mechanism
* Ensures confidentiality and integrity

### Attack Simulator

* Simulates:

  * Port scanning
  * Traffic flooding
* Used for testing IDS detection
* Operates in controlled environment

### Centralized Dashboard

* Web-based SOC interface
* Displays:

  * Live traffic
  * Alerts
  * Logs
  * Scan results
* Real-time updates via WebSockets
* Light and dark mode support

---

## System Architecture

* Backend: Python (FastAPI)
* Frontend: HTML, CSS, JavaScript
* Database: SQLite
* Real-time Communication: WebSockets
* Security: AES-256 Encryption, Token Authentication

---

## Project Structure

```
Unified-Threat-Console/
├── backend/
│   ├── main.py
│   ├── network_monitor.py
│   ├── ids_engine.py
│   ├── vuln_scanner.py
│   ├── file_transfer.py
│   ├── logs.py
│   └── database.py
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── uploads/
├── logs/
├── config.py
└── run.py
```

---

## Installation

1. Clone the repository:

```
git clone https://github.com/your-username/unified-threat-console.git
cd unified-threat-console
```

2. Install dependencies:

```
pip install -r requirements.txt
```

3. Run the application:

```
python run.py
```

---

## Usage

* Start the server using the run script
* The web dashboard will open automatically in the browser
* Monitor live traffic and alerts
* Use scanner and file transfer modules via UI

---

## Workflow

1. Capture network traffic
2. Analyze using IDS engine
3. Generate logs and alerts
4. Store data in database
5. Display results on dashboard in real-time

---

## Advantages

* Centralized monitoring
* Real-time detection
* Improved visibility
* Modular design
* User-friendly interface

---

## License

This project is intended for educational and academic purposes.
