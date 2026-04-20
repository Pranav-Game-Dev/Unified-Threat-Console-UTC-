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

* Backend: Python (FastAPI), Npcap (Windows)
* Frontend: HTML, CSS, JavaScript
* Database: SQLite
* Real-time Communication: WebSockets
* Security: AES-256 Encryption, Token Authentication

---

## Project Structure

```
Unified Threat Console (UTC)
├── app
│   ├── modules
│   │   ├── file_transfer.py
│   │   ├── ids_engine.py
│   │   ├── log_monitor.py
│   │   ├── network_monitor.py
│   │   └── vuln_scanner.py
│   ├── routers
│   │   ├── files.py
│   │   ├── logs.py
│   │   ├── network.py
│   │   ├── scanner.py
│   │   └── threats.py
│   ├── config.py
│   ├── database.py
│   ├── main.py
│   └── ws_manager.py
├── config
│   └── settings.json
├── dashboard
│   ├── app.js
│   ├── index.html
│   └── style.css
├── README.md
├── requirements.txt
└── run.py
```

---

## Screenshots
<img width="1919" height="1079" alt="Overview" src="https://github.com/user-attachments/assets/0e7901be-9640-488d-9bf8-b027492b5f5c" /> 
<p align="center">Overview Page</p>

<img width="1918" height="1079" alt="Network" src="https://github.com/user-attachments/assets/bf2885aa-487d-407e-abc7-e5569455d884" />
<p align="center">Network Monitor page</p>

<img width="1912" height="1071" alt="Threats" src="https://github.com/user-attachments/assets/36c9f5c7-8f18-4ec4-830a-f780855f5310" />
<p align="center">Threat Detection page</p>

<img width="1919" height="1079" alt="Vulnerability Scanner" src="https://github.com/user-attachments/assets/7f22e206-0c2e-4b77-a054-de527a720067" />
<p align="center">Vulnerability Scanner page</p>

<img width="1919" height="1079" alt="Logs" src="https://github.com/user-attachments/assets/00754bca-7bff-4a30-ba3b-6416252d5b1a" />
<p align="center">Logs and Alerts page</p>

<img width="1919" height="1079" alt="attack simulator" src="https://github.com/user-attachments/assets/a4252733-a290-4559-8bb3-ca3c59e82b55" />
<p align="center">Attack Simulator page</p>

---

## Installation

1. Clone the repository:

```
git clone https://github.com/your-username/unified-threat-console.git
cd unified-threat-console
```

2. Install dependencies:

Install Npcap (Windows) — required for live packet capture : 
https://npcap.com/#download
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
