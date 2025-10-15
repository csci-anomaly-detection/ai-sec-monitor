# AI-Sec-Monitor

AI-Sec-Monitor is an **AI-augmented security monitoring system** built for a simulated campus environment.  
Its purpose is to collect network and system logs, detect suspicious activity, and use AI-driven methods to summarize alerts and recommend responses.  
The system is designed for educational and research purposes in a controlled lab setting.


## Overview

The environment simulates a small campus network consisting of multiple zones, including LAN, DMZ, and campus network segments.  
Each zone runs containers representing typical infrastructure components such as web servers, routers, honeypots, sensors, and workstations.  
The **Suricata** intrusion detection system (IDS) monitors traffic across these networks, while a dedicated workstation generates controlled attack traffic to validate detection accuracy.


## Project Goals

- Simulate a multi-zone, campus-style network environment.  
- Deploy an intentionally vulnerable web application for realistic attack testing.  
- Detect attacks such as SQL injection, XSS, command injection, brute force, and directory traversal.  
- Collect and analyze IDS logs for visualization, alerting, and AI-based triage.  
- Validate detection through automated attack simulations.  
- Provide a foundation for AI-assisted anomaly detection and incident response.


## Current Features

### DVWA and Workstation Integration
- The **web server** uses the `vulnerables/web-dvwa:latest` image to host the Damn Vulnerable Web Application (DVWA).  
- The **workstation** runs on `ubuntu:latest` and executes automated attack simulations through `workstation/test_attacks.py`.  
- The attack script simulates multiple web-based threats:
  - SQL injection attempts  
  - Cross-Site Scripting (XSS) payloads  
  - Command injection  
  - Directory traversal  
  - Brute-force login attempts  
  - Malicious file uploads  
  - Port scanning  

### Suricata IDS Configuration
- The **sensor** runs `jasonish/suricata:latest` in IDS mode.  
- Captures traffic on all Docker bridge interfaces:
  - `infra_default`, `campus_net`, `dmz_net`, and `lan_net`.  
- Configuration file: `infra/sensor/suricata.local.yaml`  
- Detection rules: `infra/sensor/rules/local.rules`  
- Verified rule loading, packet capture, and alert generation.  
- Logs stored under `/var/log/suricata/` and exported for validation.

### Verification and Log Exports
- After attack simulations, Suricata logs (`fast.log` and `eve.json`) are exported to `logs/suricata/export/`.  
- These exports provide reproducible evidence of detection across multiple attack categories.  
- Runtime logs are excluded from version control through `.gitignore` to maintain a clean repository.


## Repository Structure
```
ai-sec-monitor/
├─ docs/                     # Documentation
├─ infra/                    # Docker and infrastructure configuration
│  ├─ docker-compose.routed.yml
│  ├─ sensor/
│  │  ├─ suricata.local.yaml
│  │  └─ rules/local.rules
│  └─ workstation/test_attacks.py
├─ logs/
│  └─ suricata/export/       # Verified Suricata alert logs (snapshots)
├─ ingest/                   # Log collection and schema mapping (future)
├─ detect/                   # Detection logic and rule integration
├─ ai/                       # AI-based triage and correlation (future)
├─ notify/                   # Alerting and notification components
├─ ui/                       # Dashboards and visualization
└─ scripts/                  # Utility scripts
```

## Verification Workflow

1. **Start the environment**
   
`docker compose -f infra/docker-compose.routed.yml up -d --build`

2.	Run the attack simulation

`docker exec -it workstation python3 /workstation/test_attacks.py`


3.	Check for Suricata alerts
```
docker exec -it sensor tail -n 100 /var/log/suricata/fast.log
docker exec -i sensor sh -lc 'jq -r "select(.event_type==\"alert\") | [.timestamp,.src_ip,.dest_ip,.alert.signature] | @tsv" /var/log/suricata/eve.json'
```

4.	Expected detections
	•	SQL Injection (UNION / OR 1=1)
	•	HTTP Brute Force Login Attempts
	•	XSS (Script Tag, IMG Tag, JavaScript Event)
	•	Command Injection
	•	Directory Traversal
	•	Web Shell Upload
	5.	Exported verification logs
```
logs/suricata/export/
├─ fast-<timestamp>.log
└─ eve-<timestamp>.json
```


## Development Workflow

Branch Protection Rules
	•	main is protected and must remain stable.
	•	All changes go through pull requests and require review before merging.

Creating and Merging Changes
```
git checkout main
git pull
git checkout -b feat/<description>
git add .
git commit -m "feat: description of changes"
git push -u origin feat/<description>
```
- Open a pull request on GitHub
- Set base to main and compare your feature branch
- Request a review before merging

Branch Naming Convention
```
feat/...   →  new features
fix/...    →  bug fixes
chore/...  →  maintenance or cleanup
```



## Quickstart

Prerequisites
	•	Docker Engine or Docker Desktop (WSL2 backend for Windows)
	•	docker compose plugin

Setup
```
git clone git@github.com:csci-anomaly-detection/ai-sec-monitor.git
cd ai-sec-monitor
docker compose -f infra/docker-compose.routed.yml up -d --build
```
Access Services

- DVWA Web App: http://localhost:8080
- Grafana (planned): http://localhost:3000
- OpenSearch Dashboards (planned): http://localhost:5601



## License

Apache 2.0 — see LICENSE


## Notes
- This project operates entirely in a controlled lab environment.
- Do not connect it to external or production systems.
- Attack simulations are self-contained and intended for testing detection capabilities only.
- Future work will include AI-based alert summarization and correlation for automated triage.

