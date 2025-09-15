# Local Router + IDS Lab (Quickstart)

This doc explains how to run the Cisco-like router (FRR) + Suricata IDS locally to develop and test detections.

## What you get
- Segmented lab networks (LAN and DMZ) via FRR (Cisco-like behavior)
- Web server in the DMZ
- Honeypot (SSH) in the DMZ
- Workstation in the LAN to generate “normal” and “attack” traffic
- Suricata observing both sides and writing alerts to `eve.json`

## Start the local lab
```bash
cd infra
docker compose -f docker-compose.local.yml up -d

Useful containers (names may vary slightly)

Router: router-local

Workstation: ai-sec-monitor-local-workstation-1

Sensor (Suricata): sensor-local

Quick tests

1) Routing
docker exec -it ai-sec-monitor-local-workstation-1 sh -lc \
'ip route replace default via 10.77.0.254; ping -c1 10.77.10.10'

2) Watch Alerts
docker exec -it sensor-local sh -lc 'tail -f /var/log/suricata/eve.json'
# (or alerts only)
docker exec -it sensor-local sh -lc 'tail -f /var/log/suricata/eve.json | grep "\"event_type\":\"alert\""'

3) Trigger Alerts
# SSH attempt to honeypot (triggers local rule sid:1000001)
docker exec -it ai-sec-monitor-local-workstation-1 sh -lc 'apk add --no-cache openssh-client >/dev/null || true; ssh -o ConnectTimeout=2 10.77.10.30 || true'

# Loud Nmap scan to web (triggers ET SCAN and/or local threshold rule)
docker exec -it ai-sec-monitor-local-workstation-1 sh -lc 'apk add --no-cache nmap >/dev/null || true; nmap -sS -Pn -p 1-1000 --max-rate 800 10.77.10.10 || true'

Local files (not committed)

infra/docker-compose.local.yml

infra/sensor/suricata.local.yaml

infra/logs/**

These are for developer laptops only. See repo .gitignore.

What is committed

FRR router config: infra/router/*

Starter Suricata local rules: infra/sensor/rules/local.rules

This doc.

How to stop the lab:
cd infra
docker compose -f docker-compose.local.yml down

