# AI-Sec-Monitor Launch Guide 🚀

Quick reference guide to launch the complete AI Security Monitor pipeline.

---

## Prerequisites

### Required Software
```bash
# Docker Desktop
# Download: https://www.docker.com/products/docker-desktop/

# Python 3.12+
python3 --version

# Ollama (for AI validation)
brew install ollama  # macOS
# Or: https://ollama.ai/
```

### Install Dependencies
```bash
cd /path/to/ai-sec-monitor
pip install -r requirements.txt

# For AI agent
cd ai-agent
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r ../requirements.txt
```

---

## Quick Start (5 Steps)

### Step 1: Start Infrastructure
```bash
# Start Docker network + IDS
docker compose -f infra/docker-compose.routed.yml up -d --build

# Wait for services (30 seconds)
sleep 30

# Verify containers are running
docker ps
```

**Expected containers:**
- `router` - Network routing (FRR)
- `dvwa` - Vulnerable web app
- `dvwa-db` - MySQL database
- `honeypot` - Cowrie SSH honeypot
- `workstation` - Attack simulator
- `sensor` - Suricata IDS

### Step 2: Generate Attack Traffic
```bash
# Run one-time attack simulation
docker exec -it workstation python3 /workstation/test_attacks.py

# OR run continuous traffic generation
python scripts/continuous_log_generator.py  # Press Ctrl+C to stop
```

### Step 3: Start Loki (Log Storage)

**Option A: Local Loki Setup**

Create `docker-compose.loki.yml`:
```yaml
version: "3.8"
services:
  loki:
    image: grafana/loki:2.9.0
    container_name: loki
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - loki-data:/loki
    restart: unless-stopped

  promtail:
    image: grafana/promtail:2.9.0
    container_name: promtail
    volumes:
      - ./logs/suricata:/var/log/suricata:ro
      - ./ingest/promtail/config.yml:/etc/promtail/config.yml:ro
    command: -config.file=/etc/promtail/config.yml
    depends_on:
      - loki

volumes:
  loki-data:
```

```bash
# Start Loki stack
docker compose -f docker-compose.loki.yml up -d

# Verify
curl http://localhost:3100/ready  # Should return: ready
```

**Option B: Use Remote Loki**

Create `.env` file:
```bash
echo "LOKI_URL=http://your-loki-server:3100" > .env
```

### Step 4: Start Detection API
```bash
# In a new terminal
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Verify in another terminal
curl http://localhost:8000/health
```

**API Endpoints:**
- `http://localhost:8000` - API info
- `http://localhost:8000/alerts/live?hours_back=1` - Get threats
- `http://localhost:8000/health` - Health check
- `http://localhost:8000/docs` - Interactive API docs

### Step 5: Query Alerts & Run AI Validation
```bash
# Fetch threat data
curl -s "http://localhost:8000/alerts/live?hours_back=24" | jq '.' > api_response.json

# Start Ollama (new terminal)
ollama serve

# Pull LLM model (new terminal)
ollama pull llama3.1:8b

# Run AI validation
cd ai-agent
source venv/bin/activate
python scripts/run_api_response.py

# View results
cat validation_results.json | jq '.summary'
```

---

## Verification Checklist

```bash
# ✅ Docker containers running
docker ps | grep -E "router|dvwa|sensor|honeypot|workstation"

# ✅ Suricata generating alerts
docker exec -it sensor tail -n 20 /var/log/suricata/fast.log

# ✅ Loki accessible
curl http://localhost:3100/ready

# ✅ API responding
curl http://localhost:8000/health

# ✅ Ollama running
curl http://localhost:11434/api/tags

# ✅ Threat data exists
cat api_response.json | jq '.alerts.threat_count'
```

---

## Common Commands

### View Logs
```bash
# Suricata alerts
docker exec -it sensor tail -f /var/log/suricata/eve.json

# API logs
# (visible in terminal where uvicorn is running)

# Docker logs
docker logs dvwa
docker logs sensor
```

### Save Alerts
```bash
# Get last 24 hours with nice formatting
curl -s "http://localhost:8000/alerts/live?hours_back=24" | jq '.' > alerts_$(date +%Y%m%d_%H%M%S).json

# Extract just high severity threats
cat api_response.json | jq '.alerts.correlated_threats[] | select(.severity == "HIGH" or .severity == "CRITICAL")' > high_threats.json

# Get summary
cat api_response.json | jq '{threats: .alerts.threat_count, high_severity: .alerts.high_severity_threats, logs_analyzed: .logs_analyzed}'
```

### Stop Everything
```bash
# Stop infrastructure
docker compose -f infra/docker-compose.routed.yml down

# Stop Loki
docker compose -f docker-compose.loki.yml down

# Stop API (Ctrl+C in terminal)

# Stop Ollama (Ctrl+C in terminal)
```

---

## Troubleshooting

### Docker ARM64 Issues (Mac M1/M2/M3)

**Problem:** `mysql:5.7` doesn't support ARM64

**Solution:** Edit `infra/docker-compose.routed.yml`:
```yaml
db:
  image: mysql:8.0  # Changed from 5.7
  platform: linux/amd64
  command: --default-authentication-plugin=mysql_native_password
```

### No Alerts Generated

```bash
# Check Suricata is running
docker logs sensor

# Manually trigger attacks
docker exec -it workstation python3 /workstation/test_attacks.py

# Check if Suricata sees traffic
docker exec -it sensor suricata --build-info
```

### API Cannot Connect to Loki

```bash
# Test Loki connectivity
curl http://localhost:3100/ready

# If using remote Loki, check .env
cat .env

# Update Loki URL
echo "LOKI_URL=http://localhost:3100" > .env
```

### LLM Validation Fails

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Verify model installed
ollama list

# Re-pull model
ollama pull llama3.1:8b
```

---

## Optional: Email Notifications

### Configure Email
```bash
cd ai-agent
cp .env.example .env
nano .env
```

Add your SMTP settings:
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your-app-password
RECIPIENT_EMAIL=security-team@company.com
```

### Run Pipeline with Email
```bash
cd ai-agent
source venv/bin/activate
python core/main.py
```

Sends email alerts for **CRITICAL** severity threats only.

---

## Advanced: Real-Time Monitoring

```bash
# Run continuous sliding window processing
python detect/realtime_processor.py

# This will:
# - Fetch logs every minute
# - Analyze in 5-minute windows
# - Print threats as detected
# - Continue until Ctrl+C
```

---

## Project Architecture

```
Infrastructure (Docker) → Suricata IDS → Loki Storage
                                              ↓
                                        Detection API
                                              ↓
                                Rule Engine + ML Models
                                              ↓
                                    Threat Correlation
                                              ↓
                                    AI Validation Layer
                                              ↓
                                Email Notifications (Optional)
```

---

## Quick Test (No Full Setup)

If you just want to test AI validation without the full infrastructure:

```bash
# Use existing sample data
cd ai-agent
source venv/bin/activate

# Start Ollama
ollama serve &
ollama pull llama3.1:8b

# Run validation on existing data
python scripts/run_api_response.py

# View results
cat validation_results.json | jq '.summary'
```

---

## Resources

- **API Documentation**: http://localhost:8000/docs
- **Main README**: `README.md`
- **Architecture Details**: `docs/architecture.md`
- **Threat Model**: `docs/threat-model.md`

---

## Support

For issues or questions:
1. Check logs: `docker logs <container_name>`
2. Verify services: `docker ps` and `curl` health endpoints
3. Review troubleshooting section above
4. Check project README and documentation

---

**Last Updated:** 2025-11-05

