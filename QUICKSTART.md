# Quick Start Guide ⚡

**Get AI-Sec-Monitor running in 5 minutes**

---

## Prerequisites
```bash
# Install: Docker, Python 3.12+, Ollama
brew install ollama  # macOS
pip install -r requirements.txt
```

---

## Launch Commands

```bash
# 1. Start Infrastructure (30 sec wait)
docker compose -f infra/docker-compose.routed.yml up -d --build && sleep 30

# 2. Generate Attack Traffic
docker exec -it workstation python3 /workstation/test_attacks.py

# 3. Start Loki (if local - Terminal 1)
docker compose -f docker-compose.loki.yml up -d

# 4. Start API (Terminal 2)
cd api && uvicorn main:app --host 0.0.0.0 --port 8000

# 5. Start Ollama (Terminal 3)
ollama serve

# 6. Pull LLM Model (Terminal 4)
ollama pull llama3.1:8b

# 7. Get Alerts (Terminal 4)
curl -s "http://localhost:8000/alerts/live?hours_back=24" | jq '.' > api_response.json

# 8. Run AI Validation
cd ai-agent && source venv/bin/activate && python scripts/run_api_response.py

# 9. View Results
cat validation_results.json | jq '.summary'
```

---

## Verify Everything Works

```bash
docker ps                                      # ✅ 6 containers running
curl http://localhost:3100/ready               # ✅ ready
curl http://localhost:8000/health              # ✅ healthy
curl http://localhost:11434/api/tags           # ✅ Ollama responding
cat api_response.json | jq '.alerts.threat_count'  # ✅ Threats detected
```

---

## Stop Everything

```bash
docker compose -f infra/docker-compose.routed.yml down
docker compose -f docker-compose.loki.yml down
# Ctrl+C in API and Ollama terminals
```

---

**For detailed instructions, see [LAUNCH_GUIDE.md](LAUNCH_GUIDE.md)**

