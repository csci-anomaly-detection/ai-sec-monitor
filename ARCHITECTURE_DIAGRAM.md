# AI-Sec-Monitor Architecture Diagram

Visual representation of the complete system architecture.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SIMULATED NETWORK (Docker)                        │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │    DVWA     │  │  Honeypot   │  │   Router    │  │ Workstation │   │
│  │  (Web App)  │  │  (Cowrie)   │  │    (FRR)    │  │  (Attacks)  │   │
│  │  :8080      │  │  SSH:2222   │  │  10.77.0.x  │  │  10.77.0.20 │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                 │                 │                 │          │
│         └─────────────────┴─────────────────┴─────────────────┘          │
│                                   │                                      │
│                                   ▼                                      │
│                         ┌──────────────────┐                            │
│                         │  Suricata IDS    │                            │
│                         │  (Host Mode)     │                            │
│                         │  Monitors All    │                            │
│                         └─────────┬────────┘                            │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │
                                    ▼ (eve.json logs)
┌─────────────────────────────────────────────────────────────────────────┐
│                           LOG INGESTION                                  │
│                                                                          │
│  ┌─────────────┐           ┌──────────────────────┐                    │
│  │  Promtail   │  ───────▶ │   Grafana Loki      │                    │
│  │  (Scraper)  │           │   (Log Storage)     │                    │
│  │             │           │   :3100             │                    │
│  └─────────────┘           └──────────┬───────────┘                    │
└────────────────────────────────────────┼────────────────────────────────┘
                                         │
                                         ▼ (HTTP API Queries)
┌─────────────────────────────────────────────────────────────────────────┐
│                          DETECTION ENGINE                                │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    FastAPI Server (:8000)                          │  │
│  │  /alerts/live | /health | /rules | /stats | /docs                │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                         │
│  ┌─────────────────────────────┴─────────────────────────────────────┐  │
│  │                      Data Source Layer                             │  │
│  │  ┌──────────────────────────────────────────────────────────────┐ │  │
│  │  │  LokiDataSource                                               │ │  │
│  │  │  - Query logs via HTTP API                                   │ │  │
│  │  │  - Parse JSON/alert formats                                  │ │  │
│  │  │  - Convert timestamps to UTC                                 │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                         │
│  ┌─────────────────────────────┴─────────────────────────────────────┐  │
│  │              RULE-BASED DETECTION (rules.yaml)                     │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐              │  │
│  │  │ Count Rules │  │ Group Rules │  │ Anomaly Rules│              │  │
│  │  │ threshold:10│  │ group_by:ip │  │ ML-powered   │              │  │
│  │  │ window: 5m  │  │ window: 5m  │  │ Iso. Forest  │              │  │
│  │  └─────────────┘  └─────────────┘  └──────────────┘              │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                         │
│  ┌─────────────────────────────┴─────────────────────────────────────┐  │
│  │           MACHINE LEARNING ANOMALY DETECTION                       │  │
│  │  ┌────────────────────────────────────────────────────────────┐   │  │
│  │  │  Feature Engineering                                        │   │  │
│  │  │  • Volume: requests_per_min, total_requests                │   │  │
│  │  │  • Timing: business_hours, weekend, night_time             │   │  │
│  │  │  • Traffic: unique_ips, port_diversity, IP entropy         │   │  │
│  │  │  • Behavior: alert_diversity, avg_priority                 │   │  │
│  │  │  • Statistical: request_intervals, duration_stddev         │   │  │
│  │  └────────────────────────────────────────────────────────────┘   │  │
│  │  ┌────────────────────────────────────────────────────────────┐   │  │
│  │  │  Isolation Forest Models                                    │   │  │
│  │  │  • traffic_anomaly: Network patterns                       │   │  │
│  │  │  • behavioral_anomaly: Alert behaviors                     │   │  │
│  │  │  • volume_anomaly: Request volumes                         │   │  │
│  │  │  Training: Historical "normal" data (48h window)           │   │  │
│  │  │  Persistence: trained_models.pkl                           │   │  │
│  │  └────────────────────────────────────────────────────────────┘   │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                         │
│  ┌─────────────────────────────┴─────────────────────────────────────┐  │
│  │                  THREAT CORRELATION                                │  │
│  │  ┌──────────────────────────────────────────────────────────────┐ │  │
│  │  │  ThreatCorrelator                                             │ │  │
│  │  │  1. Group alerts by IP address                               │ │  │
│  │  │  2. Calculate confidence score:                              │ │  │
│  │  │     - Rules: +0.2 per rule (max 0.6)                        │ │  │
│  │  │     - ML: +anomaly_score (max 0.4)                          │ │  │
│  │  │     - Volume: +0.1 if >100 events                           │ │  │
│  │  │  3. Determine severity: LOW/MEDIUM/HIGH/CRITICAL            │ │  │
│  │  │  4. Classify attack type                                     │ │  │
│  │  │  5. Generate recommendations                                 │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
└────────────────────────────────┼────────────────────────────────────────┘
                                 │
                                 ▼ (JSON Response)
┌─────────────────────────────────────────────────────────────────────────┐
│                      AI VALIDATION LAYER                                 │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │              PHASE 1: Feature Analyzer (Heuristic)                 │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Timing Analysis                                             │  │  │
│  │  │  • Business hours ratio (9 AM - 5 PM)                       │  │  │
│  │  │  • Weekend vs weekday patterns                              │  │  │
│  │  │  • Timestamp distribution                                   │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  IP Reputation Analysis                                      │  │  │
│  │  │  • Internal vs external (RFC1918)                           │  │  │
│  │  │  • Source/destination IP counts                             │  │  │
│  │  │  • External-to-internal traffic                             │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Traffic Pattern Analysis                                    │  │  │
│  │  │  • Event volume and rate                                    │  │  │
│  │  │  • Rule violation counts                                    │  │  │
│  │  │  • Burst activity detection                                 │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Output: Classification + Confidence                         │  │  │
│  │  │  • TRUE_POSITIVE: High confidence threat                    │  │  │
│  │  │  • FALSE_POSITIVE: Likely benign                            │  │  │
│  │  │  • NEEDS_REVIEW: Uncertain → Send to LLM                    │  │  │
│  │  │  Confidence Score: 0.0 - 1.0                                │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────┬───────────────────────────────────┘  │
│                                  │                                       │
│                                  ▼ (if NEEDS_REVIEW)                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │              PHASE 2: LLM Validator (Semantic)                     │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Ollama Integration (Llama 3.1:8b)                           │  │  │
│  │  │  - Structured prompt with threat context                     │  │  │
│  │  │  - Feature analysis results                                  │  │  │
│  │  │  - Heuristic flags                                           │  │  │
│  │  │  - Timeout: 10 seconds                                       │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  LLM Response (Structured JSON)                              │  │  │
│  │  │  {                                                           │  │  │
│  │  │    "decision": "PROCEED_TO_ANALYSIS" | "REJECT",            │  │  │
│  │  │    "confidence": 0.0-1.0,                                   │  │  │
│  │  │    "reasoning": "Detailed explanation...",                  │  │  │
│  │  │    "proceed_to_analysis": true/false                        │  │  │
│  │  │  }                                                           │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Fallback Mechanism                                          │  │  │
│  │  │  If LLM fails: Use FeatureAnalyzer classification           │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────┬───────────────────────────────────┘  │
└────────────────────────────────┼─────────────────────────────────────┘
                                 │
                                 ▼ (validation_results.json)
┌─────────────────────────────────────────────────────────────────────────┐
│                      NOTIFICATION LAYER                                  │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Email Agent (CRITICAL threats only)                              │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  HTML Email Template                                         │  │  │
│  │  │  • Color-coded severity badges                              │  │  │
│  │  │  • Threat details table                                     │  │  │
│  │  │  • AI analysis summary                                      │  │  │
│  │  │  • Recommended actions                                      │  │  │
│  │  │  Plain text fallback for compatibility                      │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  SMTP Configuration (.env)                                   │  │  │
│  │  │  • smtp.gmail.com:587 (or custom)                           │  │  │
│  │  │  • TLS encryption                                           │  │  │
│  │  │  • App password authentication                              │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

```
┌─────────────┐
│   Attack    │
│   Traffic   │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  Suricata IDS   │ ──▶ eve.json logs
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│   Promtail      │ ──▶ Scrapes logs every 10s
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│   Loki          │ ──▶ Stores time-series logs
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│   API Query     │ ──▶ GET /alerts/live?hours_back=24
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Rule Runner    │ ──▶ Applies detection rules
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  ML Anomaly     │ ──▶ Isolation Forest models
│  Detection      │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Threat         │ ──▶ Groups by IP, calculates
│  Correlator     │     confidence & severity
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  API Response   │ ──▶ api_response.json
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Feature        │ ──▶ Heuristic analysis
│  Analyzer       │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  LLM Validator  │ ──▶ Semantic reasoning (Ollama)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Validation     │ ──▶ validation_results.json
│  Results        │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Email Alert    │ ──▶ CRITICAL threats only
│  (Optional)     │
└─────────────────┘
```

---

## Component Interactions

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TIMELINE VIEW                                │
│                                                                      │
│  T=0s     Attack launched from workstation                          │
│           └─▶ HTTP requests to DVWA                                 │
│           └─▶ SSH attempts to honeypot                              │
│                                                                      │
│  T=0-1s   Suricata captures packets                                 │
│           └─▶ Applies detection rules                               │
│           └─▶ Generates alerts in eve.json                          │
│                                                                      │
│  T=10s    Promtail scrapes new logs                                 │
│           └─▶ Sends to Loki via HTTP                                │
│                                                                      │
│  T=60s    API receives query request                                │
│           └─▶ Queries Loki for last N hours                         │
│           └─▶ Applies rule engine (50-200ms)                        │
│           └─▶ Runs ML models (100-500ms)                            │
│           └─▶ Correlates threats by IP (10-50ms)                    │
│           └─▶ Returns JSON response (total: 1-3s)                   │
│                                                                      │
│  T=61s    FeatureAnalyzer processes threats                         │
│           └─▶ Timing analysis (10ms)                                │
│           └─▶ IP reputation (5ms)                                   │
│           └─▶ Traffic patterns (15ms)                               │
│           └─▶ Classification (5ms)                                  │
│                                                                      │
│  T=62s    LLMValidator (if needed)                                  │
│           └─▶ Build prompt (10ms)                                   │
│           └─▶ Ollama inference (500-2000ms)                         │
│           └─▶ Parse response (5ms)                                  │
│                                                                      │
│  T=64s    Save validation results                                   │
│           └─▶ Write validation_results.json                         │
│                                                                      │
│  T=65s    Send email (if CRITICAL)                                  │
│           └─▶ Format HTML email (50ms)                              │
│           └─▶ SMTP send (500-2000ms)                                │
│                                                                      │
│  TOTAL: ~65 seconds from attack to notification                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Network Topology

```
                    ┌─────────────────────────┐
                    │   Host Machine (Mac)    │
                    │   Docker Desktop        │
                    └────────────┬────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
    ┌───────────┴─────┐  ┌──────┴───────┐  ┌────┴──────────┐
    │  LAN Network    │  │ DMZ Network  │  │  Host Mode    │
    │  10.77.0.0/24   │  │10.77.10.0/24 │  │  Sensor       │
    └───────┬─────────┘  └──────┬───────┘  └───────────────┘
            │                   │
    ┌───────┴────────┐  ┌──────┴────────┐
    │  Workstation   │  │   DVWA        │
    │  10.77.0.20    │  │   10.77.10.10 │
    └────────────────┘  │   Honeypot    │
                        │   10.77.10.30 │
                        └───────────────┘
```

---

## Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER               TECHNOLOGY          PURPOSE             │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure      Docker Compose      Container orchestr. │
│                      FRR (FRRouting)     Network routing     │
│                      Suricata            IDS detection       │
│                                                              │
│  Ingestion           Grafana Loki        Log storage        │
│                      Promtail            Log scraping       │
│                                                              │
│  Detection           Python 3.12         Core language      │
│                      scikit-learn        ML models          │
│                      pandas, numpy       Data processing    │
│                      PyYAML              Rule configuration │
│                                                              │
│  API                 FastAPI             REST framework     │
│                      Uvicorn             ASGI server        │
│                      httpx               HTTP client        │
│                                                              │
│  AI Validation       Ollama              LLM inference      │
│                      Llama 3.1 (8B)      Language model     │
│                                                              │
│  Notification        smtplib             Email sending      │
│                      email.mime          Email formatting   │
└─────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
ai-sec-monitor/
├── infra/                      # Infrastructure configs
│   ├── docker-compose.routed.yml
│   ├── sensor/                 # Suricata configs
│   └── workstation/            # Attack scripts
├── detect/                     # Detection engine
│   ├── anomaly.py              # ML anomaly detection
│   ├── rule_runner.py          # Rule engine
│   ├── threat_correlator.py   # Threat correlation
│   ├── data_sources.py         # Loki integration
│   └── rules.yaml              # Detection rules
├── api/                        # REST API
│   └── main.py                 # FastAPI endpoints
├── ai-agent/                   # AI validation
│   ├── validation_layer/
│   │   ├── feature_analyzer.py # Heuristic analysis
│   │   └── llm_validator.py    # LLM validation
│   ├── scripts/
│   │   └── run_api_response.py # Main validation script
│   └── agents/
│       └── email_agent.py      # Email notifications
├── logs/                       # Runtime logs
├── LAUNCH_GUIDE.md             # This guide
└── QUICKSTART.md               # Quick reference
```

---

**For step-by-step launch instructions, see [LAUNCH_GUIDE.md](LAUNCH_GUIDE.md)**

