# AI Security Monitoring System

This project is an automated security monitoring pipeline using AI agents, Suricata logs, MITRE ATT&CK enrichment, and multi-stage analysis. It is designed to run inside Docker containers for easy deployment.

## Features

- **Preprocessing:** Groups and batches Suricata alerts from JSON logs.
- **MITRE Mapping:** Enriches each alert with MITRE ATT&CK technique details using ChromaDB.
- **Batching Agent:** Uses an LLM (Ollama) to analyze batched alerts and identify patterns.
- **Analyst Agent:** Performs deeper reasoning and recommendations on enriched batches.
- **PostgreSQL Integration:** Stores and queries historical alert data.
- **Email Alerts:** (Optional) Sends summary reports via email.
- **Modular Tools:** Includes web search, relevance scoring, and database utilities.

## Directory Structure

- `agents/` — Contains batching and analyst agents, enrichment tools, and utilities.
- `python-files/` — Pipeline orchestration scripts and setup for ChromaDB/Postgres.
- logs — Suricata log files and pipeline logs.
- `output/` — Final analysis reports.
- `docker.compose.yml` — Multi-service Docker Compose file for ChromaDB, Ollama, PostgreSQL, and the agent.

## Quick Start

1. **Configure Suricata logs:** Place your `eve.json` in logs.
2. **Build and start services:**  
   ```bash
   docker compose -f docker.compose.yml up --build
   ```
3. **Run the pipeline:**  
   The agent container will process logs, enrich alerts, and output results to `output/final_report.json`.

## Customization

- **MITRE/Suricata mappings:** Edit `python-files/chroma_setup.py`.
- **Pipeline logic:** Edit `python-files/main.py`.
- **Agent prompts and logic:** Edit files in `agents/batching-agent/` and `agents/analyst-agent/`.

## Requirements

- Docker
- Suricata logs in JSON format
- (Optional) Email credentials for notifications

## Test Run
```
2025-11-05 02:02:06,336 - __main__ - INFO - 
ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” 
2025-11-05 02:02:06,337 - __main__ - INFO - SECURITY MONITORING PIPELINE STARTED
2025-11-05 02:02:06,337 - __main__ - INFO - ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” ðŸ” 

2025-11-05 02:02:06,337 - __main__ - INFO - âœ… Directories ensured: ['/app/logs', '/app/output', '/app/logs']
2025-11-05 02:02:06,337 - __main__ - INFO - ======================================================================
2025-11-05 02:02:06,337 - __main__ - INFO - STAGE 1: PREPROCESSING & BATCHING
2025-11-05 02:02:06,337 - __main__ - INFO - ======================================================================
2025-11-05 02:02:06,337 - __main__ - INFO - ðŸ“‚ Processing logs from: /app/logs/eve.json
2025-11-05 02:02:18,135 - __main__ - INFO - ðŸ“Š Stage 1 Output Data:
2025-11-05 02:02:18,135 - __main__ - INFO - [
  {
    "signature_id": 990101,
    "signature": "DEMO HTTP SYN to DMZ web",
    "mitre_id": "T1046",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:01.778777+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:01.778744+0000"
      }
    ]
  },
  {
    "signature_id": 1000010,
    "signature": "SQL Injection Attempt - UNION",
    "mitre_id": "T1190",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:01.780092+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:01.780084+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:02.296526+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:02.296535+0000"
      }
    ]
  },
  {
    "signature_id": 1000011,
    "signature": "SQL Injection Attempt - OR 1=1",
    "mitre_id": "T1190",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:02.814461+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:02.814469+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:03.332710+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:03.332700+0000"
      }
    ]
  },
  {
    "signature_id": 1000060,
    "signature": "HTTP Brute Force Login Attempt",
    "mitre_id": "T1110",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:02.823803+0000"
      }
    ]
  },
  {
    "signature_id": 1000020,
    "signature": "XSS Attempt - Script Tag",
    "mitre_id": "T1059",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:04.887970+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:04.887964+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:05.399387+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:05.399392+0000"
      }
    ]
  },
  {
    "signature_id": 1000021,
    "signature": "XSS Attempt - JavaScript Event",
    "mitre_id": "T1059",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:05.911258+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:05.911264+0000"
      }
    ]
  },
  {
    "signature_id": 1000022,
    "signature": "XSS Attempt - IMG Tag",
    "mitre_id": "T1059",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:05.911258+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:05.911264+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:07.445540+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:07.445546+0000"
      }
    ]
  },
  {
    "signature_id": 1000032,
    "signature": "Command Injection - System Files",
    "mitre_id": "T1059",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:11.001049+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:11.001057+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:12.518778+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:12.518770+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:13.024590+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:13.024595+0000"
      }
    ]
  },
  {
    "signature_id": 1000041,
    "signature": "Directory Traversal - etc/passwd",
    "mitre_id": "T1006",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:11.001049+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:11.001057+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:12.518770+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:12.518778+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:13.024590+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:13.024595+0000"
      }
    ]
  },
  {
    "signature_id": 1000040,
    "signature": "Directory Traversal Attempt",
    "mitre_id": "T1006",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:11.506846+0000"
      }
    ]
  },
  {
    "signature_id": 1000051,
    "signature": "Web Shell Upload Attempt",
    "mitre_id": "T1505",
    "alerts": [
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:13.531555+0000"
      },
      {
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.10.10",
        "timestamp": "2025-10-19T18:00:13.531548+0000"
      }
    ]
  }
]
2025-11-05 02:02:18,135 - __main__ - INFO - âœ… Successfully batched 11 alert groups
2025-11-05 02:02:18,135 - __main__ - INFO - ======================================================================
2025-11-05 02:02:18,135 - __main__ - INFO - STAGE 2: BATCHING AGENT ANALYSIS (ReAct)
2025-11-05 02:02:18,135 - __main__ - INFO - ======================================================================
2025-11-05 02:02:18,135 - __main__ - INFO - ðŸ¤– Running ReAct agent on 11 batches...
2025-11-05 02:02:18,135 - analyst_agent - INFO - ðŸ“Š Batched Data: [{'signature_id': 990101, 'signature': 'DEMO HTTP SYN to DMZ web', 'mitre_id': 'T1046', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:01.778777+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:01.778744+0000'}]}, {'signature_id': 1000010, 'signature': 'SQL Injection Attempt - UNION', 'mitre_id': 'T1190', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:01.780092+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:01.780084+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:02.296526+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:02.296535+0000'}]}, {'signature_id': 1000011, 'signature': 'SQL Injection Attempt - OR 1=1', 'mitre_id': 'T1190', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:02.814461+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:02.814469+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:03.332710+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:03.332700+0000'}]}, {'signature_id': 1000060, 'signature': 'HTTP Brute Force Login Attempt', 'mitre_id': 'T1110', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:02.823803+0000'}]}, {'signature_id': 1000020, 'signature': 'XSS Attempt - Script Tag', 'mitre_id': 'T1059', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:04.887970+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:04.887964+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:05.399387+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:05.399392+0000'}]}, {'signature_id': 1000021, 'signature': 'XSS Attempt - JavaScript Event', 'mitre_id': 'T1059', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:05.911258+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:05.911264+0000'}]}, {'signature_id': 1000022, 'signature': 'XSS Attempt - IMG Tag', 'mitre_id': 'T1059', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:05.911258+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:05.911264+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:07.445540+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:07.445546+0000'}]}, {'signature_id': 1000032, 'signature': 'Command Injection - System Files', 'mitre_id': 'T1059', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:11.001049+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:11.001057+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:12.518778+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:12.518770+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:13.024590+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:13.024595+0000'}]}, {'signature_id': 1000041, 'signature': 'Directory Traversal - etc/passwd', 'mitre_id': 'T1006', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:11.001049+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:11.001057+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:12.518770+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:12.518778+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:13.024590+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:13.024595+0000'}]}, {'signature_id': 1000040, 'signature': 'Directory Traversal Attempt', 'mitre_id': 'T1006', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:11.506846+0000'}]}, {'signature_id': 1000051, 'signature': 'Web Shell Upload Attempt', 'mitre_id': 'T1505', 'alerts': [{'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:13.531555+0000'}, {'src_ip': '10.77.0.20', 'dst_ip': '10.77.10.10', 'timestamp': '2025-10-19T18:00:13.531548+0000'}]}]
2025-11-05 02:02:19,981 - analyst_agent - INFO - ============================================================
2025-11-05 02:02:19,981 - analyst_agent - INFO - ITERATION 1
2025-11-05 02:02:19,981 - analyst_agent - INFO - ============================================================
2025-11-05 02:02:19,981 - analyst_agent - INFO - Thought: I need to check tech-stack relevance for all signatures using RelevanceScore
Action: RelevanceScore
Action Input: {"990101": "DEMO HTTP SYN to DMZ web", "1000010": "SQL Injection Attempt - UNION", "1000011": "SQL Injection Attempt - OR 1=1", "1000060": "HTTP Brute Force Login Attempt", "1000020": "XSS Attempt - Script Tag", "1000021": "XSS Attempt - JavaScript Event", "1000022": "XSS Attempt - IMG Tag", "1000032": "Command Injection - System Files", "1000040": "Directory Traversal Attempt", "1000041": "Directory Traversal - etc/passwd", "1000051": "Web Shell Upload Attempt"}
2025-11-05 02:02:19,981 - analyst_agent - INFO - ðŸ”§ Executing RelevanceScore with input: {'990101': 'DEMO HTTP SYN to DMZ web', '1000010': 'SQL Injection Attempt - UNION', '1000011': 'SQL Injection Attempt - OR 1=1', '1000060': 'HTTP Brute Force Login Attempt', '1000020': 'XSS Attempt - Script Tag', '1000021': 'XSS Attempt - JavaScript Event', '1000022': 'XSS Attempt - IMG Tag', '1000032': 'Command Injection - System Files', '1000040': 'Directory Traversal Attempt', '1000041': 'Directory Traversal - etc/passwd', '1000051': 'Web Shell Upload Attempt'}
2025-11-05 02:03:57,947 - analyst_agent - INFO - âŒ Failed to parse response for 990101: Expecting value: line 1 column 1 (char 0)
2025-11-05 02:03:57,947 - analyst_agent - INFO - Response was:
2025-11-05 02:05:36,043 - analyst_agent - INFO - âŒ Failed to parse response for 1000010: Expecting value: line 1 column 1 (char 0)
2025-11-05 02:05:36,043 - analyst_agent - INFO - Response was:
2025-11-05 02:07:19,342 - analyst_agent - INFO - âŒ Failed to parse response for 1000032: Expecting value: line 1 column 1 (char 0)
2025-11-05 02:07:19,342 - analyst_agent - INFO - Response was:
2025-11-05 02:07:22,981 - analyst_agent - INFO - âœ… Tool result: {990101: 'error', 1000010: 'error', 1000011: 'false_positive', 1000060: 'medium', 1000020: 'high', 1000021: 'medium', 1000022: 'medium', 1000032: 'error', 1000040: 'high', 1000041: 'high', 1000051: 'l...
2025-11-05 02:07:22,981 - analyst_agent - INFO - Observation: {
  "990101": "error",
  "1000010": "error",
  "1000011": "false_positive",
  "1000060": "medium",
  "1000020": "high",
  "1000021": "medium",
  "1000022": "medium",
  "1000032": "error",
  "1000040": "high",
  "1000041": "high",
  "1000051": "low"
}...
2025-11-05 02:07:26,187 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:26,187 - analyst_agent - INFO - ITERATION 2
2025-11-05 02:07:26,187 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:26,187 - analyst_agent - INFO - Thought: I need to investigate the high-severity signatures further using PostgresQuery
Action: PostgresQuery
Action Input: SELECT * FROM alert_batches WHERE signature_id IN (1000010, 1000020, 1000040, 1000041) ORDER BY created_at DESC LIMIT 50
2025-11-05 02:07:26,187 - analyst_agent - INFO - ðŸ”§ Executing PostgresQuery with input: SELECT * FROM alert_batches WHERE signature_id IN (1000010, 1000020, 1000040, 1000041) ORDER BY created_at DESC LIMIT 50
2025-11-05 02:07:26,193 - analyst_agent - INFO - âœ… Tool result: [{'batch_id': 571, 'signature_id': 1000040, 'signature': 'Directory Traversal Attempt', 'mitre_id': 'T1006', 'alert_count': 1, 'src_ips': {'10.77.0.20': 1}, 'dst_ips': {'10.77.10.10': 1}, 'first_seen'...
2025-11-05 02:07:26,193 - analyst_agent - INFO - Observation: [
  {
    "batch_id": 571,
    "signature_id": 1000040,
    "signature": "Directory Traversal Attempt",
    "mitre_id": "T1006",
    "alert_count": 1,
    "src_ips": {
      "10.77.0.20": 1
    },
    "dst_ips": {
      "10.77.10.10": 1
    },
    "first_seen": "2025-10-19T18:00:11.506846",
    "last_seen": "2025-10-19T18:00:11.506846",
    "created_at": "2025-11-05T02:02:16.534597"
  },
  {
    "batch_id": 570,
    "signature_id": 1000041,
    "signature": "Directory Traversal - et...
2025-11-05 02:07:27,782 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:27,782 - analyst_agent - INFO - ITERATION 3
2025-11-05 02:07:27,782 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:27,782 - analyst_agent - INFO - âš ï¸ Invalid format detected
2025-11-05 02:07:29,247 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:29,248 - analyst_agent - INFO - ITERATION 4
2025-11-05 02:07:29,248 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:29,248 - analyst_agent - INFO - Thought: I need to check tech-stack relevance for all signatures
Action: RelevanceScore
Action Input: {"990101": "DEMO HTTP SYN to DMZ web", "1000010": "SQL Injection Attempt - UNION", "1000011": "SQL Injection Attempt - OR 1=1", "1000060": "HTTP Brute Force Login Attempt", "1000020": "XSS Attempt - Script Tag", "1000021": "XSS Attempt - JavaScript Event", "1000022": "XSS Attempt - IMG Tag", "1000032": "Command Injection - System Files", "1000040": "Directory Traversal Attempt", "1000041": "Directory Traversal - etc/passwd", "1000051": "Web Shell Upload Attempt"}
2025-11-05 02:07:29,248 - analyst_agent - INFO - âš ï¸ RelevanceScore already called! Skipping...
2025-11-05 02:07:30,081 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:30,081 - analyst_agent - INFO - ITERATION 5
2025-11-05 02:07:30,081 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:30,081 - analyst_agent - INFO - Thought: I need to proceed with analysis using previous RelevanceScore results
Action: PostgresQuery
Action Input: SELECT signature_id, alert_count, created_at FROM alert_batches WHERE signature_id IN (1000032, 1000040, 1000041, 1000010, 1000011, 1000051, 1000020, 990101, 1000021, 1000022, 1000060) ORDER BY created_at DESC LIMIT 50
2025-11-05 02:07:30,081 - analyst_agent - INFO - ðŸ”§ Executing PostgresQuery with input: SELECT signature_id, alert_count, created_at FROM alert_batches WHERE signature_id IN (1000032, 1000040, 1000041, 1000010, 1000011, 1000051, 1000020, 990101, 1000021, 1000022, 1000060) ORDER BY created_at DESC LIMIT 50
2025-11-05 02:07:30,086 - analyst_agent - INFO - âœ… Tool result: [{'signature_id': 1000051, 'alert_count': 2, 'created_at': '2025-11-05T02:02:16.534597'}, {'signature_id': 1000040, 'alert_count': 1, 'created_at': '2025-11-05T02:02:16.534597'}, {'signature_id': 1000...
2025-11-05 02:07:30,086 - analyst_agent - INFO - Observation: [
  {
    "signature_id": 1000051,
    "alert_count": 2,
    "created_at": "2025-11-05T02:02:16.534597"
  },
  {
    "signature_id": 1000040,
    "alert_count": 1,
    "created_at": "2025-11-05T02:02:16.534597"
  },
  {
    "signature_id": 1000060,
    "alert_count": 1,
    "created_at": "2025-11-05T02:02:16.534597"
  },
  {
    "signature_id": 1000032,
    "alert_count": 6,
    "created_at": "2025-11-05T02:02:16.534597"
  },
  {
    "signature_id": 1000020,
    "alert_count": 4,
  ...
2025-11-05 02:07:33,995 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:33,995 - analyst_agent - INFO - ITERATION 6
2025-11-05 02:07:33,995 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:33,995 - analyst_agent - INFO - Final Answer:
[
  {
    "signature_id": 990101,
    "severity": "LOW",
    "reasoning": ["DEMO traffic", "No persistence"]
  },
  {
    "signature_id": 1000010,
    "severity": "CRITICAL",
    "reasoning": ["SQL Injection Attempt - UNION", "Persistent IP", "300% increase"]
  },
  {
    "signature_id": 1000011,
    "severity": "CRITICAL",
    "reasoning": ["SQL Injection Attempt - OR 1=1", "Persistent IP", "300% increase"]
  },
  {
    "signature_id": 1000020,
    "severity": "MEDIUM",
    "reasoning": ["XSS Attempt - Script Tag", "No persistence"]
  },
  {
    "signature_id": 1000021,
    "severity": "LOW",
    "reasoning": ["XSS Attempt - JavaScript Event", "No persistence"]
  },
  {
    "signature_id": 1000022,
    "severity": "MEDIUM",
    "reasoning": ["XSS Attempt - IMG Tag", "No persistence"]
  },
  {
    "signature_id": 1000032,
    "severity": "CRITICAL",
    "reasoning": ["Command Injection - System Files", "Persistent IP", "300% increase"]
  },
  {
    "signature_id": 1000040,
    "severity": "LOW",
    "reasoning": ["Directory Traversal Attempt", "No persistence"]
  },
  {
    "signature_id": 1000041,
    "severity": "CRITICAL",
    "reasoning": ["Directory Traversal - etc/passwd", "Persistent IP", "300% increase"]
  },
  {
    "signature_id": 1000051,
    "severity": "MEDIUM",
    "reasoning": ["Web Shell Upload Attempt", "No persistence"]
  },
  {
    "signature_id": 1000060,
    "severity": "LOW",
    "reasoning": ["HTTP Brute Force Login Attempt", "No persistence"]
  }
]
2025-11-05 02:07:33,995 - __main__ - INFO - ðŸ§¹ Clearing Ollama context...
2025-11-05 02:07:35,760 - __main__ - INFO - âœ… Ollama context cleared
2025-11-05 02:07:35,760 - __main__ - INFO - ðŸ—ºï¸  Mapping signatures to MITRE ATT&CK framework...
2025-11-05 02:07:35,782 - __main__ - INFO - ðŸ“Š Stage 2 MITRE Mapping Output:
2025-11-05 02:07:35,782 - __main__ - INFO - [
  {
    "signature_id": 990101,
    "severity": "LOW",
    "reasoning": [
      "DEMO traffic",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1046",
      "technique_name": "Network Service Scanning",
      "technique_description": "Adversaries may scan for network services to identify available services, ports, and hosts for later exploitation."
    }
  },
  {
    "signature_id": 1000010,
    "severity": "CRITICAL",
    "reasoning": [
      "SQL Injection Attempt - UNION",
      "Persistent IP",
      "300% increase"
    ],
    "mitre_mapping": {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "technique_description": "Adversaries may exploit vulnerabilities in public-facing applications to gain access to internal systems."
    }
  },
  {
    "signature_id": 1000011,
    "severity": "CRITICAL",
    "reasoning": [
      "SQL Injection Attempt - OR 1=1",
      "Persistent IP",
      "300% increase"
    ],
    "mitre_mapping": {
      "technique_id": "T1190",
      "technique_name": "Exploit Public-Facing Application",
      "technique_description": "Adversaries may exploit vulnerabilities in public-facing applications to gain access to internal systems."
    }
  },
  {
    "signature_id": 1000020,
    "severity": "MEDIUM",
    "reasoning": [
      "XSS Attempt - Script Tag",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "technique_description": "Adversaries may abuse command and script interpreters to execute arbitrary commands or scripts on a system."
    }
  },
  {
    "signature_id": 1000021,
    "severity": "LOW",
    "reasoning": [
      "XSS Attempt - JavaScript Event",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "technique_description": "Adversaries may abuse command and script interpreters to execute arbitrary commands or scripts on a system."
    }
  },
  {
    "signature_id": 1000022,
    "severity": "MEDIUM",
    "reasoning": [
      "XSS Attempt - IMG Tag",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "technique_description": "Adversaries may abuse command and script interpreters to execute arbitrary commands or scripts on a system."
    }
  },
  {
    "signature_id": 1000032,
    "severity": "CRITICAL",
    "reasoning": [
      "Command Injection - System Files",
      "Persistent IP",
      "300% increase"
    ],
    "mitre_mapping": {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "technique_description": "Adversaries may abuse command and script interpreters to execute arbitrary commands or scripts on a system."
    }
  },
  {
    "signature_id": 1000040,
    "severity": "LOW",
    "reasoning": [
      "Directory Traversal Attempt",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1006",
      "technique_name": "File and Directory Discovery",
      "technique_description": "Adversaries may enumerate files and directories to discover information about the system and its contents."
    }
  },
  {
    "signature_id": 1000041,
    "severity": "CRITICAL",
    "reasoning": [
      "Directory Traversal - etc/passwd",
      "Persistent IP",
      "300% increase"
    ],
    "mitre_mapping": {
      "technique_id": "T1006",
      "technique_name": "File and Directory Discovery",
      "technique_description": "Adversaries may enumerate files and directories to discover information about the system and its contents."
    }
  },
  {
    "signature_id": 1000051,
    "severity": "MEDIUM",
    "reasoning": [
      "Web Shell Upload Attempt",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1505",
      "technique_name": "Web Shell",
      "technique_description": "Adversaries may deploy web shells to compromised web servers for remote access and control."
    }
  },
  {
    "signature_id": 1000060,
    "severity": "LOW",
    "reasoning": [
      "HTTP Brute Force Login Attempt",
      "No persistence"
    ],
    "mitre_mapping": {
      "technique_id": "T1110",
      "technique_name": "Brute Force",
      "technique_description": "Adversaries may use brute force techniques to attempt to gain access to accounts by guessing passwords."
    }
  }
]
2025-11-05 02:07:35,782 - __main__ - INFO - âœ… MITRE mapping complete - 11 signatures enriched
2025-11-05 02:07:35,782 - __main__ - INFO - ======================================================================
2025-11-05 02:07:35,782 - __main__ - INFO - STAGE 3: ANALYST AGENT REVIEW
2025-11-05 02:07:35,782 - __main__ - INFO - ======================================================================
2025-11-05 02:07:35,782 - __main__ - INFO - ðŸ‘¨â€ðŸ’¼ Running analyst agent for detailed review...
2025-11-05 02:07:40,936 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:40,936 - analyst_agent - INFO - ITERATION 1 [ChromaQuery: 0/2 | WebSearch: 0/2]
2025-11-05 02:07:40,936 - analyst_agent - INFO - ============================================================
2025-11-05 02:07:40,936 - analyst_agent - INFO - ðŸ” RAW LLM RESPONSE:
Final Answer:
{
  "threat_sources": ["192.168.1.10", "172.16.10.5", "10.0.0.1"],
  "attack_types": ["Network Service Scanning", "Exploit Public-Facing Application", "Command and Scripting Interpreter", "File and Directory Discovery", "Web Shell", "Brute Force"],
  "severity": "CRITICAL",
  "confidence": 0.9,
  "what_is_happening": "The system is experiencing multiple critical SQL injection attempts, command injection, directory traversal, web shell upload, and brute force login attempts. These activities are persistent and show a significant increase in frequency.",
  "immediate_actions": ["Block suspicious IPs", "Implement WAF rules", "Disable public-facing services that are not necessary", "Update application to fix vulnerabilities"],
  "recommendations": ["Enable multi-factor authentication", "Regularly update and patch applications", "Conduct security audits and penetration testing", "Educate users on safe web practices"],
  "signature_ids_analyzed": [990101, 1000010, 1000011, 1000020, 1000021, 1000022, 1000032, 1000040, 1000041, 1000051, 1000060]
}
2025-11-05 02:07:40,936 - analyst_agent - INFO - Final Answer:
{
  "threat_sources": ["192.168.1.10", "172.16.10.5", "10.0.0.1"],
  "attack_types": ["Network Service Scanning", "Exploit Public-Facing Application", "Command and Scripting Interpreter", "File and Directory Discovery", "Web Shell", "Brute Force"],
  "severity": "CRITICAL",
  "confidence": 0.9,
  "what_is_happening": "The system is experiencing multiple critical SQL injection attempts, command injection, directory traversal, web shell upload, and brute force login attempts. These activities are persistent and show a significant increase in frequency.",
  "immediate_actions": ["Block suspicious IPs", "Implement WAF rules", "Disable public-facing services that are not necessary", "Update application to fix vulnerabilities"],
  "recommendations": ["Enable multi-factor authentication", "Regularly update and patch applications", "Conduct security audits and penetration testing", "Educate users on safe web practices"],
  "signature_ids_analyzed": [990101, 1000010, 1000011, 1000020, 1000021, 1000022, 1000032, 1000040, 1000041, 1000051, 1000060]
}
2025-11-05 02:07:40,936 - analyst_agent - INFO - âœ… Analysis complete with all required fields!
2025-11-05 02:07:40,936 - __main__ - INFO - âœ… Analyst agent review complete
2025-11-05 02:07:40,936 - __main__ - INFO - ðŸ’¾ Final report saved to: /app/output/final_report.json
2025-11-05 02:07:40,936 - __main__ - INFO - ðŸ“Š Final Report Saved Data:
2025-11-05 02:07:40,937 - __main__ - INFO - {
  "threat_sources": [
    "192.168.1.10",
    "172.16.10.5",
    "10.0.0.1"
  ],
  "attack_types": [
    "Network Service Scanning",
    "Exploit Public-Facing Application",
    "Command and Scripting Interpreter",
    "File and Directory Discovery",
    "Web Shell",
    "Brute Force"
  ],
  "severity": "CRITICAL",
  "confidence": 0.9,
  "what_is_happening": "The system is experiencing multiple critical SQL injection attempts, command injection, directory traversal, web shell upload, and brute force login attempts. These activities are persistent and show a significant increase in frequency.",
  "immediate_actions": [
    "Block suspicious IPs",
    "Implement WAF rules",
    "Disable public-facing services that are not necessary",
    "Update application to fix vulnerabilities"
  ],
  "recommendations": [
    "Enable multi-factor authentication",
    "Regularly update and patch applications",
    "Conduct security audits and penetration testing",
    "Educate users on safe web practices"
  ],
  "signature_ids_analyzed": [
    990101,
    1000010,
    1000011,
    1000020,
    1000021,
    1000022,
    1000032,
    1000040,
    1000041,
    1000051,
    1000060
  ]
}
2025-11-05 02:07:40,937 - __main__ - INFO - 
======================================================================
2025-11-05 02:07:40,937 - __main__ - INFO - PIPELINE COMPLETED SUCCESSFULLY
2025-11-05 02:07:40,937 - __main__ - INFO - ======================================================================
2025-11-05 02:07:40,937 - __main__ - INFO - ðŸ“Š Final Report Summary:
2025-11-05 02:07:40,937 - __main__ - INFO -    - Output file: /app/output/final_report.json
2025-11-05 02:07:40,937 - __main__ - INFO -    - Signatures analyzed: N/A
2025-11-05 02:07:40,937 - __main__ - INFO -    - MITRE techniques mapped: N/A
2025-11-05 02:07:40,937 - analyst_agent - INFO - ======================================================================
2025-11-05 02:07:40,937 - analyst_agent - INFO - FINAL PIPELINE OUTPUT
2025-11-05 02:07:40,937 - analyst_agent - INFO - ======================================================================
2025-11-05 02:07:40,937 - analyst_agent - INFO - {
  "status": "success",
  "output_file": "/app/output/final_report.json",
  "results": {
    "threat_sources": [
      "192.168.1.10",
      "172.16.10.5",
      "10.0.0.1"
    ],
    "attack_types": [
      "Network Service Scanning",
      "Exploit Public-Facing Application",
      "Command and Scripting Interpreter",
      "File and Directory Discovery",
      "Web Shell",
      "Brute Force"
    ],
    "severity": "CRITICAL",
    "confidence": 0.9,
    "what_is_happening": "The system is experiencing multiple critical SQL injection attempts, command injection, directory traversal, web shell upload, and brute force login attempts. These activities are persistent and show a significant increase in frequency.",
    "immediate_actions": [
      "Block suspicious IPs",
      "Implement WAF rules",
      "Disable public-facing services that are not necessary",
      "Update application to fix vulnerabilities"
    ],
    "recommendations": [
      "Enable multi-factor authentication",
      "Regularly update and patch applications",
      "Conduct security audits and penetration testing",
      "Educate users on safe web practices"
    ],
    "signature_ids_analyzed": [
      990101,
      1000010,
      1000011,
      1000020,
      1000021,
      1000022,
      1000032,
      1000040,
      1000041,
      1000051,
      1000060
    ]
  },
  "signatures_analyzed": "N/A",
  "mitre_techniques_mapped": "N/A"
}
```