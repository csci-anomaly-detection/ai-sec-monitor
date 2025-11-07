# Agent Integration Design Document

## Metadata
- **Status:** Draft
- **Author(s):** AI Security Monitor Team
- **Reviewers:** TBD
- **Created:** 2025-10-25
- **Updated:** 2025-10-25
- **Implementation PR(s):** TBD

## Overview

The AI Security Monitor currently has two separate agent systems operating in isolation:

1. **Batching Agent** - A sophisticated ReAct agent that processes raw Suricata IDS alerts, performs tech-stack-aware threat analysis, and leverages PostgreSQL and ChromaDB for intelligent batching and pattern recognition.

2. **Analysis Agents** - Simpler agents that read pre-processed threat JSON files, perform basic LLM analysis, and send email alerts for critical threats.

**The Problem:** These two systems don't communicate. The batching agent produces rich, context-aware threat analysis (including severity scores, historical patterns, and multi-stage attack detection), but this valuable output never reaches the email alerting system or the downstream analysis pipeline.

**Why Now:** To create a unified, end-to-end security monitoring pipeline that:
- Automatically processes raw Suricata alerts through intelligent batching
- Applies tech-stack-aware threat scoring using server profiles
- Routes critical threats to email alerts without manual intervention
- Maintains a comprehensive audit trail of all analyses
- Enables real-time incident response workflows

## Goals

### Primary Goals
1. **Unified Data Flow**: Create a seamless pipeline from Batching Agent output → Analysis Agents input
2. **Automated Critical Alerting**: Email notifications for CRITICAL/HIGH severity threats identified by batching agent
3. **Comprehensive Logging**: Store batching agent analyses in standardized format alongside existing analysis outputs
4. **Real-time Processing**: Enable continuous monitoring with minimal latency (<2 minutes from alert to email)

### Secondary Goals
5. **Backward Compatibility**: Preserve existing agent functionality for manual threat analysis
6. **Extensibility**: Design integration layer to support future agents (Slack, PagerDuty, SOAR platforms)
7. **Error Resilience**: Graceful degradation if batching agent or email service fails

### Non-Goals
- Replacing the batching agent's ReAct architecture with simpler logic
- Migrating away from dual LLM models (Llama 3.2 for batching, Llama 3.1 for analysis)
- Building a web UI for threat visualization (separate effort)

## Proposed Solution

### High-Level Approach

We will create an **Integration Orchestrator** that acts as a bridge between the two agent systems. This orchestrator will:

1. **Poll** the Batching Agent's PostgreSQL database for new analysis results
2. **Transform** batching agent outputs into the format expected by Analysis Agents
3. **Route** threats based on severity:
   - CRITICAL/HIGH → Email Agent + File Writer + Incident Response Queue
   - MEDIUM/LOW → File Writer only
   - FALSE_POSITIVE → Archival storage
4. **Coordinate** the execution of downstream agents (email, logging, future integrations)

The integration leverages existing infrastructure (PostgreSQL, Docker Compose) and introduces minimal new dependencies.

### Key Components

- **Integration Orchestrator (`integration_orchestrator.py`):** 
  - Main coordinator service running as Docker container
  - Polls PostgreSQL for new batching agent results (every 30-60 seconds)
  - Transforms data formats and routes to appropriate handlers
  - Maintains processing state to avoid duplicate alerts

- **Threat Adapter (`threat_adapter.py`):** 
  - Data transformation layer
  - Converts batching agent's JSON output to Analysis Agent's expected format
  - Enriches threat data with additional context from ChromaDB
  - Normalizes severity levels across different agent outputs

- **Alert Router (`alert_router.py`):** 
  - Decision engine for routing threats
  - Configurable severity thresholds
  - Rate limiting to prevent alert storms
  - Deduplication logic for repeat threats from same source IP

- **Enhanced File Writer (`enhanced_file_writer.py`):**
  - Extends existing file_writer.py
  - Stores batching agent analyses with full ReAct execution trace
  - Creates timestamped analysis files in unified format
  - Supports both JSON and human-readable text outputs

- **Integration Database Schema:**
  - New PostgreSQL table `integration_state` to track processing status
  - Prevents duplicate processing of same batch results
  - Stores alert delivery confirmations and retry attempts

### Simple Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SURICATA IDS (DVWA)                               │
└────────────────────────┬────────────────────────────────────────────────┘
                         │ eve.json logs
                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     PRE-BATCHING LAYER                                   │
│  - Signature grouping, deduplication, IP aggregation                    │
└────────────────────────┬────────────────────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────────────┐
        │    STORAGE LAYER                       │
        │  PostgreSQL (batches)                  │
        │  ChromaDB (logs + rules)               │
        └──────────┬─────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────────────────────────┐
        │   BATCHING AGENT (ReAct)                 │
        │  - Llama 3.2 (Ollama)                    │
        │  - Tools: PostgresQuery, ChromaQuery,    │
        │           RelevanceScore                 │
        │  - Server Profile Awareness              │
        └──────────┬───────────────────────────────┘
                   │
                   │ Writes analysis results
                   ▼
        ┌──────────────────────────────────────────┐
        │   ANALYSIS RESULTS TABLE                 │
        │  (New: threat_analysis_results)          │
        │  - signature_id, severity, reasoning     │
        │  - batch_id (FK), timestamp              │
        │  - processed (boolean flag)              │
        └──────────┬───────────────────────────────┘
                   │
                   │ [NEW INTEGRATION LAYER]
                   ▼
        ┌──────────────────────────────────────────┐
        │  INTEGRATION ORCHESTRATOR                │
        │  - Polls for new results                 │
        │  - Data transformation                   │
        │  - Routing logic                         │
        └──────────┬───────────────────────────────┘
                   │
        ┌──────────┴────────────────────────────────┐
        │                                           │
        ▼                                           ▼
┌───────────────────┐                    ┌──────────────────────┐
│  ALERT ROUTER     │                    │  THREAT ADAPTER      │
│  - Severity check │                    │  - Format conversion │
│  - Rate limiting  │                    │  - Data enrichment   │
└────────┬──────────┘                    └──────────────────────┘
         │
         │
    ┌────┴─────────────────────┬──────────────────────┐
    │                          │                      │
    ▼                          ▼                      ▼
┌──────────────┐      ┌─────────────────┐   ┌────────────────────┐
│ EMAIL AGENT  │      │  FILE WRITER    │   │  FUTURE INTEGR.    │
│ (CRITICAL/   │      │  - JSON logs    │   │  - Slack           │
│  HIGH only)  │      │  - Text reports │   │  - PagerDuty       │
│              │      │  - Audit trail  │   │  - SOAR Platform   │
└──────────────┘      └─────────────────┘   └────────────────────┘
```

## Design Considerations

### 1. Data Polling vs. Event-Driven Architecture

**Context:** The orchestrator needs to know when new batching agent results are available. We can either poll the database periodically or implement an event-driven system with message queues.

**Options:**
- **Option A: Database Polling (30-60 second intervals)**
  - Pros: 
    - Simple to implement (no new infrastructure)
    - Works with existing PostgreSQL setup
    - Easy debugging and observability
    - Postgres LISTEN/NOTIFY support available for optimization
  - Cons: 
    - Slight latency (up to 60 seconds delay)
    - Inefficient if batching agent runs infrequently
    - Adds database load (minimal with proper indexing)

- **Option B: Message Queue (RabbitMQ/Redis)**
  - Pros: 
    - Near-instant notification (<1 second)
    - Decoupled architecture
    - Better for high-throughput scenarios
  - Cons: 
    - Additional infrastructure complexity
    - New failure modes (queue downtime)
    - Overkill for current alert volume (~1-10 batches per minute)

- **Option C: File System Watcher**
  - Pros: 
    - No polling overhead
    - Simple implementation
  - Cons: 
    - Fragile (Docker volume mount issues)
    - Not suitable for distributed deployments
    - Bypasses database as source of truth

**Recommendation:** **Option A (Database Polling)** for initial implementation. Use PostgreSQL `LISTEN/NOTIFY` feature for near-real-time updates without complex message queue infrastructure. This provides 95% of the benefits of Option B with 10% of the complexity. Migrate to Option B if alert volume exceeds 100 batches/minute.

### 2. Threat Data Format Standardization

**Context:** Batching agent outputs detailed JSON with `signature_id`, `severity`, `reasoning` arrays, while Analysis Agents expect simpler `ip`, `attack_type`, `severity`, `total_events` format.

**Options:**
- **Option A: Canonical Threat Schema (New Standard)**
  - Pros: 
    - Single source of truth for threat data structure
    - Easier to add new agents
    - Versioned schema for backward compatibility
  - Cons: 
    - Requires refactoring both existing systems
    - Migration complexity
    - Breaking change for any external integrations

- **Option B: Adapter Pattern (Transform at Integration Layer)**
  - Pros: 
    - Zero changes to existing agents
    - Flexible transformation logic
    - Can support multiple output formats
  - Cons: 
    - Potential data loss during transformation
    - Adapter becomes complex over time
    - Duplicate validation logic

- **Option C: Dual Format Support**
  - Pros: 
    - Agents can accept either format
    - Gradual migration path
  - Cons: 
    - Bloated agent code
    - Inconsistent behavior across agents

**Recommendation:** **Option B (Adapter Pattern)** initially, with migration plan to Option A. Create `ThreatAdapter` class that maps:

```python
# Batching Agent Output
{
  "signature_id": 1000032,
  "severity": "CRITICAL",
  "reasoning": ["Command injection targets Apache/PHP stack", "120 alerts in 24h"],
  "src_ips": {"10.77.0.20": 120},
  "attack_type": "Command Injection - System Files"
}

# → Analysis Agent Input (after transformation)
{
  "ip": "10.77.0.20",  # Most frequent src_ip
  "severity": "CRITICAL",
  "attack_type": "Command Injection - System Files",
  "total_events": 120,
  "recommendation": "IMMEDIATE ACTION: Block IP at firewall, patch command injection vulnerability"
}
```

Future work: Define canonical schema as part of API standardization effort.

### 3. Alert Deduplication Strategy

**Context:** Same attacker IP may trigger multiple critical signatures. We need to decide whether to send separate emails or consolidate into single alert.

**Options:**
- **Option A: One Email Per Signature**
  - Pros: 
    - Complete information per threat type
    - Easy to implement
    - Clear separation of concerns
  - Cons: 
    - Email flooding for sophisticated attacks (10+ signatures)
    - Alert fatigue
    - Fragmented incident context

- **Option B: Consolidated Attack Report (Group by Source IP)**
  - Pros: 
    - Single comprehensive email per attacker
    - Better incident context ("multi-stage attack from 10.77.0.20")
    - Reduced alert fatigue
  - Cons: 
    - More complex email formatting
    - May delay individual signature alerts
    - Requires time window for grouping (2-5 minutes)

- **Option C: Hybrid (CRITICAL = immediate, HIGH = batched)**
  - Pros: 
    - Balance between urgency and consolidation
    - Respects severity hierarchy
  - Cons: 
    - Complex routing logic
    - Inconsistent user experience

**Recommendation:** **Option B (Consolidated Attack Report)** with 2-minute aggregation window. Email format should include:
- Primary threat (highest severity signature)
- Additional threats list (other signatures from same IP)
- Campaign analysis (relationship between signatures)
- Consolidated recommendation

Implement rate limiting: Maximum 1 email per source IP per 10 minutes, regardless of new signatures detected.

## Lifecycle of Code for Key Use Case

**Use Case:** Batching Agent detects critical command injection attack → Email sent to security team

### Normal Flow

1. **Batching Agent Completes Analysis:**
   - ReAct agent finishes processing alert batch
   - Writes results to `threat_analysis_results` table:
     ```sql
     INSERT INTO threat_analysis_results (batch_id, signature_id, severity, reasoning, created_at, processed)
     VALUES (220, 1000032, 'CRITICAL', '["Command injection...", "120 alerts..."]', NOW(), false);
     ```

2. **Integration Orchestrator Detects New Result:**
   - Polling loop queries database every 30 seconds:
     ```sql
     SELECT * FROM threat_analysis_results WHERE processed = false ORDER BY created_at ASC LIMIT 100;
     ```
   - Finds unprocessed CRITICAL threat for signature 1000032

3. **Data Enrichment:**
   - Orchestrator calls `ThreatAdapter.enrich()`
   - Queries ChromaDB for full alert payload details
   - Queries PostgreSQL `alert_batches` for source IP frequency
   - Constructs Analysis Agent-compatible threat object

4. **Routing Decision:**
   - `AlertRouter.should_send_email()` checks:
     - Severity = CRITICAL ✅
     - Not duplicate (same IP not alerted in last 10 min) ✅
     - Not rate limited (email count < 10 in last hour) ✅
   - Decision: SEND EMAIL

5. **Email Agent Execution:**
   - Calls `send_critical_alert(threat_data, analysis_text)`
   - SMTP connection to configured mail server
   - HTML email sent with threat details + LLM analysis
   - Returns success confirmation

6. **File Writer Execution:**
   - Calls `write_analysis()` and `write_analysis_json()`
   - Saves to `ai-agent/analysis_output/threat_analysis_10_77_0_20_20251025_143022.json`
   - Includes full ReAct execution trace

7. **Mark as Processed:**
   - Updates database:
     ```sql
     UPDATE threat_analysis_results 
     SET processed = true, 
         processed_at = NOW(), 
         email_sent = true, 
         email_recipient = 'security@example.com'
     WHERE id = 12345;
     ```

8. **Logging and Metrics:**
   - Log event to orchestrator logs: `"CRITICAL alert processed: signature 1000032, email sent to security@example.com"`
   - Increment Prometheus counter: `alerts_processed_total{severity="CRITICAL"}`

### Error Scenarios

- **If ChromaDB enrichment fails:** 
  - Log warning: "Enrichment failed for batch_id 220, using basic data only"
  - Proceed with available data from `threat_analysis_results` table
  - Mark enrichment_status = 'partial' in database

- **If SMTP server is down:** 
  - Email agent returns `{success: false, message: "SMTP timeout"}`
  - Orchestrator does NOT mark as processed
  - Retry with exponential backoff (30s, 2m, 5m, 10m)
  - After 4 failed attempts (20 minutes), mark as `processed=true, email_sent=false, error='SMTP failure'`
  - Log to stderr and send to monitoring system
  - Continue processing other threats (fail open, not fail closed)

- **If file write fails (disk full):**
  - Log error: "File write failed: No space left on device"
  - Email still sent (email prioritized over file logging)
  - Mark as `processed=true, file_saved=false, error='Disk full'`
  - Trigger alert to ops team about disk space

- **If transformation fails (invalid data):**
  - Log error with full stack trace
  - Mark as `processed=true, error='Transformation error: missing src_ips'`
  - Save raw batching agent output to error queue for manual review
  - Continue processing next threat

- **If duplicate detection fails (Redis down):**
  - Fall back to in-memory deduplication (last 100 processed threats)
  - Log warning: "Redis unavailable, using fallback dedup"
  - Accept risk of duplicate emails for 10-minute restart window

## Detailed Design

### Schema Updates

```sql
-- New table to store batching agent analysis results
CREATE TABLE threat_analysis_results (
    id SERIAL PRIMARY KEY,
    batch_id INTEGER REFERENCES alert_batches(batch_id) ON DELETE CASCADE,
    signature_id INTEGER NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('FALSE_POSITIVE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reasoning JSONB NOT NULL,  -- Array of reasoning strings
    attack_type TEXT,          -- Human-readable attack description
    src_ips JSONB,             -- {"10.77.0.20": 120, ...} - IP to count mapping
    recommendation TEXT,       -- Actionable recommendation
    
    -- Processing tracking
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    processed BOOLEAN NOT NULL DEFAULT false,
    processed_at TIMESTAMP,
    
    -- Delivery tracking
    email_sent BOOLEAN DEFAULT false,
    email_recipient TEXT,
    file_saved BOOLEAN DEFAULT false,
    file_path TEXT,
    
    -- Error handling
    retry_count INTEGER DEFAULT 0,
    error TEXT,
    
    -- Metadata
    enrichment_status VARCHAR(20) DEFAULT 'pending',  -- pending, complete, partial, failed
    
    CONSTRAINT unique_batch_signature UNIQUE(batch_id, signature_id)
);

-- Indexes for performance
CREATE INDEX idx_threat_analysis_processed ON threat_analysis_results(processed, created_at);
CREATE INDEX idx_threat_analysis_severity ON threat_analysis_results(severity, created_at);
CREATE INDEX idx_threat_analysis_batch ON threat_analysis_results(batch_id);

-- State tracking table for orchestrator
CREATE TABLE integration_state (
    id SERIAL PRIMARY KEY,
    orchestrator_instance TEXT NOT NULL,  -- Hostname for multi-instance deployments
    last_poll_time TIMESTAMP NOT NULL,
    last_processed_id INTEGER,
    status VARCHAR(20) NOT NULL,  -- running, stopped, error
    error_message TEXT,
    heartbeat TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT unique_instance UNIQUE(orchestrator_instance)
);

-- Alert deduplication tracking (time-series data)
CREATE TABLE alert_dedupe_log (
    id SERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    signature_id INTEGER NOT NULL,
    severity VARCHAR(20) NOT NULL,
    alerted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    threat_analysis_result_id INTEGER REFERENCES threat_analysis_results(id),
    
    -- Automatically clean up entries older than 24 hours
    CONSTRAINT check_recent CHECK (alerted_at > NOW() - INTERVAL '24 hours')
);

CREATE INDEX idx_dedupe_src_ip ON alert_dedupe_log(src_ip, alerted_at DESC);
```

### API Endpoints

**Note:** The integration orchestrator is primarily a backend service, but we expose some endpoints for monitoring and manual control.

#### `POST /api/v1/integration/trigger`

**Description:** Manually trigger integration processing (for testing or emergency runs)

**Request:**
```json
{
  "force": false,          // Process all threats, even if already processed
  "severity_filter": ["CRITICAL", "HIGH"],  // Optional: only process certain severities
  "batch_ids": [220, 221]  // Optional: process specific batches only
}
```

**Response (200 OK):**
```json
{
  "status": "success",
  "processed_count": 3,
  "email_sent_count": 2,
  "errors": [],
  "processing_time_seconds": 4.2
}
```

**Error Response (503 Service Unavailable):**
```json
{
  "error": "orchestrator_busy",
  "message": "Integration orchestrator is already processing. Try again in 30 seconds.",
  "retry_after": 30
}
```

#### `GET /api/v1/integration/status`

**Description:** Get current orchestrator health and processing status

**Response (200 OK):**
```json
{
  "status": "healthy",
  "last_poll_time": "2025-10-25T14:30:22Z",
  "unprocessed_threats": 0,
  "last_24h_stats": {
    "total_processed": 47,
    "emails_sent": 12,
    "critical_threats": 3,
    "high_threats": 9,
    "errors": 0
  },
  "current_backlog": 0,
  "average_processing_time_ms": 1850
}
```

#### `POST /api/v1/integration/reprocess/{threat_id}`

**Description:** Reprocess a specific threat (e.g., after fixing email configuration)

**Request:**
```json
{
  "force_email": true,  // Send email even if already sent
  "skip_deduplication": true  // Bypass dedup checks
}
```

**Response (200 OK):**
```json
{
  "status": "reprocessed",
  "threat_id": 12345,
  "email_sent": true,
  "file_saved": true
}
```

### Services / Business Logic

#### Integration Orchestrator (`integration_orchestrator.py`)

```python
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from dataclasses import dataclass

from threat_adapter import ThreatAdapter
from alert_router import AlertRouter
from enhanced_file_writer import EnhancedFileWriter
from email_agent import send_critical_alert
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

@dataclass
class ThreatAnalysisResult:
    """Data model for batching agent output"""
    id: int
    batch_id: int
    signature_id: int
    severity: str
    reasoning: List[str]
    attack_type: str
    src_ips: Dict[str, int]
    recommendation: str
    created_at: datetime

class IntegrationOrchestrator:
    """
    Main coordinator service that bridges batching agent and analysis agents.
    
    Responsibilities:
    - Poll database for new threat analysis results
    - Transform data using ThreatAdapter
    - Route threats using AlertRouter
    - Execute downstream agents (email, file writer)
    - Track processing state and handle retries
    """
    
    def __init__(self, 
                 db_config: dict,
                 poll_interval_seconds: int = 30,
                 instance_name: str = "orchestrator-1"):
        self.db_config = db_config
        self.poll_interval = poll_interval_seconds
        self.instance_name = instance_name
        
        self.adapter = ThreatAdapter(db_config)
        self.router = AlertRouter(db_config)
        self.file_writer = EnhancedFileWriter()
        
        self._running = False
        self._last_processed_id = 0
        
    def start(self):
        """Start the orchestrator polling loop"""
        self._running = True
        logger.info(f"Orchestrator {self.instance_name} starting...")
        
        # Register instance in database
        self._register_instance()
        
        while self._running:
            try:
                self._update_heartbeat()
                unprocessed = self._fetch_unprocessed_threats()
                
                if unprocessed:
                    logger.info(f"Found {len(unprocessed)} unprocessed threats")
                    for threat in unprocessed:
                        self._process_threat(threat)
                else:
                    logger.debug("No new threats to process")
                
                time.sleep(self.poll_interval)
                
            except KeyboardInterrupt:
                logger.info("Shutdown signal received")
                self._running = False
            except Exception as e:
                logger.error(f"Orchestrator error: {e}", exc_info=True)
                time.sleep(self.poll_interval)
        
        self._unregister_instance()
        logger.info("Orchestrator stopped")
    
    def _fetch_unprocessed_threats(self) -> List[ThreatAnalysisResult]:
        """Query database for threats that haven't been processed"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, batch_id, signature_id, severity, reasoning,
                           attack_type, src_ips, recommendation, created_at
                    FROM threat_analysis_results
                    WHERE processed = false
                      AND retry_count < 5  -- Max 5 retry attempts
                    ORDER BY severity DESC, created_at ASC  -- CRITICAL first
                    LIMIT 50;
                """)
                
                rows = cur.fetchall()
                return [ThreatAnalysisResult(**row) for row in rows]
        finally:
            conn.close()
    
    def _process_threat(self, threat: ThreatAnalysisResult):
        """
        Process a single threat through the integration pipeline.
        
        Steps:
        1. Enrich data using ThreatAdapter
        2. Determine routing using AlertRouter
        3. Execute email agent if needed
        4. Execute file writer
        5. Mark as processed in database
        """
        logger.info(f"Processing threat {threat.id}: signature {threat.signature_id}, severity {threat.severity}")
        
        email_sent = False
        file_saved = False
        error = None
        
        try:
            # Step 1: Transform data
            enriched_threat = self.adapter.transform(threat)
            
            # Step 2: Routing decision
            should_email = self.router.should_send_email(
                severity=threat.severity,
                src_ip=enriched_threat['ip'],
                signature_id=threat.signature_id
            )
            
            # Step 3: Send email if needed
            if should_email:
                try:
                    result = send_critical_alert(
                        threat_data=enriched_threat,
                        analysis_text=self._format_analysis(threat)
                    )
                    email_sent = result['success']
                    
                    if email_sent:
                        logger.info(f"Email sent for threat {threat.id}")
                        self.router.record_alert(enriched_threat['ip'], threat.signature_id, threat.severity)
                    else:
                        logger.error(f"Email failed for threat {threat.id}: {result['message']}")
                        error = result['message']
                        
                except Exception as e:
                    logger.error(f"Email exception for threat {threat.id}: {e}", exc_info=True)
                    error = str(e)
            
            # Step 4: Save to files
            try:
                file_path = self.file_writer.write_enhanced_analysis(
                    threat_data=enriched_threat,
                    analysis_text=self._format_analysis(threat),
                    react_trace=threat.reasoning
                )
                file_saved = True
                logger.info(f"File saved for threat {threat.id}: {file_path}")
            except Exception as e:
                logger.error(f"File write failed for threat {threat.id}: {e}")
                if not error:
                    error = f"File write error: {str(e)}"
            
        except Exception as e:
            logger.error(f"Processing failed for threat {threat.id}: {e}", exc_info=True)
            error = str(e)
        
        finally:
            # Step 5: Mark as processed (even if partial failure)
            self._mark_processed(
                threat_id=threat.id,
                email_sent=email_sent,
                file_saved=file_saved,
                error=error
            )
    
    def _format_analysis(self, threat: ThreatAnalysisResult) -> str:
        """Format threat reasoning into human-readable analysis text"""
        analysis_parts = [
            "## Threat Analysis\n",
            f"**Severity:** {threat.severity}\n",
            f"**Attack Type:** {threat.attack_type}\n\n",
            "### Key Findings:\n"
        ]
        
        for i, reason in enumerate(threat.reasoning, 1):
            analysis_parts.append(f"{i}. {reason}\n")
        
        analysis_parts.append(f"\n### Recommendation:\n{threat.recommendation}")
        
        return "".join(analysis_parts)
    
    def _mark_processed(self, threat_id: int, email_sent: bool, file_saved: bool, error: Optional[str]):
        """Update database to mark threat as processed"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE threat_analysis_results
                    SET processed = true,
                        processed_at = NOW(),
                        email_sent = %s,
                        file_saved = %s,
                        error = %s,
                        retry_count = retry_count + 1
                    WHERE id = %s;
                """, (email_sent, file_saved, error, threat_id))
                conn.commit()
        finally:
            conn.close()
    
    def _register_instance(self):
        """Register orchestrator instance in database"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO integration_state (orchestrator_instance, last_poll_time, status)
                    VALUES (%s, NOW(), 'running')
                    ON CONFLICT (orchestrator_instance) 
                    DO UPDATE SET status = 'running', last_poll_time = NOW();
                """, (self.instance_name,))
                conn.commit()
        finally:
            conn.close()
    
    def _update_heartbeat(self):
        """Update heartbeat timestamp"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE integration_state
                    SET heartbeat = NOW(), last_poll_time = NOW()
                    WHERE orchestrator_instance = %s;
                """, (self.instance_name,))
                conn.commit()
        finally:
            conn.close()
    
    def _unregister_instance(self):
        """Mark instance as stopped"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE integration_state
                    SET status = 'stopped'
                    WHERE orchestrator_instance = %s;
                """, (self.instance_name,))
                conn.commit()
        finally:
            conn.close()


if __name__ == "__main__":
    import os
    
    db_config = {
        'host': os.getenv('POSTGRES_HOST', 'localhost'),
        'port': int(os.getenv('POSTGRES_PORT', 5432)),
        'database': os.getenv('POSTGRES_DB', 'security_monitor'),
        'user': os.getenv('POSTGRES_USER', 'postgres'),
        'password': os.getenv('POSTGRES_PASSWORD', '')
    }
    
    orchestrator = IntegrationOrchestrator(db_config)
    orchestrator.start()
```

#### Threat Adapter (`threat_adapter.py`)

```python
from typing import Dict, List
from datetime import datetime
import json
import psycopg2
from psycopg2.extras import RealDictCursor

class ThreatAdapter:
    """
    Transforms batching agent output format to analysis agent input format.
    Also enriches data with additional context from ChromaDB and PostgreSQL.
    """
    
    def __init__(self, db_config: dict):
        self.db_config = db_config
    
    def transform(self, threat_result) -> dict:
        """
        Transform batching agent result to analysis agent format.
        
        Input (batching agent):
        {
            "signature_id": 1000032,
            "severity": "CRITICAL",
            "reasoning": ["reason1", "reason2"],
            "src_ips": {"10.77.0.20": 120, "10.77.0.21": 5},
            "attack_type": "Command Injection - System Files",
            "recommendation": "Block IP..."
        }
        
        Output (analysis agent):
        {
            "ip": "10.77.0.20",  # Most active IP
            "severity": "CRITICAL",
            "attack_type": "Command Injection - System Files",
            "total_events": 125,
            "recommendation": "Block IP..."
        }
        """
        
        # Find most active source IP
        if threat_result.src_ips:
            primary_ip = max(threat_result.src_ips.items(), key=lambda x: x[1])
            ip_address = primary_ip[0]
            total_events = sum(threat_result.src_ips.values())
        else:
            # Fallback: query database for batch details
            batch_data = self._get_batch_details(threat_result.batch_id)
            ip_address = list(batch_data.get('src_ips', {}).keys())[0] if batch_data else "Unknown"
            total_events = batch_data.get('alert_count', 0) if batch_data else 0
        
        return {
            "ip": ip_address,
            "severity": threat_result.severity,
            "attack_type": threat_result.attack_type or f"Signature {threat_result.signature_id}",
            "total_events": total_events,
            "recommendation": threat_result.recommendation or self._generate_recommendation(threat_result)
        }
    
    def _get_batch_details(self, batch_id: int) -> dict:
        """Fetch batch metadata from PostgreSQL"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT signature_id, signature, alert_count, src_ips, dst_ips
                    FROM alert_batches
                    WHERE batch_id = %s;
                """, (batch_id,))
                return cur.fetchone()
        finally:
            conn.close()
    
    def _generate_recommendation(self, threat_result) -> str:
        """Generate recommendation based on severity"""
        severity_actions = {
            'CRITICAL': 'IMMEDIATE ACTION: Block IP at firewall, isolate affected systems, initiate incident response',
            'HIGH': 'Block IP, investigate logs, monitor for lateral movement',
            'MEDIUM': 'Monitor closely, review firewall rules, consider IP blocking if pattern continues',
            'LOW': 'Log and monitor, no immediate action required',
            'FALSE_POSITIVE': 'No action required - technology stack mismatch'
        }
        
        return severity_actions.get(threat_result.severity, 'Review and assess')
```

#### Alert Router (`alert_router.py`)

```python
from datetime import datetime, timedelta
import psycopg2
from typing import Optional

class AlertRouter:
    """
    Decision engine for routing threats to appropriate handlers.
    Implements deduplication and rate limiting.
    """
    
    def __init__(self, db_config: dict):
        self.db_config = db_config
        
        # Configuration
        self.email_severities = ['CRITICAL', 'HIGH']
        self.dedup_window_minutes = 10
        self.rate_limit_per_hour = 10
    
    def should_send_email(self, severity: str, src_ip: str, signature_id: int) -> bool:
        """
        Determine if email should be sent for this threat.
        
        Checks:
        1. Severity is CRITICAL or HIGH
        2. Not duplicate (same IP+signature not alerted recently)
        3. Not rate limited (too many emails in last hour)
        """
        
        # Check 1: Severity threshold
        if severity not in self.email_severities:
            return False
        
        # Check 2: Deduplication
        if self._is_duplicate(src_ip, signature_id):
            return False
        
        # Check 3: Rate limiting
        if self._is_rate_limited(src_ip):
            return False
        
        return True
    
    def _is_duplicate(self, src_ip: str, signature_id: int) -> bool:
        """Check if same IP+signature was alerted recently"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM alert_dedupe_log
                    WHERE src_ip = %s::inet
                      AND signature_id = %s
                      AND alerted_at > NOW() - INTERVAL '%s minutes';
                """, (src_ip, signature_id, self.dedup_window_minutes))
                
                count = cur.fetchone()[0]
                return count > 0
        finally:
            conn.close()
    
    def _is_rate_limited(self, src_ip: str) -> bool:
        """Check if too many emails sent for this IP recently"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM alert_dedupe_log
                    WHERE src_ip = %s::inet
                      AND alerted_at > NOW() - INTERVAL '1 hour';
                """, (src_ip,))
                
                count = cur.fetchone()[0]
                return count >= self.rate_limit_per_hour
        finally:
            conn.close()
    
    def record_alert(self, src_ip: str, signature_id: int, severity: str):
        """Record that email was sent for this threat"""
        conn = psycopg2.connect(**self.db_config)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO alert_dedupe_log (src_ip, signature_id, severity, alerted_at)
                    VALUES (%s::inet, %s, %s, NOW());
                """, (src_ip, signature_id, severity))
                conn.commit()
        finally:
            conn.close()
```

### Data Migration Plan

**Migration Strategy:**

1. **Phase 1 - Schema Deployment (Week 1):**
   - Create new tables (`threat_analysis_results`, `integration_state`, `alert_dedupe_log`)
   - Add indexes for performance
   - Deploy schema changes during maintenance window (low-risk, read-only tables)

2. **Phase 2 - Batching Agent Modification (Week 1-2):**
   - Modify batching agent's `react_agent()` function to write results to `threat_analysis_results` table
   - Keep existing behavior (stdout logging) for backward compatibility
   - Deploy as backward-compatible change

3. **Phase 3 - Integration Orchestrator Deployment (Week 2):**
   - Deploy orchestrator as new Docker container
   - Run in shadow mode (process threats but don't send emails)
   - Monitor logs and verify data transformation

4. **Phase 4 - Email Integration (Week 3):**
   - Enable email sending in orchestrator
   - Start with test email addresses
   - Gradually expand to production recipients

5. **Phase 5 - Cleanup (Week 4):**
   - Remove manual threat analysis workflow once proven redundant
   - Archive old `sample_response.json` approach

**Rollback Plan:**

- Orchestrator is stateless - can be stopped without data loss
- New database tables are append-only - can be safely truncated
- Batching agent writes to new table but doesn't depend on it - can revert code change
- Email agent unchanged - continues to work independently

**Estimated Data Volume:**

- Assuming 100 alert batches/day × 10 signatures/batch = 1,000 rows/day in `threat_analysis_results`
- At 1KB/row → ~1MB/day → ~365MB/year (negligible storage impact)
- Dedup log auto-purges after 24 hours → max ~10,000 rows (~100KB)

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Email server outage causes alert backlog | High | Medium | Implement retry queue with exponential backoff. Log all failures to monitoring system. After 5 attempts (20 min), mark as processed and alert ops team via alternate channel (Slack). |
| Database polling causes performance degradation | Medium | Low | Use PostgreSQL LISTEN/NOTIFY for event-driven updates. Add connection pooling (max 5 connections). Index `processed` column for fast queries. |
| Data transformation loses critical context | High | Low | Comprehensive unit tests for `ThreatAdapter`. Log both input and output formats. Include validation checks that fail loudly if required fields are missing. |
| Duplicate emails sent during orchestrator restart | Medium | Medium | Use database-backed deduplication (survives restarts). Add idempotency keys to email records. Track processed IDs in database, not memory. |
| Batching agent and orchestrator schemas drift | Medium | Medium | Version all data structures. Add schema validation tests. Use Alembic migrations for database changes. Automated CI checks for schema compatibility. |
| Orchestrator becomes single point of failure | High | Low | Design stateless orchestrator (can run multiple instances). Use database heartbeat to detect failures. Implement leader election if multi-instance deployment needed. |

### Technical Debt

- **Adapter Pattern Complexity:** Current approach transforms data at integration layer. Future work should define canonical threat schema and migrate all agents to use it (eliminates transformation overhead).

- **Polling vs. Event-Driven:** Initial implementation uses polling for simplicity. Should migrate to PostgreSQL LISTEN/NOTIFY or message queue (RabbitMQ) when alert volume exceeds 100 batches/minute.

- **Monolithic Orchestrator:** All routing logic in single service. Consider splitting into microservices (enrichment service, routing service, delivery service) if deployment patterns become more complex.

- **No Dead Letter Queue:** Failed alerts retry 5 times then dropped. Should implement persistent dead letter queue for manual review and reprocessing.

## Rollout Plan

### Deployment Strategy

- [x] **Feature flag implementation:** 
  - Environment variable `ENABLE_INTEGRATION_ORCHESTRATOR=true` to toggle orchestrator on/off
  - Environment variable `INTEGRATION_EMAIL_MODE=test|production` to control recipient list
  
- [x] **Canary deployment percentage:** 
  - Week 1: 0% (shadow mode - no emails sent, only logging)
  - Week 2: 10% (emails sent to test recipients only, 10% of CRITICAL threats)
  - Week 3: 50% (emails to production recipients, 50% of CRITICAL+HIGH threats)
  - Week 4: 100% (full rollout)
  
- [x] **Full rollout criteria:** 
  - Zero data loss in transformation (audit logs match batching agent output)
  - Email delivery success rate > 95%
  - Average processing latency < 5 seconds from threat creation to email sent
  - No duplicate emails detected in production
  - Ops team approval after 1 week of 50% deployment

### Rollback Plan

**Automated Rollback Triggers:**
- If email failure rate > 10% for 30 consecutive minutes → disable orchestrator, alert on-call
- If database query latency > 5 seconds → reduce poll frequency to 120 seconds
- If unprocessed threat backlog > 500 → pause orchestrator, alert ops team

**Manual Rollback Steps:**
1. Set `ENABLE_INTEGRATION_ORCHESTRATOR=false` in Docker Compose
2. Restart orchestrator container (gracefully finishes in-progress threats)
3. Verify batching agent continues to operate independently
4. Manually process any CRITICAL threats from database using old workflow
5. Review logs to identify root cause
6. Fix issue and re-deploy

**Data Preservation:**
- All threat analysis results remain in `threat_analysis_results` table
- Processed flags prevent reprocessing during rollback
- Can manually trigger reprocessing of specific threats via API

### Monitoring & Alerts

**Key Metrics:**

1. **Processing Metrics:**
   - `integration_threats_processed_total{severity}` (counter) - total threats processed by severity
   - `integration_processing_duration_seconds` (histogram) - time from threat creation to completion
   - `integration_unprocessed_threats` (gauge) - current backlog size

2. **Email Metrics:**
   - `integration_emails_sent_total{status}` (counter) - emails sent (status: success/failure)
   - `integration_email_duration_seconds` (histogram) - SMTP delivery time

3. **Error Metrics:**
   - `integration_errors_total{type}` (counter) - errors by type (transformation, email, database)
   - `integration_retries_total` (counter) - retry attempts

**Alert Thresholds:**

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Email Delivery Failure | Email failure rate > 10% for 15 min | Critical | Page on-call engineer. Check SMTP server status. |
| Processing Backlog | Unprocessed threats > 100 | High | Alert ops team. Investigate orchestrator health. |
| Database Performance | Query latency > 2 seconds | Medium | Alert database team. Check connection pool. |
| Orchestrator Down | No heartbeat for 5 minutes | Critical | Page on-call. Check container status. |
| Duplicate Emails | Same IP alerted >3 times in 10 min | Medium | Alert team. Check dedup logic. |

**Dashboards:**

- **Integration Orchestrator Dashboard** (Grafana):
  - Processing throughput (threats/minute)
  - Email delivery success rate (%)
  - Processing latency percentiles (p50, p95, p99)
  - Error rate by type
  - Current backlog size
  
- **Threat Analysis Dashboard:**
  - Threats by severity over time
  - Top attacking IPs (by email count)
  - Most common signatures detected
  - Average time-to-alert for CRITICAL threats

## Open Questions

1. **Multi-Instance Orchestrator:** If we deploy multiple orchestrator instances for redundancy, how do we prevent duplicate processing? 
   - **Proposed Answer:** Use PostgreSQL row-level locking (`SELECT ... FOR UPDATE SKIP LOCKED`) or implement leader election with etcd/Consul.

2. **Historical Data Migration:** Should we backfill `threat_analysis_results` table with historical batching agent outputs?
   - **Proposed Answer:** No - start fresh on deployment. Historical data remains in `alert_batches` table for analysis but won't trigger emails.

3. **Email Template Customization:** Should email format be configurable per recipient (some want JSON, some want HTML)?
   - **Proposed Answer:** Phase 2 feature. Initial implementation sends HTML+plaintext. Add recipient preferences table in v2.

4. **Integration with SOAR Platforms:** When should we add support for PagerDuty/Splunk/QRadar?
   - **Proposed Answer:** After 1 month of stable production operation. Design alert router to be pluggable (abstract `AlertHandler` interface).

5. **Rate Limiting Scope:** Should rate limiting be per-IP or global?
   - **Proposed Answer:** Per-IP to avoid missing genuine attacks. Add global rate limit (e.g., 50 emails/hour) as safety net.

## References

- [Batching Agent Architecture Documentation](../ai-agent/batching-agent/README.md)
- [Email Agent Implementation](../ai-agent/email_agent.py)
- [PostgreSQL LISTEN/NOTIFY Documentation](https://www.postgresql.org/docs/current/sql-listen.html)
- [ReAct Agent Pattern Paper](https://arxiv.org/abs/2210.03629)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

