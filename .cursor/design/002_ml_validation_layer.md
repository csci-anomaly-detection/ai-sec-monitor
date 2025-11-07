# ML Validation Layer Design Document

## Metadata
- **Status:** Draft
- **Author(s):** AI Security Monitor Team
- **Reviewers:** TBD
- **Created:** 2025-10-27
- **Updated:** 2025-10-27
- **Implementation PR(s):** TBD

## Overview

The AI Security Monitor's Isolation Forest model (in `detect/anomaly.py`) currently generates anomalies that flow directly into the threat correlation and analysis pipeline. This model has proven effective at detecting unusual patterns but suffers from false positives - benign anomalies that match attack-like behavior (e.g., legitimate traffic spikes, scheduled maintenance, honeypot noise).

**The Problem:** Without validation, these false positives:
- Consume analyst time reviewing non-threats
- Trigger alert fatigue in the email notification system
- Waste LLM compute cycles on false alarms
- Reduce trust in the automated detection system

**Why Now:** With the system processing real-time alerts from Suricata through sliding window analysis, false positive reduction becomes critical for operational efficiency. The current system can generate dozens of anomalies per hour, and each false positive wastes downstream processing resources.

## Goals

### Primary Goals
1. **Reduce False Positive Rate**: Filter out at least 40-60% of ML-generated false positives before they reach analysis agents
2. **Maintain True Positive Rate**: Ensure real threats still reach the analysis pipeline with >95% detection rate
3. **Add Explainability**: Provide reasoning for why anomalies were filtered or approved
4. **Minimal Latency**: Keep validation overhead under 500ms per anomaly

### Secondary Goals
5. **Configurable Sensitivity**: Allow tuning of validation strictness based on operational needs
6. **Learning Capability**: Build foundation for future active learning/feedback loops
7. **Graceful Degradation**: System continues operating if validation service is unavailable

### Non-Goals
- Retraining the Isolation Forest model (separate ML improvement effort)
- Replacing human analyst review (validation is pre-filtering, not replacement)
- Real-time blocking (validation is for alerting, not automatic response)

## Proposed Solution

### High-Level Approach

We will implement a **two-tier validation layer** that sits between the Isolation Forest anomaly detector and the ThreatCorrelator. This layer uses heuristic analysis and lightweight LLM validation to separate real threats from false positives.

**Approach 1A - Single Agent Validation** will be implemented initially for speed and simplicity. This uses one lightweight LLM agent to quickly classify anomalies. **Approach 1B - Multi-Agent Validation** will be designed as a future enhancement for scenarios requiring higher precision or when single agent validation proves insufficient.

The validation layer acts as a smart filter, examining anomalies flagged by ML and using contextual understanding to distinguish between:
- **REAL_THREAT**: Malicious activity requiring immediate analysis
- **SUSPICIOUS**: Ambiguous case that needs closer examination
- **FALSE_POSITIVE**: Benign anomaly (maintenance, known patterns, honeypot noise)
- **BENIGN_ANOMALY**: Unusual but legitimate behavior (log for trending)

### Key Components

- **AnomalyValidator**: Main entry point that receives anomalies from Isolation Forest
- **FeatureAnalyzer**: Heuristic validation that filters obvious false positives based on feature patterns
- **LLMValidator**: Lightweight validation agent that uses Llama 3.2 for contextual analysis
- **ValidationStore**: Database table to track validation decisions for learning and audit
- **ValidationStats**: Metrics collection for monitoring false positive rates and accuracy

### Simple Architecture Diagram

#### Approach 1A: Single Agent Validation (Initial Implementation)

```
┌───────────────────────────────────────────────────────────────────┐
│                    Isolation Forest (ML Model)                    │
│               detect_anomalies_advanced() generates               │
│              anomaly score + suspicious features                  │
└────────────────────┬──────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ANOMALY VALIDATION LAYER (1A)                          │
│                                                                     │
│  ┌──────────────────┐         ┌──────────────────┐                  │
│  │ FeatureAnalyzer  │────────▶│  LLMValidator    │                  │
│  │  (Heuristics)    │         │  (Single Agent)  │                  │
│  │                  │         │                  │                  │
│  │ • Feature        │         │ • Context check  │                  │
│  │   analysis       │         │ • Pattern match  │                  │
│  │ • Z-score        │         │ • Time of day    │                  │
│  │   filtering      │         │ • Known IPs      │                  │
│  └──────────────────┘         └──────────────────┘                  │
│           │                              │                          │
│           └────────────┬─────────────────┘                          │
│                        ▼                                            │
│              Classification Decision                                │
│   ├─ REAL_THREAT    (→ Full analysis pipeline)                      │
│   ├─ SUSPICIOUS     (→ Full analysis, lower confidence)             │
│   ├─ FALSE_POSITIVE (→ Archive only, no alert)                      │
│   └─ BENIGN_ANOMALY (→ Log for trending)                            │
└────────────────────┬────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ThreatCorrelator (Existing Component)                  │
│              Combines validated anomalies with rule alerts          │
└────────────────────┬─────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│            Analysis Agents + Email Agent (Existing)                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Characteristics:**
- Single LLM call per anomaly (~200-500ms latency)
- One agent makes final decision
- Heuristics pre-filter obvious false positives
- Lower cost and simpler to maintain

#### Approach 1B: Multi-Agent Validation (Future Enhancement)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Isolation Forest (ML Model)                     │
│               detect_anomalies_advanced() generates                │
│              anomaly score + suspicious features                    │
└────────────────────┬──────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│          ANOMALY VALIDATION LAYER (1B - Multi-Agent)               │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │   Feature    │  │   Context    │  │    Attack    │            │
│  │   Analyzer   │  │    Agent     │  │   Pattern    │            │
│  │   Agent      │  │              │  │    Agent     │            │
│  │              │  │              │  │              │            │
│  │ • Stats      │  │ • Time of    │  │ • Match      │            │
│  │   analysis   │  │   day check  │  │   attack     │            │
│  │ • Z-scores   │  │ • IP history │  │   signatures │            │
│  │ • Outliers   │  │ • Known      │  │ • Behavioral │            │
│  │              │  │   patterns   │  │   anomalies  │            │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│         │                 │                 │                      │
│         └─────────┬────────┴────────┬────────┘                      │
│                   │                │                                │
│            ┌──────▼─────────────────▼────┐                          │
│            │    Consensus Agent         │                          │
│            │  (weighs all opinions)    │                          │
│            │  • 2-of-3 majority        │                          │
│            │  • Confidence weighting   │                          │
│            │  • Conflict resolution     │                          │
│            └────────────┬───────────────┘                          │
│                         ▼                                            │
│              Classification Decision                                │
│   ├─ REAL_THREAT    (→ Full analysis pipeline)                      │
│   ├─ SUSPICIOUS     (→ Full analysis, lower confidence)            │
│   ├─ FALSE_POSITIVE (→ Archive only, no alert)                     │
│   └─ BENIGN_ANOMALY (→ Log for trending)                            │
└────────────────────┬─────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ThreatCorrelator (Existing Component)                  │
│              Combines validated anomalies with rule alerts          │
└────────────────────┬─────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│            Analysis Agents + Email Agent (Existing)                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Characteristics:**
- Multiple LLM calls per anomaly (~800-2000ms latency)
- Three specialized agents analyze from different perspectives
- Consensus agent combines opinions with weighted voting
- Higher accuracy but more expensive and complex

## Design Considerations

### 1. Validation Architecture: Single vs Multi-Agent

**Context:** Need to balance accuracy, latency, and complexity in the validation decision-making process.

**Options:**

**Option 1A: Single LLM Validator Agent**
- **Pros:**
  - Low latency (~200-500ms per anomaly)
  - Simple implementation and maintenance
  - Lower operational cost (1 LLM call per anomaly)
  - Easy to tune with prompt engineering
  - Sufficient for majority of cases
- **Cons:**
  - May miss nuanced multi-feature anomalies
  - Single point of reasoning (no cross-validation)
  - Less explainable for complex decisions
  - Prompt quality critical for accuracy

**Option 1B: Multi-Agent Validation System**
- **Pros:**
  - Higher accuracy through multiple perspectives
  - More explainable (shows reasoning from each agent)
  - Better handling of complex edge cases
  - Can use specialized agents for different attack types
- **Cons:**
  - Higher latency (800-2000ms per anomaly)
  - More complex implementation (4+ agents, coordination logic)
  - Higher cost (4+ LLM calls per anomaly)
  - Potential for agent disagreement requiring consensus logic
  - Best for lower-volume, high-stakes scenarios

**Recommendation:** **Implement Option 1A (Single Agent) initially**, with architecture designed to support upgrade to Option 1B if needed. This provides immediate value with manageable complexity. Option 1B can be added later if analysis shows single agent validation has >20% false positive rate remaining after implementation.

### 2. Heuristic Pre-Filtering: Before or Instead of LLM?

**Context:** LLM calls are expensive and add latency. We can reduce volume by pre-filtering obvious false positives.

**Options:**

**Option 2A: Heuristic-Only Validation**
- Use heuristics to filter obvious false positives, pass everything else through
- No LLM validation
- **Pros:** Ultra-fast (<1ms), zero LLM costs, fully transparent
- **Cons:** Will miss nuanced false positives, requires extensive rule engineering

**Option 2B: LLM-Only Validation**
- Skip heuristics, use LLM for all anomalies
- **Pros:** Catches nuanced cases, no rule maintenance needed
- **Cons:** Slow, expensive, LLM overkill for obvious cases

**Option 2C: Heuristic + LLM (Two-Pass Validation)**
- Heuristics catch 60-80% of obvious false positives instantly
- Remaining anomalies go to LLM for nuanced analysis
- Only suspicious cases require LLM processing
- **Pros:** Best of both worlds - fast for obvious cases, accurate for edge cases
- **Cons:** More complex code path, two validation steps

**Recommendation:** **Option 2C (Two-Pass Validation)** - This provides optimal balance between speed, cost, and accuracy. Heuristics handle obvious cases instantly, LLM handles nuanced ones. Total added latency is acceptable for the volume reduction achieved.

### 3. Validation Decision Granularity

**Context:** What level of detail should validation decisions provide?

**Options:**

**Option 3A: Binary (Pass/Reject)**
- Simple boolean: send to analysis pipeline or filter out
- **Pros:** Simple, fast decisions
- **Cons:** No nuance for different threat levels, loses confidence information

**Option 3B: Four-State Classification**
- REAL_THREAT, SUSPICIOUS, FALSE_POSITIVE, BENIGN_ANOMALY
- **Pros:** Preserves nuance, allows downstream systems to adjust confidence
- **Cons:** More complex state management in downstream components

**Option 3C: Confidence Score + Category**
- Classification plus 0.0-1.0 confidence score
- **Pros:** Maximum information for downstream systems, enables dynamic thresholds
- **Cons:** Most complex to implement and maintain

**Recommendation:** **Option 3B (Four-State Classification)** - Provides necessary nuance without excessive complexity. Downstream ThreatCorrelator can use these states to adjust confidence scores. Option 3C could be added later if dynamic confidence thresholding is needed.

### 4. Persistence Strategy: Where to Store Validation Decisions?

**Context:** Need to track what was filtered and why, for learning and auditing.

**Options:**

**Option 4A: In-Memory Only (No Persistence)**
- Validation decisions not stored anywhere
- **Pros:** Zero overhead, simple implementation
- **Cons:** No audit trail, can't learn from patterns, can't analyze accuracy over time

**Option 4B: Log File**
- Write validation decisions to log files
- **Pros:** Simple, human-readable for debugging
- **Cons:** Hard to query/analyze, no structured data

**Option 4C: Database Table**
- Store decisions in PostgreSQL `ml_validation_decisions` table
- **Pros:** Queryable, supports future active learning, audit trail
- **Cons:** Additional database writes, schema management

**Option 4D: Hybrid (Console + Database)**
- Log decisions to console for debugging, store in database for analytics
- **Pros:** Best for operations and future ML improvements
- **Cons:** Some redundancy, more complexity

**Recommendation:** **Option 4C (Database Table)** - The audit trail and future learning capabilities are worth the minimal overhead. Can add console logging as enhancement but don't rely on it as primary persistence mechanism.

## Lifecycle of Code for Key Use Case

**Use Case:** Isolation Forest detects traffic spike anomaly → Validation layer filters false positive → No alert generated

### Normal Flow

1. **Isolation Forest Detection:**
   - `detect_anomalies_advanced()` runs on sliding window of logs
   - Identifies anomaly with score -0.72 in 5-minute window
   - Feature deviations: high request rate (z=3.2), unusual timing pattern (z=2.1)

2. **Validation Layer Receives Anomaly:**
   - Anomaly passed to `AnomalyValidator.validate(anomaly)` with metadata:
     - Anomaly score, suspicious features, time window, raw logs
     - Source IP (192.168.100.50), event count (156 events in 5 minutes)

3. **Feature Analyzer Pre-Filter:**
   - `FeatureAnalyzer` checks anomaly characteristics
   - Determines: This is a legitimate traffic spike (all features point to normal activity during business hours)
   - Decision: Not a clear false positive, needs LLM review

4. **LLM Validator Analysis:**
   - `LLMValidator` receives anomaly for contextual analysis
   - Llama 3.2 model reviews:
     - Time: 14:30 on weekday (business hours)
     - IP: No prior history in threat database
     - Pattern: Sudden spike to 30 req/sec (within normal range for login periods)
     - Response codes: 95% 200 OK, 5% 404
   - LLM determines: "BENIGN_ANOMALY - Legitimate traffic surge during login window"

5. **Validation Decision Stored:**
   - Decision written to `ml_validation_decisions` table:
     - Classification: BENIGN_ANOMALY
     - Reasoning: "Traffic spike during expected login hours, no attack signatures"
     - Confidence: 0.85
     - Timestamp: NOW()

6. **Response to Pipeline:**
   - Validation layer returns: `{decision: "BENIGN_ANOMALY", proceed: false}`
   - Anomaly logged for trending analysis but not sent to ThreatCorrelator
   - No email alert generated

7. **Post-Processing:**
   - Statistics updated: false positive rate tracking
   - If validation decision seems wrong (later analyst feedback), can retrain

### Error Scenarios

**If LLM validator is unavailable:**
- Fallback to heuristic-only validation
- Log warning: "LLM validation disabled, using heuristics only"
- System continues operating with reduced accuracy
- Metrics tracked separately for heuristic vs LLM decisions

**If database write fails:**
- Validation decision still proceeds (don't block pipeline)
- Error logged, attempt retry on next validation cycle
- Consider validation decision if retry fails after 3 attempts

**If validation takes too long (>2 seconds):**
- Timeout occurs, treat as SUSPICIOUS (fail-open approach)
- Log warning about latency
- Trigger alert for monitoring team to investigate validation performance

## Detailed Design

### Schema Updates

```sql
-- Store validation decisions for learning and audit
CREATE TABLE ml_validation_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Anomaly details
    anomaly_score DECIMAL(10, 6) NOT NULL,
    feature_data JSONB NOT NULL,  -- Suspicious features array
    anomaly_timestamp TIMESTAMPTZ NOT NULL,
    
    -- Validation result
    validation_classification VARCHAR(20) NOT NULL,  -- REAL_THREAT, SUSPICIOUS, FALSE_POSITIVE, BENIGN_ANOMALY
    validation_confidence DECIMAL(3, 2) NOT NULL,  -- 0.00 to 1.00
    validation_reasoning TEXT,
    
    -- Tracking
    validator_type VARCHAR(20) DEFAULT 'llm_validator',  -- llm_validator, heuristic_only, multi_agent
    was_correct BOOLEAN,  -- NULL until analyst feedback
    analyst_feedback TEXT,  -- Human override if needed
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for analytics
CREATE INDEX idx_validations_by_classification ON ml_validation_decisions(validation_classification);
CREATE INDEX idx_validations_by_timestamp ON ml_validation_decisions(anomaly_timestamp);
CREATE INDEX idx_validations_by_correct ON ml_validation_decisions(was_correct) WHERE was_correct IS NOT NULL;

-- View for validation statistics
CREATE VIEW validation_stats AS
SELECT 
    validation_classification,
    COUNT(*) as count,
    AVG(validation_confidence) as avg_confidence,
    AVG(anomaly_score) as avg_anomaly_score,
    COUNT(CASE WHEN was_correct = FALSE THEN 1 END) as incorrect_count
FROM ml_validation_decisions
WHERE anomaly_timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY validation_classification;
```

### API Endpoints

#### `POST /api/v1/validation/validate`
**Purpose:** Validate a single anomaly from Isolation Forest

**Request:**
```json
{
  "anomaly_score": -0.72,
  "anomaly_timestamp": "2025-10-27T14:30:00Z",
  "suspicious_features": [
    {"name": "requests_per_minute", "value": 30.5, "z_score": 3.2},
    {"name": "error_rate", "value": 0.05, "z_score": 2.1}
  ],
  "window_logs": [
    {"@timestamp": "...", "src_ip": "192.168.100.50", "status": "200"},
    ...
  ],
  "context": {
    "total_events": 156,
    "time_window_minutes": 5
  }
}
```

**Response (200 OK):**
```json
{
  "decision": "BENIGN_ANOMALY",
  "confidence": 0.85,
  "reasoning": "Traffic spike during expected login hours, normal HTTP response codes",
  "proceed_to_analysis": false,
  "validation_id": "uuid-here",
  "validator_used": "llm_validator"
}
```

**Error Response (4xx/5xx):**
```json
{
  "error": "validation_service_unavailable",
  "message": "LLM validator is unavailable, using heuristic fallback",
  "decision": "SUSPICIOUS",
  "proceed_to_analysis": true
}
```

#### `GET /api/v1/validation/stats`
**Purpose:** Retrieve validation statistics for monitoring

**Response (200 OK):**
```json
{
  "last_24h": {
    "total_validated": 142,
    "real_threats": 23,
    "suspicious": 18,
    "false_positives": 89,
    "benign_anomalies": 12,
    "false_positive_rate": 0.626,
    "avg_confidence": 0.82
  },
  "validator_health": {
    "llm_validator_available": true,
    "avg_latency_ms": 342
  }
}
```

#### `POST /api/v1/validation/feedback`
**Purpose:** Analyst provides feedback to improve validation accuracy

**Request:**
```json
{
  "validation_id": "uuid-here",
  "was_correct": false,
  "correct_classification": "REAL_THREAT",
  "analyst_notes": "This was actually a sophisticated attack that validation missed"
}
```

**Response (200 OK):**
```json
{
  "status": "feedback_recorded",
  "validation_id": "uuid-here"
}
```

### Services / Business Logic

#### Validation Orchestration Flow

**AnomalyValidator** - Main entry point that coordinates validation:
1. Receives anomaly from Isolation Forest with metadata (score, features, logs)
2. Runs FeatureAnalyzer for fast heuristic pre-filtering
3. For ambiguous cases, calls LLMValidator for contextual analysis
4. Stores decision in database for learning and audit
5. Returns classification with confidence and reasoning

**FeatureAnalyzer** - Heuristic pre-filtering:
- Checks for obvious false positive patterns
- Analyzes feature deviations (z-scores, statistical outliers)
- Evaluates HTTP response code distribution
- Checks timing patterns (maintenance windows, business hours)
- Fast decision making (<1ms for most cases)

**LLMValidator** - Single agent validation (Approach 1A):
- Takes anomaly context and suspicious features
- Uses Llama 3.2 model for contextual understanding
- Considers legitimate traffic patterns, known network behavior
- Returns JSON classification with confidence score
- Latency: ~200-500ms per anomaly

**MultiAgentValidator** - Future enhancement (Approach 1B):
- Three specialized agents analyze anomaly in parallel:
  - Feature Analyzer Agent: Statistical analysis
  - Context Agent: Historical patterns, time-of-day, known IPs
  - Attack Pattern Agent: Signature matching, behavioral analysis
- Consensus Agent combines agent opinions with weighted voting
- Latency: ~800-2000ms per anomaly (higher cost, higher accuracy)

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| LLM hallucination creates false negatives | High | Medium | Use conservative thresholds, allow SUSPICIOUS to proceed even if LLM uncertain |
| Validation adds >2s latency | Medium | Low | Use lightweight Llama 3.2, implement timeout fallback, pre-filter with heuristics |
| LLM validator becomes bottleneck | Medium | Low | Batch processing for high-volume periods, async validation queue |
| FeatureAnalyzer heuristics miss novel attacks | Medium | Low | Keep heuristic rules broad, fail-open (let ambiguous cases through) |
| Database storage overhead | Low | Low | Retention policy: archive decisions older than 90 days, keep only for analysis |
| Analyst feedback loop not implemented | Low | High | Phase 1: collect decisions for analysis, Phase 2: implement feedback mechanism |

### Technical Debt
- **No active learning loop initially**: Validation decisions are stored but not used for model retraining yet. Will implement feedback collection in Phase 1, learning algorithm in Phase 2.
- **Single agent architecture**: Multi-agent system is designed but not implemented. Can add later if single agent accuracy is insufficient.
- **No dynamic threshold tuning**: Confidence thresholds are fixed. Future enhancement could tune based on operational metrics.

## Rollout Plan

### Deployment Strategy
- [x] Feature flag implementation (via configuration flag `enable_ml_validation`)
- [ ] Canary deployment: Start with validation in "SUSPICIOUS-only" mode (don't filter anything, just log decisions)
- [ ] Monitor validation accuracy for 48 hours
- [ ] Enable full validation filtering after accuracy validation
- [ ] Full rollout criteria: False positive rate <60%, true positive retention >95%

### Rollback Plan
- Configuration flag allows instant disable: `enable_ml_validation=false`
- If validation causes problems, disable via configuration
- Existing anomalies continue to flow through unmodified path
- No data migration required for rollback

### Monitoring & Alerts
- **Key metrics:**
  - Validation false positive rate (target: <60% reduction)
  - True positive retention rate (target: >95%)
  - LLM validator latency (p95, p99)
  - LLM validator availability/error rate
  - Validation decision distribution (REAL_THREAT vs filtered)
  
- **Alert thresholds:**
  - LLM validator unavailable for >5 minutes
  - Validation latency p99 >2 seconds
  - True positive retention rate drops below 90%
  - Validation accuracy dips below established baseline
  
- **Dashboards:**
  - Validation effectiveness (before/after comparison)
  - Anomaly volume filtered vs proceeding
  - LLM validator performance metrics
  - False positive reduction trend over time

## Open Questions

1. **What's the acceptable latency budget?** Current target is <500ms. Is this acceptable for operational needs?

2. **Should we implement validation bypass for known low-risk IPs?** Could add allowlist feature where certain IPs/networks skip validation for performance.

3. **What's the retention policy for validation decisions?** Proposing 90 days for operational data, 1 year for analytics.

4. **How should we handle analyst feedback?** Phase 1: Just store feedback, Phase 2: Train secondary model on feedback data.

5. **Should multi-agent system be implemented in Phase 1 or later?** Recommendation: Later, but architecture supports it.

## References
- Existing Isolation Forest implementation: `detect/anomaly.py`
- Threat correlation logic: `detect/threat_correlator.py`
- Agent architecture: `ai-agent/agents.py`
- Integration design: `.cursor/design/001_agent_integration.md`

