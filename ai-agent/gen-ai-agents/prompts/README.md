# Context Agent Prompt System

## Overview

The Context Agent uses a structured prompt system to provide comprehensive historical context to the LLM for threat classification decisions.

## Files

### 1. `context_analysis_prompt.md`
Main prompt template that guides the LLM through threat classification.

**Purpose:** Provides structured format for LLM analysis with:
- Current threat details
- Historical IP reputation
- Similar threats analysis
- Decision guidelines
- Response format requirements

### 2. `_build_context_prompt()` Function
Located in: `context_agent.py:527-729`

**Purpose:** Dynamically fills the template with actual threat data and context.

## How It Works

### Step 1: Gather Context Data
```python
context_summary = {
    "ip_history": _gather_ip_history(),
    "ip_reputation": _analyze_ip_reputation(),
    "similar_threats": _query_similar_threats()
}
```

### Step 2: Build Prompt
```python
prompt = context_agent._build_context_prompt(
    threat_data=current_threat,
    context_summary=context_summary
)
```

### Step 3: Send to LLM
```python
response = ollama.chat(
    model="llama3.1:8b",
    messages=[{"role": "user", "content": prompt}]
)
```

## Prompt Structure

### Section 1: Current Threat Details
- IP address, attack type, severity, description
- Provides immediate context for what we're analyzing

### Section 2: Historical Context Analysis

#### IP Reputation Analysis
- Reputation score (0.0-1.0)
- Reputation category (malicious/suspicious/neutral/trusted)
- Risk factors (concerns)
- Trust factors (reasons to trust)
- Recommendation (filter/review/escalate)

#### Similar Threats Analysis
- Pattern summary (e.g., "4/5 similar threats were false positives")
- Confidence in pattern match
- Detailed list of top 5 similar threats

#### IP Historical Record
- Total threat count
- Novel IP flag
- False positive rate
- FP pattern detection
- Escalation detection

### Section 3: Decision Guidelines
Clear rules for classification:
- **REAL_THREAT:** Confirmed malicious activity
- **SUSPICIOUS:** Unclear, needs manual review
- **FALSE_POSITIVE:** Benign activity misclassified
- **BENIGN_ANOMALY:** Unusual but legitimate

### Section 4: Response Format
Enforces JSON output with required fields:
- classification
- confidence
- reasoning
- recommendation
- key_evidence

## Helper Functions

### `_format_ip_reputation_summary()`
Converts raw reputation data into readable text:
```
"IP has a reputation score of 0.85 (category: trusted) with 75% confidence based on historical data."
```

### `_format_similarity_summary()`
Summarizes similar threats findings:
```
"Found 5 similar threats with 82% confidence. Pattern suggests false positive (multiple similar FPs found)."
```

### `_format_similar_threats_details()`
Lists top 5 similar threats with details:
```
1. IP: 192.168.1.50 | Attack: SQL Injection | Classification: false_positive | Severity: high | Similarity: 95%
2. IP: 10.0.0.20 | Attack: SQLi | Classification: false_positive | Severity: medium | Similarity: 90%
...
```

### `_build_fallback_prompt()`
Minimal prompt if template loading fails - ensures system continues working even if template file is unavailable.

## Example Output

```markdown
# Context Analysis Prompt Template

You are a cybersecurity expert analyzing a potential threat alert to determine if it's a real threat or a false positive.

## Current Threat Details

**IP Address:** 192.168.1.100
**Attack Type:** SQL Injection
**Severity:** high
**Description:** Malicious SQL query detected in login form
**Timestamp:** 2025-11-20T14:30:00Z

## Historical Context Analysis

### IP Reputation Analysis
IP has a reputation score of 0.85 (category: trusted) with 75% confidence based on historical data.

**Reputation Score:** 0.85 (0.0 = malicious, 1.0 = trusted)
**Reputation Category:** trusted
**Recommendation:** filter

**Risk Factors:**
- None identified

**Trust Factors:**
- Recurring false positive pattern (5 FPs)
- High FP rate (83%)

### Similar Threats Analysis
Found 5 similar threats with 82% confidence. Pattern suggests false positive (multiple similar FPs found).

**Pattern Summary:** 4/5 similar threats were false positives, mostly SQL Injection
**Confidence in Pattern Match:** 0.82

**Top Similar Threats:**

1. IP: 192.168.1.50 | Attack: SQL Injection | Classification: false_positive | Severity: high | Similarity: 95%
2. IP: 10.0.0.20 | Attack: SQLi | Classification: false_positive | Severity: medium | Similarity: 90%
3. IP: 172.16.0.10 | Attack: SQL Attack | Classification: false_positive | Severity: high | Similarity: 85%
4. IP: 192.168.5.25 | Attack: SQL Injection | Classification: false_positive | Severity: medium | Similarity: 80%
5. IP: 10.0.1.100 | Attack: SQLi | Classification: REAL_THREAT | Severity: critical | Similarity: 75%

### IP Historical Record
- **Threat Count:** 6 previous alerts
- **Novel IP:** No
- **False Positive Rate:** 83%
- **Has FP Pattern:** Yes
- **Escalation Detected:** No

## Your Task

Based on the historical context and current threat characteristics, classify this alert...

[Rest of prompt with guidelines and format requirements]
```

## Usage in Context Agent

```python
def analyze_context(self, threat_data: Dict) -> Dict:
    """Main orchestration function."""

    # Gather all context
    ip_history = self._gather_ip_history(threat_data["ip"])
    ip_reputation = self._analyze_ip_reputation(threat_data["ip"], ip_history)
    similar_threats = self._query_similar_threats(threat_data)

    # Build context summary
    context_summary = {
        "ip_history": ip_history,
        "ip_reputation": ip_reputation,
        "similar_threats": similar_threats
    }

    # Build prompt
    prompt = self._build_context_prompt(threat_data, context_summary)

    # Send to LLM for classification
    response = ollama.chat(
        model=self.model,
        messages=[{"role": "user", "content": prompt}],
        format="json"
    )

    # Parse and return classification
    return json.loads(response["message"]["content"])
```

## Benefits

1. **Structured Context:** All relevant historical data presented clearly
2. **Consistent Format:** Same format for every classification decision
3. **Explainable:** Clear reasoning guidelines for LLM
4. **Maintainable:** Template can be updated without code changes
5. **Fallback Safety:** System continues working even if template fails
6. **Human-Readable:** Analysts can review prompts to understand decisions

## Future Enhancements

1. **Multiple Templates:** Different templates for different threat types
2. **Dynamic Guidelines:** Adjust decision thresholds based on operational mode
3. **Confidence Weighting:** Emphasize high-confidence signals more in prompt
4. **A/B Testing:** Compare different prompt formats for accuracy
5. **Localization:** Support multiple languages for international teams
