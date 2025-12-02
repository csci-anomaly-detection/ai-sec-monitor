def build_validation_prompt(threat_data: dict, feature_analyzer_result: dict) -> str:
    """
    Build LLM validation prompt from FeatureAnalyzer results.
    
    Args:
        threat_data: Original threat dictionary with ip, severity, confidence_score, etc.
        feature_analyzer_result: Output from FeatureAnalyzer.analyze_threat() with:
            - classification: "FALSE_POSITIVE", "NEEDS_LLM_REVIEW", "POSSIBLE_THREAT"
            - ml_confidence_score: float
            - feature_analyzer_confidence_score: float
            - reasoning: str
            - heuristic_flags: List[str]
            - analysis_results: {timing, ip_reputation, traffic}
    
    Returns:
        Formatted prompt string for LLM validation
    """
    
    # Extract from FeatureAnalyzer result
    fa_classification = feature_analyzer_result.get("classification", "NEEDS_LLM_REVIEW")
    ml_confidence = feature_analyzer_result.get("ml_confidence_score", 0.5)
    fa_confidence = feature_analyzer_result.get("feature_analyzer_confidence_score", 0.5)
    fa_reasoning = feature_analyzer_result.get("reasoning", "")
    heuristic_flags = feature_analyzer_result.get("heuristic_flags", [])
    analysis_results = feature_analyzer_result.get("analysis_results", {})
    
    # Extract timing analysis
    timing = analysis_results.get("timing", {})
    ip_reputation = analysis_results.get("ip_reputation", {})
    traffic = analysis_results.get("traffic", {})
    
    # Extract original threat data
    ip = threat_data.get("ip", "unknown")
    severity = threat_data.get("severity", "UNKNOWN")
    attack_type = threat_data.get("attack_type", "Unknown")
    total_events = threat_data.get("total_events", 0)
    rules_violated = threat_data.get("rules_violated", [])
    
    # Build prompt sections
    timing_section = f"""
TIMING ANALYSIS:
- Business hours: {timing.get("is_business_hours", False)}
- Maintenance window: {timing.get("is_maintenance_window", False)}
- Weekday: {timing.get("is_weekday", False)}
- Weekend: {timing.get("is_weekend", False)}
- Business hours ratio: {timing.get("business_hours_ratio", 0.0):.2%}
- Activity window: {timing.get("earliest_timestamp", "N/A")} to {timing.get("latest_timestamp", "N/A")}
"""
    
    ip_section = f"""
IP REPUTATION ANALYSIS:
- Source IP: {ip}
- All source IPs internal: {ip_reputation.get("all_src_internal", False)}
- Has external source: {ip_reputation.get("has_external_src", False)}
- Internal-to-internal: {ip_reputation.get("internal_to_internal", False)}
- External-to-internal: {ip_reputation.get("external_to_internal", False)}
- Unique source IPs: {ip_reputation.get("unique_src_ips", 0)}
"""
    
    traffic_section = f"""
TRAFFIC PATTERN ANALYSIS:
- Total events: {total_events}
- High volume: {traffic.get("high_volume", False)}
- Very high volume: {traffic.get("very_high_volume", False)}
- Low volume: {traffic.get("low_volume", False)}
- High request rate: {traffic.get("high_request_rate", False)}
- Burst activity: {traffic.get("burst_activity", False)}
- Has high severity rules: {traffic.get("has_high_severity_rules", False)}
- Rule violation count: {traffic.get("rule_violation_count", 0)}
- High success rate: {traffic.get("high_success_rate", False)}
"""
    
    heuristic_section = f"""
HEURISTIC FLAGS DETECTED:
{chr(10).join(f"- {flag}" for flag in heuristic_flags) if heuristic_flags else "- None"}
"""
    
    prompt = f"""You are a cybersecurity anomaly validator. Your job is to make the final classification decision after heuristic pre-filtering.

═══════════════════════════════════════════════════════════════
ORIGINAL THREAT DATA
═══════════════════════════════════════════════════════════════

- IP Address: {ip}
- Attack Type: {attack_type}
- Severity: {severity}
- Total Events: {total_events}
- ML Confidence Score: {ml_confidence:.2f}
- Rules Violated: {len(rules_violated)} rule(s)

═══════════════════════════════════════════════════════════════
HEURISTIC ANALYSIS RESULTS
═══════════════════════════════════════════════════════════════

FeatureAnalyzer Classification: {fa_classification}
FeatureAnalyzer Confidence: {fa_confidence:.2f}
FeatureAnalyzer Reasoning: {fa_reasoning if fa_reasoning else "No specific reasoning provided"}
{timing_section}
{ip_section}
{traffic_section}
{heuristic_section}

═══════════════════════════════════════════════════════════════
YOUR TASK: FINAL CLASSIFICATION
═══════════════════════════════════════════════════════════════

The FeatureAnalyzer has classified this as "{fa_classification}". Your job is to review this classification and make the final decision.

Classify into ONE of these categories:

1. REAL_THREAT: Malicious activity requiring immediate analysis
   - Indicators: Attack signatures, malicious payloads, persistent suspicious behavior
   - Even if timing seems normal, if attack indicators are present, classify as REAL_THREAT
   
2. SUSPICIOUS: Ambiguous case needing closer examination
   - Indicators: Some concerning patterns but not clearly malicious
   - Default choice when uncertain - better safe than sorry
   
3. FALSE_POSITIVE: Benign anomaly incorrectly flagged by ML
   - Indicators: Maintenance windows, known safe patterns, honeypot noise
   - Clear benign explanation (e.g., scheduled backup, legitimate traffic spike)
   
4. BENIGN_ANOMALY: Unusual but legitimate behavior
   - Indicators: Traffic spike during expected times (login windows, business hours)
   - Log for trending but not a security concern

═══════════════════════════════════════════════════════════════
DECISION GUIDELINES
═══════════════════════════════════════════════════════════════

Consider the FeatureAnalyzer classification:

- If FeatureAnalyzer says "FALSE_POSITIVE": 
  → Confirm if reasoning is sound, or upgrade to BENIGN_ANOMALY/SUSPICIOUS if context suggests otherwise
  
- If FeatureAnalyzer says "POSSIBLE_THREAT":
  → Evaluate if indicators are strong enough for REAL_THREAT or should be SUSPICIOUS
  
- If FeatureAnalyzer says "NEEDS_LLM_REVIEW":
  → This is why you're here - make the final call based on all available context

TIMING FACTORS:
- Business hours + internal traffic = likely BENIGN_ANOMALY or FALSE_POSITIVE
- Off-hours + external IP = more suspicious
- Maintenance window activity = likely FALSE_POSITIVE

TRAFFIC FACTORS:
- High volume + high success rate (90%+) = likely legitimate traffic
- High volume + low success rate = likely attack
- External IP + high severity rules = likely REAL_THREAT

CONFIDENCE FACTORS:
- ML confidence < 0.2 AND clear benign indicators = FALSE_POSITIVE
- ML confidence > 0.7 AND attack indicators = REAL_THREAT
- Mixed signals = SUSPICIOUS

═══════════════════════════════════════════════════════════════
REQUIRED OUTPUT FORMAT
═══════════════════════════════════════════════════════════════

Respond with JSON only (no markdown, no explanation outside JSON):

{{
  "decision": "REAL_THREAT" | "SUSPICIOUS" | "FALSE_POSITIVE" | "BENIGN_ANOMALY",
  "confidence": 0.00-1.00,
  "reasoning": "Brief 2-3 sentence explanation of why this classification",
  "proceed_to_analysis": true | false
}}

IMPORTANT:
- "proceed_to_analysis": true only for REAL_THREAT and SUSPICIOUS
- "proceed_to_analysis": false for FALSE_POSITIVE and BENIGN_ANOMALY
- Be conservative: When in doubt, choose SUSPICIOUS (fail-open approach)
- Confidence should reflect certainty: 0.9+ = very sure, 0.5-0.7 = uncertain
- Consider both ML confidence ({ml_confidence:.2f}) and FeatureAnalyzer confidence ({fa_confidence:.2f}) when setting your confidence

Begin your analysis now. Return JSON only."""
    
    return prompt