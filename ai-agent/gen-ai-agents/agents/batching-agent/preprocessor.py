import json
from datetime import datetime, timedelta


# Loads validation_results.json and returns the 'detailed_results' array
def load_validation_results(filepath: str):
    with open(filepath, "r") as f:
        data = json.load(f)
    return data.get("detailed_results", [])

def parse_time(ts: str) -> datetime:
    """Handle Suricata ISO timestamps with +0000 suffix."""
    return datetime.fromisoformat(ts.replace("+0000", "+00:00"))


# Preprocess a single threat entry from validation_results.json
def preprocess_entry(entry: dict):
    threat = entry.get("threat", {})
    analysis = entry.get("analysis", {})
    llm_validation = entry.get("llm_validation", {})
    
    # Extract IP from multiple possible locations
    ip_address = None
    
    # Try src_ips first
    if threat.get('src_ips'):
        ip_address = threat['src_ips'][0] if isinstance(threat['src_ips'], list) else threat['src_ips']
    
    # Fallback to dest_ips
    if not ip_address and threat.get('dest_ips'):
        ip_address = threat['dest_ips'][0] if isinstance(threat['dest_ips'], list) else threat['dest_ips']
    
    # Fallback to direct ip field
    if not ip_address:
        ip_address = threat.get('ip', 'UNKNOWN')
    
    # Extract signature_ids if present
    signature_ids = threat.get('signature_ids', [])
    if not signature_ids and threat.get('rules_violated'):
        # Extract from rules_violated if signature_ids not present
        signature_ids = [rule.get('sid') for rule in threat.get('rules_violated', []) if rule.get('sid')]

    return {
        "ip": ip_address,
        "severity": threat.get("severity"),
        "severity_level": threat.get("severity_level"),
        "confidence_score": threat.get("confidence_score"),
        "attack_type": threat.get("attack_type"),
        "total_events": threat.get("total_events"),
        "rules_violated": threat.get("rules_violated", []),
        "ml_anomalies": threat.get("ml_anomalies", []),
        "timestamps": threat.get("timestamps", []),
        "src_ips": threat.get("src_ips", []),
        "dest_ips": threat.get("dest_ips", []),
        "ports": threat.get("ports", []),
        "signature_ids": signature_ids,  # ✅ Added for analyst agent
        "alerts": threat.get("alerts", []),  # ✅ Preserve original alerts
        "classification": analysis.get("classification"),
        "ml_confidence_score": analysis.get("ml_confidence_score"),
        "feature_analyzer_confidence_score": analysis.get("feature_analyzer_confidence_score"),
        "llm_confidence_score": analysis.get("llm_confidence_score"),
        "reasoning": analysis.get("reasoning"),
        "heuristic_flags": analysis.get("heuristic_flags", []),
        "llm_decision": llm_validation.get("decision"),
        "llm_confidence": llm_validation.get("confidence"),
        "llm_reasoning": llm_validation.get("reasoning"),
        "proceed_to_analysis": llm_validation.get("proceed_to_analysis", True),
        "validator_used": llm_validation.get("validator_used"),
        "llm_latency_ms": llm_validation.get("latency_ms"),
        "llm_errors": llm_validation.get("errors", [])
    }


# Preprocess logs from validation_results.json (accepts dict or filepath)
def preprocess_logs(data_source):
    """
    Preprocess validated threat data.
    
    Args:
        data_source: Either a dict (from Stage 0) or filepath string
    
    Returns:
        List of preprocessed threat entries
    """
    if isinstance(data_source, dict):
        # Direct dict from Stage 0
        entries = data_source.get("detailed_results", [])
    elif isinstance(data_source, str):
        # Filepath
        entries = load_validation_results(data_source)
    else:
        return []
    
    processed = []
    for e in entries:
        preprocessed = preprocess_entry(e)
        if preprocessed and preprocessed.get('ip') != 'UNKNOWN':
            processed.append(preprocessed)
    
    return processed