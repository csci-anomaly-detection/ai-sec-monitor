import argparse
import json
from typing import Optional, Dict, List, Any, Union
from pathlib import Path
import yaml  # type: ignore
from datetime import datetime, timedelta, UTC
import pickle  # Add this at the top

from . import anomaly
from .data_sources import LokiDataSource  # New import
from .threat_correlator import ThreatCorrelator, format_threat_report
from .training_manager import TrainingDataManager  # Fixed import

RULES_PATH = Path(__file__).parent / "rules.yaml"
DEFAULT_FIXTURE_PATH = Path(__file__).parent / "tests" / "fixtures" / "logs.ndjson"

with open(RULES_PATH, "r") as f:
    rules = yaml.safe_load(f)["rules"]

def parse_ts(ts: str) -> Optional[datetime]:
    if ts.endswith("Z"):
        ts = ts[:-1]
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt

def in_time_window(log: Dict[str, Any], cutoff: datetime, window: timedelta) -> bool:
    """Check if log is within the time window (cutoff - window, cutoff]"""
    raw = log.get("@timestamp")
    if not raw:
        return False
    dt = parse_ts(raw)
    if not dt:
        return False
    
    # Check if log is within the window
    window_start = cutoff - window
    return window_start <= dt <= cutoff

def matches_pattern(val: Any, pattern: str) -> bool:
    s = str(val)
    if pattern == "5xx":
        return s.isdigit() and len(s) == 3 and s.startswith("5")
    if pattern.endswith("xx") and len(pattern) == 3:
        return s.isdigit() and s.startswith(pattern[0])
    return s == pattern

def numeric_compare(v: Any, op: str, target: float) -> bool:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return False
    return {
        ">=": n >= target,
        ">": n > target,
        "<=": n <= target,
        "<": n < target,
        "==": n == target
    }.get(op, False)

def parse_time_window(window_str: str) -> timedelta:
    """Parse time window strings like '5m', '1h', '30s' into timedelta objects"""
    if not window_str:
        return timedelta(minutes=5)  # default
    
    # Extract number and unit
    import re
    match = re.match(r'(\d+)([smhd])', window_str.lower())
    if not match:
        return timedelta(minutes=5)  # default fallback
    
    value, unit = match.groups()
    value = int(value)
    
    if unit == 's':
        return timedelta(seconds=value)
    elif unit == 'm':
        return timedelta(minutes=value)
    elif unit == 'h':
        return timedelta(hours=value)
    elif unit == 'd':
        return timedelta(days=value)
    else:
        return timedelta(minutes=5)  # fallback

# Initialize training manager at module level
training_manager = TrainingDataManager()

def evaluate_rule(rule: Dict[str, Any], logs: List[Dict[str, Any]], now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    if now is None:
        now = datetime.now(UTC)
    
    cond = rule["condition"]
    rtype = cond.get("type")
    
    if rtype == "count":
        field = cond["field"]
        threshold = cond["threshold"]
        window_str = cond["window"]
        
        # Don't apply additional time window filtering for historical analysis
        window_logs = logs  # Use all logs from the query timeframe
        
        # Apply field matching
        matched_logs = []
        for log in window_logs:
            field_value = log.get(field)
            
            if field_value is None:
                continue
                
            # Handle different matching types
            if "match" in cond:
                # Pattern matching
                import re
                if re.match(cond["match"], str(field_value)):
                    matched_logs.append(log)
            elif "op" in cond and "value" in cond:
                # Numeric comparison
                try:
                    if cond["op"] == ">=" and int(field_value) >= cond["value"]:
                        matched_logs.append(log)
                except (ValueError, TypeError):
                    continue
        
        # Only print if there's a match
        if len(matched_logs) >= threshold:
            print(f"  → Found {len(matched_logs)} matches (threshold: {threshold})")
            return {
                "rule_id": rule["id"],
                "description": rule["description"],
                "severity": rule["severity"],
                "count": len(matched_logs),
                "threshold": threshold,
                "window": window_str,
                "matches": matched_logs[:10]
            }
    
    elif rtype == "group_count":
        field = cond["field"]
        group_by = cond["group_by"]
        threshold = cond["threshold"]
        window_str = cond["window"]
        
        window_logs = logs
        
        # Group by specified field and count matches
        from collections import defaultdict
        groups = defaultdict(list)
        
        for log in window_logs:
            field_value = log.get(field)
            if "match" in cond and field_value and str(field_value) == cond["match"]:
                group_key = log.get(group_by)
                if group_key:
                    groups[group_key].append(log)
        
        # Only print significant findings
        for group_key, group_logs in groups.items():
            if len(group_logs) >= threshold:
                print(f"  → Group {group_key}: {len(group_logs)} events (threshold: {threshold})")
                return {
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "group": group_key,
                    "count": len(group_logs),
                    "threshold": threshold,
                    "window": window_str,
                    "matches": group_logs[:10]
                }
    
    elif rtype == "anomaly":
        # SIMPLIFIED - no verbose logging
        if not training_manager.trained_models:
            training_manager._load_models()
        
        if training_manager.trained_models:
            anomalies = training_manager.predict_with_trained_models(logs)
            
            threshold = cond.get("threshold", 1)
            if anomalies and len(anomalies) >= threshold:
                return {
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "anomalies_detected": len(anomalies),
                    "detection_method": "trained_models"
                }
        else:
            # Fallback to unsupervised (keep existing logic)
            features = cond.get("features", ["src_ip", "dest_port"])
            contamination = cond.get("contamination", 0.1)
            
            result = anomaly.run_isolation_forest(logs, contamination, features)
            
            if result:
                return {
                    "rule_id": rule["id"],
                    "description": rule["description"], 
                    "severity": rule["severity"],
                    "anomaly_score": result["most_severe_score"],
                    "anomalies_detected": result["anomalies_detected"],
                    "detection_method": "unsupervised"
                }
    
    return None

def run_rules_on_live_data(logs: List[Dict[str, Any]], now: datetime = None) -> Dict[str, Any]:
    """Apply rules to live Loki data and correlate threats"""
    if now is None:
        now = datetime.now(UTC)
    
    print(f"Running {len(rules)} rules on {len(logs)} live logs")
    
    # SIMPLIFIED: Only train if absolutely necessary
    if not training_manager.trained_models:
        training_manager._load_models()  # Try loading first
        
        if not training_manager.trained_models:  # Only then train
            from .data_sources import LokiDataSource
            loki = LokiDataSource()
            training_manager.train_baseline_models(loki)
    
    # Run all rules (both traditional and ML)
    rule_alerts = []
    
    for rule in rules:
        try:
            print(f"Applying rule: {rule['id']}")
            
            alert = evaluate_rule(rule, logs, now)
            if alert:
                rule_alerts.append(alert)
                detection_method = alert.get('detection_method', 'traditional')
                print(f"✓ {rule['id']} generated 1 alert ({detection_method})")
            else:
                print(f"  {rule['id']} - no matches")
                
        except Exception as e:
            print(f"✗ Error in rule {rule['id']}: {e}")
    
    # Correlate threats by IP
    correlator = ThreatCorrelator()
    threats = correlator.correlate_threats(rule_alerts, [], logs)  # Empty ml_results since it's all in rule_alerts now
    
    # Generate threat report
    threat_report = format_threat_report(threats)
    print("\n" + threat_report)
    
    print(f"\nTotal alerts generated: {len(rule_alerts)}")
    
    # Convert threats to JSON-serializable format
    serializable_threats = []
    for threat in threats:
        serializable_threats.append({
            'ip': threat.ip,
            'rules_violated': threat.rules_violated,
            'ml_anomalies': threat.ml_anomalies,
            'severity': threat.severity.name,
            'severity_level': threat.severity.value,
            'confidence_score': threat.confidence_score,
            'attack_type': threat.attack_type,
            'recommendation': threat.recommendation,
            'total_events': threat.total_events
        })
    
    return {
        'individual_alerts': rule_alerts,
        'correlated_threats': serializable_threats,
        'threat_report': threat_report,
        'threat_count': len(threats),
        'high_severity_threats': len([t for t in threats if t.severity.value >= 3])
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--now", help="ISO time (e.g. 2025-09-10T10:00:00Z)")
    ap.add_argument("--fixtures", help="Path to fixture file")
    args = ap.parse_args()
    override = None
    if args.now:
        iso = args.now.rstrip("Z")
        override = datetime.fromisoformat(iso)
        if override.tzinfo is None:
            override = override.replace(tzinfo=UTC)
        else:
            override = override.astimezone(UTC)
    alerts = run_all_rules(now=override, fixture_file=args.fixtures)
    print(json.dumps(alerts, indent=2))

if __name__ == "__main__":
    main()