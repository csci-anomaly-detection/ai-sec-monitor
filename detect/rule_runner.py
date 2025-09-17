import argparse
import json
from typing import Optional, Dict, List, Any, Union
from pathlib import Path
import yaml # type: ignore
from datetime import datetime, timedelta, UTC
import os

from . import anomaly

RULES_PATH = Path(__file__).parent / "rules.yaml"
DEFAULT_FIXTURE_PATH = Path(__file__).parent / "tests" / "fixtures" / "logs.ndjson"

with open(RULES_PATH, "r") as f:
    rules = yaml.safe_load(f)["rules"]

def load_logs(filename: Union[str, Path] = DEFAULT_FIXTURE_PATH) -> List[Dict[str, Any]]:
    p = Path(filename)
    if not p.exists():
        raise FileNotFoundError(p)
    logs: List[Dict[str, Any]] = []
    with p.open("r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    logs.append(obj)
            except json.JSONDecodeError:
                continue
    return logs

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

def in_time_window(log: Dict[str, Any], cutoff: datetime) -> bool:
    raw = log.get("@timestamp")
    if not raw:
        return False
    dt = parse_ts(raw)
    return bool(dt and dt >= cutoff)

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

def evaluate_rule(rule: Dict[str, Any], logs: List[Dict[str, Any]], now: Optional[datetime] = None):
    cond = rule["condition"]
    window = cond.get("window", "5m")
    minutes = int(window.rstrip("m"))
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(minutes=minutes)
    window_logs = [l for l in logs if in_time_window(l, cutoff)]
    rtype = cond["type"]

    if rtype == "count":
        matched = 0
        for l in window_logs:
            if "match" in cond:
                if matches_pattern(l.get(cond["field"]), cond["match"]):
                    matched += 1
            elif "op" in cond:
                if numeric_compare(l.get(cond["field"]), cond["op"], cond["value"]):
                    matched += 1
        if matched >= cond["threshold"]:
            return {
                "rule_id": rule["id"],
                "description": rule["description"],
                "severity": rule["severity"],
                "count": matched,
                "window": window
            }
        return None

    if rtype == "group_count":
        buckets: Dict[str, int] = {}
        for l in window_logs:
            if matches_pattern(l.get(cond["field"]), cond["match"]):
                key = str(l.get(cond["group_by"], "UNKNOWN"))
                buckets[key] = buckets.get(key, 0) + 1
        groups = [{"entity": k, "count": v} for k, v in buckets.items() if v >= cond["threshold"]]
        if groups:
            return {
                "rule_id": rule["id"],
                "description": rule["description"],
                "severity": rule["severity"],
                "groups": groups,
                "window": window
            }
        return None

    # Handle anomaly detection rules
    if rtype == "anomaly":
        from . import anomaly
        import pickle
        import json
        
        try:
            # Check if we have a trained model or need to train one
            model_path = Path(__file__).parent / "models" / f"{rule['id']}.model.pkl"
            feature_path = Path(__file__).parent / "models" / f"{rule['id']}.features.json"
            
            features = cond.get("features", [])
            contamination = cond.get("contamination", 0.05)
            threshold = cond.get("threshold", 0.0)
            
            # Ensure models directory exists
            model_dir = model_path.parent
            if not model_dir.exists():
                model_dir.mkdir(parents=True)
            
            # Train or load model
            model = None
            feature_cols = []
            
            if model_path.exists() and feature_path.exists():
                try:
                    with open(model_path, 'rb') as f:
                        model = pickle.load(f)
                    with open(feature_path, 'r') as f:
                        feature_cols = json.load(f)
                except Exception as e:
                    print(f"Error loading model: {e}")
                    model = None
            
            if model is None:
                # Train new model on window logs
                model, feature_cols = anomaly.train_model(
                    window_logs, features, contamination
                )
                # Save model and features
                with open(model_path, 'wb') as f:
                    pickle.dump(model, f)
                with open(feature_path, 'w') as f:
                    json.dump(feature_cols, f)
            
            # Detect anomalies
            anomalies = anomaly.detect_anomalies(
                window_logs, model, features, feature_cols, threshold
            )
            
            if anomalies:
                return {
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "anomaly_count": len(anomalies),
                    "anomalies": anomalies,
                    "window": window
                }
        except Exception as e:
            print(f"Anomaly detection error: {e}")
        return None

    return None

def run_all_rules(now: Optional[datetime] = None, fixture_file: Optional[Union[str, Path]] = None):
    logs = load_logs(fixture_file) if fixture_file else load_logs()
    alerts = []
    for r in rules:
        a = evaluate_rule(r, logs, now=now)
        if a:
            alerts.append(a)
    return alerts

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