from datetime import datetime, UTC, timedelta
import json
from pathlib import Path
import pytest

from detect import anomaly, rule_runner

# Single fixture file for all tests
MASTER_FIXTURE = Path(__file__).parent / "fixtures" / "logs.ndjson"
FIXED_NOW = datetime(2025, 9, 10, 9, 50, 0, tzinfo=UTC)  # 9:50 AM

def test_threshold_rules():
    """Test all threshold-based rules trigger correctly"""
    alerts = rule_runner.run_all_rules(now=FIXED_NOW, fixture_file=MASTER_FIXTURE)
    
    # Should trigger all 3 threshold rules
    rule_ids = {alert["rule_id"] for alert in alerts}
    expected_rules = {"api_5xx_spike", "auth_bruteforce", "db_slow_query_storm"}
    
    print(f"Triggered rules: {rule_ids}")
    assert rule_ids == expected_rules, f"Expected {expected_rules}, got {rule_ids}"

def test_anomaly_feature_extraction():
    """Test that features can be extracted from logs"""
    logs = rule_runner.load_logs(MASTER_FIXTURE)
    features = ["duration_ms", "status"]
    
    df = anomaly.extract_features(logs, features, time_window=10)
    
    # Should have multiple time windows
    assert len(df) > 1, f"Expected multiple windows, got {len(df)}"
    
    # Should have the right feature columns
    assert "duration_ms_mean" in df.columns
    assert "duration_ms_max" in df.columns
    assert "event_count" in df.columns
    
    print(f"Extracted features across {len(df)} time windows")

def test_anomaly_detection_standalone():
    """Test anomaly detection algorithm works"""
    logs = rule_runner.load_logs(MASTER_FIXTURE)
    
    # Split into normal (first 70%) and test data (all data)
    split_point = int(len(logs) * 0.7)
    train_logs = logs[:split_point]  # Normal baseline
    test_logs = logs  # All data including anomalies
    
    features = ["duration_ms"]
    
    # Train model on normal data
    model, feature_cols = anomaly.train_model(
        train_logs, features, contamination=0.1
    )
    
    # Detect anomalies
    detected = anomaly.detect_anomalies(
        test_logs, model, features, feature_cols, threshold=0.0
    )
    
    print(f" Detected {len(detected)} anomalies")
    assert len(detected) > 0, "Should detect some anomalies"

def test_anomaly_rule_integration():
    """Test anomaly detection integrated with rule runner"""
    # Create anomaly rule
    anomaly_rule = {
        "id": "latency_anomaly_test",
        "description": "Detect unusual response time patterns",
        "severity": "medium",
        "condition": {
            "type": "anomaly",
            "features": ["duration_ms"],
            "contamination": 0.1,
            "threshold": 0.0,
            "window": "60m"
        }
    }
    
    # Temporarily add anomaly rule to rules list
    original_rules = rule_runner.rules
    rule_runner.rules = rule_runner.rules + [anomaly_rule]
    
    # Ensure models directory exists
    model_dir = Path(__file__).parents[1] / "models"
    model_dir.mkdir(exist_ok=True)
    
    try:
        # Run all rules (threshold + anomaly)
        alerts = rule_runner.run_all_rules(
            now=FIXED_NOW, 
            fixture_file=MASTER_FIXTURE
        )
        
        # Should have both threshold and anomaly alerts
        rule_types = set()
        for alert in alerts:
            if alert["rule_id"] == "latency_anomaly_test":
                rule_types.add("anomaly")
                assert "anomaly_count" in alert
                assert alert["anomaly_count"] > 0
            else:
                rule_types.add("threshold")
        
        print(f" Alert types generated: {rule_types}")
        assert "anomaly" in rule_types, "Should detect anomaly-based alerts"
        assert "threshold" in rule_types, "Should detect threshold-based alerts"
        
    finally:
        # Restore original rules
        rule_runner.rules = original_rules

def test_complete_detection_pipeline():
    """End-to-end test of the entire detection system"""
    # This test validates the complete pipeline works
    logs = rule_runner.load_logs(MASTER_FIXTURE)
    
    # Verify log data quality
    assert len(logs) > 100, f"Need substantial test data, got {len(logs)} logs"
    
    # Verify time range spans multiple periods  
    timestamps = [log.get("@timestamp") for log in logs if "@timestamp" in log]
    first_time = min(timestamps)
    last_time = max(timestamps)
    
    print(f" Log data spans from {first_time} to {last_time}")
    print(f" Total logs: {len(logs)}")
    
    # Run all detection types
    threshold_alerts = rule_runner.run_all_rules(
        now=FIXED_NOW, 
        fixture_file=MASTER_FIXTURE
    )
    
    print(f" Complete detection pipeline: {len(threshold_alerts)} alerts")
    assert len(threshold_alerts) >= 3, "Should trigger multiple detection rules"

if __name__ == "__main__":
    # Can run individual tests
    test_threshold_rules()
    test_anomaly_feature_extraction()
    test_anomaly_detection_standalone()
    test_anomaly_rule_integration()
    test_complete_detection_pipeline()
    print("All detection tests passed!")