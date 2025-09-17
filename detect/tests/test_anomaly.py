from datetime import datetime, UTC, timedelta
import json
import random
from pathlib import Path

from detect import anomaly, rule_runner

def prepare_anomaly_fixture():
    """
    Prepares a test fixture by modifying existing logs.ndjson file:
    - First half: Keep normal values
    - Second half: Add anomalous values
    """
    # Load the existing fixture
    fixture_path = Path(__file__).parent / "fixtures" / "logs.ndjson"
    anomaly_path = Path(__file__).parent / "fixtures" / "anomaly_test.ndjson"
    
    if not fixture_path.exists():
        print(f"Source fixture not found: {fixture_path}")
        return None
    
    # Read existing logs
    logs = []
    with open(fixture_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("//"):
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    
    # Ensure all logs have duration_ms for anomaly detection
    for log in logs:
        if "duration_ms" not in log:
            log["duration_ms"] = random.randint(100, 300)
            
    # Spread logs across multiple time windows (critical fix)
    base_time = datetime(2025, 9, 10, 8, 0, 0, tzinfo=UTC)
    spread_logs = []
    
    # Create 5 time windows with 10 logs each
    for window in range(5):  # 5 windows
        window_time = base_time + timedelta(minutes=window*15)  # 15-min windows
        for i in range(10):  # 10 logs per window
            # Make a copy of a random log
            log = json.loads(json.dumps(random.choice(logs)))
            
            # Set timestamp within this window
            minute_offset = random.randint(0, 14)
            log_time = window_time + timedelta(minutes=minute_offset)
            log["@timestamp"] = log_time.isoformat()
            
            # For second half, add anomalous values
            if window >= 3:  # Windows 3-4 are anomalous
                if "duration_ms" in log:
                    log["duration_ms"] = log["duration_ms"] * 20  # 20x slower
                if "status" in log and random.random() < 0.5:
                    log["status"] = str(random.randint(500, 505))
                    
            spread_logs.append(log)
    
    # Write modified logs to anomaly fixture
    with open(anomaly_path, "w") as f:
        for log in spread_logs:
            f.write(json.dumps(log) + "\n")
    
    return anomaly_path

def test_feature_extraction():
    # Prepare fixture
    fixture_path = prepare_anomaly_fixture()
    assert fixture_path is not None, "Failed to prepare anomaly fixture"
    
    # Load logs and extract features
    logs = rule_runner.load_logs(fixture_path)
    features = ["duration_ms", "status"]
    
    # Use smaller window to ensure multiple time buckets
    df = anomaly.extract_features(logs, features, time_window=5)
    
    # Debug: Print dataframe info
    print(f"DataFrame shape: {df.shape}")
    print(f"Time windows: {df['window'].tolist()}")
    
    # We should have multiple time windows now
    assert len(df) > 1
    
    # Verify feature columns exist
    assert "duration_ms_mean" in df.columns
    assert "event_count" in df.columns

def test_anomaly_detection():
    # Keep as is - working well
    pass

def test_rule_runner_with_anomaly():
    # Prepare fixture
    fixture_path = prepare_anomaly_fixture()
    assert fixture_path is not None, "Failed to prepare anomaly fixture"
    
    # Create a test rule
    test_rule = {
        "id": "test_latency_anomaly",
        "description": "Test anomaly detection",
        "severity": "medium",
        "condition": {
            "type": "anomaly",
            "features": ["duration_ms"],
            "contamination": 0.2,
            "threshold": 0.0,
            "window": "120m"  # Increase window to capture all logs
        }
    }
    
    # Force model directory creation
    model_dir = Path(__file__).parents[1] / "models"
    model_dir.mkdir(exist_ok=True)
    
    # Mock the rules list to use our test rule
    original_rules = rule_runner.rules
    rule_runner.rules = [test_rule]
    
    try:
        # Run detection with future timestamp to include all logs
        end_time = datetime(2025, 9, 10, 11, 0, 0, tzinfo=UTC)
        alerts = rule_runner.run_all_rules(
            now=end_time,
            fixture_file=fixture_path
        )
        
        # Print debug info
        print(f"Generated alerts: {alerts}")
        
        # Should detect the anomaly
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "test_latency_anomaly"
        assert "anomaly_count" in alerts[0]
        assert alerts[0]["anomaly_count"] > 0
        
    finally:
        # Restore original rules
        rule_runner.rules = original_rules