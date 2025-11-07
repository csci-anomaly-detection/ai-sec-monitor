# test_isolation_forest_direct.py
import json
from detect.data_sources import LokiDataSource
from detect.anomaly import detect_anomalies_advanced, run_isolation_forest
from datetime import datetime, timedelta, UTC

# Connect to Loki
loki = LokiDataSource()

# Get recent logs
end_time = datetime.now(UTC)
start_time = end_time - timedelta(hours=1)

print(f"Fetching logs from Loki...")
logs = loki.query_logs('{job="suricata"}', start_time, end_time, limit=500)

print(f"Got {len(logs)} logs from Loki\n")

if len(logs) < 10:
    print("❌ Not enough logs (need at least 10). Generate more logs first.")
else:
    # Run Isolation Forest directly
    print("Running Isolation Forest anomaly detection...\n")
    
    # Option A: Use detect_anomalies_advanced (raw)
    anomalies = detect_anomalies_advanced(logs, contamination=0.1, window_minutes=5)
    
    print(f"✅ Detected {len(anomalies)} anomalies\n")
    
    if anomalies:
        for i, anomaly in enumerate(anomalies, 1):
            print(f"Anomaly #{i}:")
            print(f"  Score: {anomaly['anomaly_score']:.3f}")
            print(f"  Severity: {anomaly['severity']}")
            print(f"  Suspicious Features:")
            for feature in anomaly['suspicious_features'][:5]:
                print(f"    - {feature}")
            print()
        
        # Save full output
        with open("isolation_forest_direct_output.json", "w") as f:
            json.dump(anomalies, f, indent=2)
        print("Full results saved to: isolation_forest_direct_output.json")
    else:
        print("No anomalies detected")
    
    # Option B: Use wrapper function
    print("\n" + "="*50)
    print("Testing run_isolation_forest wrapper:")
    print("="*50)
    
    result = run_isolation_forest(logs, contamination=0.1)
    
    if result:
        print(json.dumps(result, indent=2))
        
        with open("isolation_forest_wrapper_output.json", "w") as f:
            json.dump(result, f, indent=2)
        print("\nWrapper output saved to: isolation_forest_wrapper_output.json")
    else:
        print("No anomalies detected")