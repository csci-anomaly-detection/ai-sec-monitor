from fastapi import FastAPI, Query # type: ignore
from fastapi.responses import JSONResponse # type: ignore
from datetime import datetime, UTC
from pathlib import Path
import sys

# Ensure detect can be imported
sys.path.insert(0, str(Path(__file__).parents[1]))
from detect import rule_runner

app = FastAPI(
    title="AI Security Monitor API",
    description="API for running security detection rules against log data",
    version="0.1.0",
)

@app.get("/")
def read_root():
    return {"status": "ok", "message": "AI Security Monitor API"}

@app.get("/alerts")
def get_alerts(
    timestamp: str = Query(None, description="ISO timestamp (default: now)"),
    fixture_path: str = Query(None, description="Path to log fixture file")
):
    """Run all rules and return alerts"""
    now = None
    if timestamp:
        try:
            now = datetime.fromisoformat(timestamp.rstrip("Z"))
            if now.tzinfo is None:
                now = now.replace(tzinfo=UTC)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"}
            )
    
    alerts = rule_runner.run_all_rules(now=now, fixture_file=fixture_path)
    return {
        "timestamp": now.isoformat() if now else datetime.now(UTC).isoformat(),
        "alert_count": len(alerts),
        "alerts": alerts
    }

@app.get("/rules")
def get_rules():
    """List all available rules"""
    return {
        "count": len(rule_runner.rules),
        "rules": [
            {
                "id": rule["id"],
                "description": rule["description"],
                "severity": rule["severity"],
                "condition_type": rule["condition"]["type"],
                "window": rule["condition"]["window"]
            }
            for rule in rule_runner.rules
        ]
    }

@app.get("/anomalies")
def get_anomalies(
    timestamp: str = Query(None, description="ISO timestamp (default: now)"),
    fixture_path: str = Query(None, description="Path to log fixture file"),
    rule_id: str = Query(None, description="Filter by rule ID")
):
    """Run anomaly detection rules and return results"""
    now = None
    if timestamp:
        try:
            now = datetime.fromisoformat(timestamp.rstrip("Z"))
            if now.tzinfo is None:
                now = now.replace(tzinfo=UTC)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"}
            )
    
    # Run all rules
    all_alerts = rule_runner.run_all_rules(now=now, fixture_file=fixture_path)
    
    # Filter for anomaly-type alerts
    anomaly_alerts = [a for a in all_alerts if "anomaly_count" in a]
    
    # Apply rule_id filter if specified
    if rule_id:
        anomaly_alerts = [a for a in anomaly_alerts if a["rule_id"] == rule_id]
    
    return {
        "timestamp": now.isoformat() if now else datetime.now(UTC).isoformat(),
        "anomaly_count": len(anomaly_alerts),
        "anomalies": anomaly_alerts
    }