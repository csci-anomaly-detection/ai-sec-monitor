from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from datetime import datetime, UTC, timedelta
from pathlib import Path
import sys

# Ensure detect can be imported
sys.path.insert(0, str(Path(__file__).parents[1]))
from detect import rule_runner
from detect.data_sources import LokiDataSource

app = FastAPI(
    title="AI Security Monitor API",
    description="AI-powered threat detection and security monitoring",
    version="0.1.0",
)

# ===============================
# CORE PRODUCTION ENDPOINTS
# ===============================

@app.get("/alerts/live")
async def get_live_alerts(
    hours_back: int = Query(1, description="Hours to analyze (1-24)", ge=1, le=24),
    query: str = Query(None, description="Custom Loki query (optional)")
):
    """🎯 PRIMARY ENDPOINT: Real-time AI threat detection with ML anomaly analysis"""
    now = datetime.now(UTC)
    start_time = now - timedelta(hours=hours_back)
    
    # Get live data from Loki
    loki = LokiDataSource()
    if query:
        logs = loki.query_logs(query, start_time, now)
    else:
        logs = loki.query_all_logs(start_time, now)
    
    if not logs:
        return JSONResponse({
            "message": f"No logs found in the last {hours_back} hours",
            "alerts": {"individual_alerts": [], "correlated_threats": [], "threat_count": 0},
            "logs_analyzed": 0
        })
    
    # Apply your AI detection rules
    try:
        from detect.rule_runner import run_rules_on_live_data
        alerts = run_rules_on_live_data(logs, now)
        
        return JSONResponse({
            "alerts": alerts,
            "logs_analyzed": len(logs),
            "time_range": f"{start_time.isoformat()} to {now.isoformat()}",
            "rules_applied": 7,
            "ml_models_used": 3
        })
        
    except Exception as e:
        return JSONResponse({
            "error": f"Detection engine failed: {str(e)}",
            "alerts": {"individual_alerts": [], "correlated_threats": [], "threat_count": 0},
            "logs_analyzed": len(logs)
        }, status_code=500)

@app.get("/rules")
def get_rules():
    """📋 List all detection rules and their configurations"""
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

@app.get("/loki/health")
async def loki_health():
    """🏥 System health check - Loki connection and data availability"""
    loki = LokiDataSource()
    is_healthy = loki.health_check()
    
    if is_healthy:
        labels = loki.get_available_labels()
        return JSONResponse({
            "status": "healthy",
            "loki_url": loki.base_url,
            "available_labels": labels[:10],
            "total_labels": len(labels)
        })
    else:
        return JSONResponse(
            {"status": "unhealthy", "loki_url": loki.base_url},
            status_code=503
        )

# ===============================
# API INFORMATION & INTEGRATION
# ===============================

@app.get("/api/info")
def get_api_info():
    """ℹ️ API capabilities and integration information"""
    return {
        "name": "AI Security Monitor API",
        "version": "0.1.0",
        "description": "AI-powered threat detection and security monitoring",
        "capabilities": [
            "Real-time threat detection",
            "ML-powered anomaly detection", 
            "Multi-layered rule correlation",
            "IP-based threat attribution",
            "Suricata log analysis"
        ],
        "main_endpoint": "/alerts/live",
        "data_sources": ["Grafana Loki", "Suricata IDS"],
        "ml_models": ["Traffic Anomaly", "Behavioral Anomaly", "Timing Pattern"]
    }

@app.get("/api/stats")
async def get_api_stats():
    """📊 System status, ML models, and operational statistics"""
    try:
        from detect.training_manager import TrainingDataManager
        trainer = TrainingDataManager()
        model_info = trainer.get_model_info()
        
        return {
            "system_status": "operational",
            "ml_models": {
                "status": model_info.get("status", "unknown"),
                "model_count": model_info.get("model_count", 0),
                "models": model_info.get("models", [])
            },
            "detection_rules": len(rule_runner.rules),
            "api_version": "0.1.0"
        }
    except Exception as e:
        return {
            "system_status": "degraded",
            "error": str(e),
            "detection_rules": len(rule_runner.rules),
            "api_version": "0.1.0"
        }

@app.get("/api/sample")
async def get_sample_response():
    """📄 Sample JSON response for integration testing and development"""
    return {
        "sample_response": {
            "alerts": {
                "individual_alerts": [
                    {
                        "rule_id": "suricata_alert_storm",
                        "severity": "high",
                        "description": "Suricata alert storm detected",
                        "matches": 5000,
                        "detection_method": "traditional"
                    },
                    {
                        "rule_id": "advanced_traffic_anomaly",
                        "severity": "high", 
                        "description": "Advanced ML-based traffic pattern anomaly",
                        "anomalies_detected": 3,
                        "detection_method": "trained_models"
                    }
                ],
                "correlated_threats": [
                    {
                        "ip": "10.77.0.20",
                        "severity": "CRITICAL",
                        "confidence_score": 0.85,
                        "attack_type": "SSH Brute Force",
                        "total_events": 9,
                        "recommendation": "IMMEDIATE ACTION: Block IP, isolate affected systems"
                    }
                ],
                "threat_count": 1,
                "high_severity_threats": 1
            },
            "logs_analyzed": 5000,
            "rules_applied": 7,
            "ml_models_used": 3
        },
        "integration_notes": [
            "All timestamps are in ISO 8601 UTC format",
            "Severity levels: LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4", 
            "Confidence scores range from 0.0 to 1.0"
        ]
    }