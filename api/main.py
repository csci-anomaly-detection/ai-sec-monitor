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
    version="1.0.0",  # Updated to 1.0 since it's production ready
)

# ===============================
# PRODUCTION ENDPOINTS
# ===============================

@app.get("/alerts/live")
async def get_live_alerts(
    hours_back: int = Query(1, description="Hours to analyze (1-24)", ge=1, le=24),
    query: str = Query(None, description="Custom Loki query (optional)")
):
    """PRIMARY ENDPOINT: Real-time AI threat detection with ML anomaly analysis"""
    
    try:
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=hours_back)
        
        # Initialize data source
        loki = LokiDataSource()
        
        # Check health first
        if not loki.health_check():
            return JSONResponse({
                "error": "Loki service unavailable",
                "alerts": {"individual_alerts": [], "correlated_threats": [], "threat_count": 0},
                "logs_analyzed": 0
            }, status_code=503)
        
        # Get logs
        if query:
            all_logs = loki.query_logs(query, start_time, end_time, limit=500)
        else:
            all_logs = loki.query_logs('{job="suricata"}', start_time, end_time, limit=500)
        
        # Filter for security events only
        logs = [
            log for log in all_logs 
            if (log.get('log_type') not in ['stats', 'flow'] 
                and log.get('src_ip') not in ['0.0.0.0', None]
                and log.get('event_type') != 'stats')
        ]
        
        if len(logs) == 0:
            return JSONResponse({
                "message": f"No logs found in the last {hours_back} hours",
                "time_range": f"{start_time.isoformat()} to {end_time.isoformat()}",
                "alerts": {"individual_alerts": [], "correlated_threats": [], "threat_count": 0},
                "logs_analyzed": 0
            })
        
        # Apply detection rules
        from detect.rule_runner import run_rules_on_live_data
        alerts = run_rules_on_live_data(logs, end_time)
        
        return JSONResponse({
            "alerts": alerts,
            "logs_analyzed": len(logs),
            "time_range": f"{start_time.isoformat()} to {end_time.isoformat()}",
            "analysis_timestamp": end_time.isoformat()
        })
        
    except Exception as e:
        return JSONResponse({
            "error": f"Detection engine failed: {str(e)}",
            "alerts": {"individual_alerts": [], "correlated_threats": [], "threat_count": 0},
            "logs_analyzed": 0
        }, status_code=500)

@app.get("/rules")
def get_rules():
    """List all detection rules and their configurations"""
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

@app.get("/health")
async def health_check():
    """System health check - Loki connection and data availability"""
    loki = LokiDataSource()
    is_healthy = loki.health_check()
    
    if is_healthy:
        return JSONResponse({
            "status": "healthy",
            "service": "AI Security Monitor",
            "version": "1.0.0",
            "loki_connection": "ok"
        })
    else:
        return JSONResponse({
            "status": "unhealthy", 
            "service": "AI Security Monitor",
            "version": "1.0.0",
            "loki_connection": "failed"
        }, status_code=503)

@app.get("/")
def get_api_info():
    """API information and capabilities"""
    return {
        "service": "AI Security Monitor API",
        "version": "1.0.0",
        "status": "operational",
        "description": "AI-powered threat detection and security monitoring",
        "capabilities": [
            "Real-time threat detection",
            "ML-powered anomaly detection", 
            "Multi-layered rule correlation",
            "IP-based threat attribution",
            "Suricata log analysis"
        ],
        "endpoints": {
            "primary": "/alerts/live?hours_back=1",
            "health": "/health",
            "rules": "/rules"
        },
        "data_sources": ["Grafana Loki", "Suricata IDS"]
    }

@app.get("/stats")
async def get_system_stats():
    """System statistics and model information"""
    try:
        from detect.training_manager import TrainingDataManager
        trainer = TrainingDataManager()
        model_info = trainer.get_model_info()
        
        return {
            "system_status": "operational",
            "version": "1.0.0",
            "ml_models": {
                "status": model_info.get("status", "unknown"),
                "model_count": model_info.get("model_count", 0),
                "models": model_info.get("models", [])
            },
            "detection_rules": len(rule_runner.rules)
        }
    except Exception as e:
        return {
            "system_status": "degraded",
            "error": str(e),
            "version": "1.0.0",
            "detection_rules": len(rule_runner.rules)
        }