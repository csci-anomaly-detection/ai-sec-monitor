import sys
import os
import json
import logging
from pathlib import Path
from datetime import datetime

# Add paths for imports
sys.path.insert(0, '/app')

# Suppress httpx and other verbose loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("chromadb.telemetry").setLevel(logging.WARNING)
logging.getLogger("chromadb").setLevel(logging.WARNING)

# ANSI Color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class StageFormatter(logging.Formatter):
    """Custom formatter - no level prefix, just message"""
    def format(self, record):
        return record.getMessage()

# Configure logging
class HttpxFilter(logging.Filter):
    def filter(self, record):
        # Exclude all httpx, chromadb, and telemetry logs
        excluded = ["httpx", "chromadb", "telemetry", "posthog"]
        return not any(exc in record.name for exc in excluded)

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler(os.path.expanduser('/app/logs/pipeline.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
for handler in logger.handlers:
    handler.setFormatter(StageFormatter())

# Import pipeline stages
from analyst_agent import analyze_all_threats_batch
from validation_orchestrator import ValidationOrchestrator

# Configuration
RAW_LOG_LOCATION = os.getenv("RAW_LOG_LOCATION", "/app/logs/demo.json")
VALIDATED_LOG_LOCATION = os.getenv("VALIDATED_LOG_LOCATION", "/app/logs/validated_threats.json")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
ENABLE_EMAIL = os.getenv("ENABLE_EMAIL", "false").lower() == "true"
ENABLE_VALIDATION = os.getenv("ENABLE_VALIDATION", "false").lower() == "true"

def print_stage_header(stage_num, stage_name, color):
    """Print colorful stage header"""
    print(f"\n{color}{'█' * 80}{Colors.ENDC}")
    print(f"{color}█ STAGE {stage_num}: {stage_name}{' ' * (70 - len(stage_name))}{color}█{Colors.ENDC}")
    print(f"{color}{'█' * 80}{Colors.ENDC}\n")

def print_stage_box(content_lines, color):
    """Print stage content in a colored box"""
    print(f"{color}┌{'─' * 78}┐{Colors.ENDC}")
    for line in content_lines:
        print(f"{color}│{Colors.ENDC} {line:<76} {color}│{Colors.ENDC}")
    print(f"{color}└{'─' * 78}┘{Colors.ENDC}\n")

def load_validated_data(validated_log_location: str) -> tuple:
    """Load pre-existing validated data from file"""
    try:
        validated_file_path = Path(validated_log_location)
        
        if not validated_file_path.exists():
            logger.error(f"❌ Validated data file not found: {validated_log_location}")
            return {}, {}
        
        logger.info(f"📂 Loading validated data from: {validated_log_location}")
        
        with open(validated_file_path, 'r') as f:
            validated_data = json.load(f)
        
        # Extract summary and detailed_results from loaded data
        validation_stats = validated_data.get("summary", {})
        detailed_results = validated_data.get("detailed_results", [])
        
        logs = [
            f"✅ Loaded {len(detailed_results)} validated alerts",
            f"   • Total: {validation_stats.get('total_alerts', 0)}",
            f"   • Validated: {validation_stats.get('validated', 0)}",
            f"   • Filtered: {validation_stats.get('filtered_false_positive', 0) + validation_stats.get('filtered_benign', 0)}"
        ]
        print_stage_box(logs, Colors.GREEN)
        
        return validated_data, validation_stats
    
    except json.JSONDecodeError as e:
        logger.error(f"❌ Invalid JSON in validated data file: {e}")
        return {}, {}
    except Exception as e:
        logger.error(f"❌ Error loading validated data: {e}", exc_info=True)
        return {}, {}

def stage_0_validation(raw_log_location: str) -> tuple:
    """Stage 0: Validate raw alerts before pipeline processing."""
    
    try:
        # Load raw data
        with open(raw_log_location, 'r') as f:
            raw_data = json.load(f)
        
        # Initialize validator
        validator = ValidationOrchestrator()
        
        print_stage_box([f"🔍 Running validation on: {raw_log_location}"], Colors.CYAN)
        print_stage_box([f"✅ Validation orchestrator initialized"], Colors.GREEN)
        
        # ✅ EXTRACT ALL THREATS (Correlated + Individual)
        alerts_data = raw_data.get("alerts", {})
        all_threats = []
        
        # 1. Get Correlated Threats (already have proper structure)
        correlated = alerts_data.get("correlated_threats", [])
        if isinstance(correlated, list):
            all_threats.extend(correlated)
        
        # 2. Get Individual Alerts (need to extract IP from matches)
        individual = alerts_data.get("individual_alerts", [])
        if isinstance(individual, list):
            for alert in individual:
                if isinstance(alert, dict):
                    # ✅ Extract IP from matches array
                    matches = alert.get("matches", [])
                    if matches and len(matches) > 0:
                        first_match = matches[0]
                        ip = first_match.get("src_ip", "unknown")
                        
                        # Build threat object from individual alert
                        threat_obj = {
                            "ip": ip,
                            "attack_type": alert.get("rule_id", "unknown").replace("_", " ").title(),
                            "severity": alert.get("severity", "LOW").upper(),
                            "total_events": alert.get("count", len(matches)),
                            "description": alert.get("description", ""),
                            "rules_violated": [alert],
                            "confidence_score": 0.5,
                            "timestamps": [m.get("@timestamp", "") for m in matches[:10]]
                        }
                        all_threats.append(threat_obj)

        if not all_threats:
            print_stage_box([f"⚠️  No threats found in {raw_log_location}"], Colors.YELLOW)
            return [], {"total_threats": 0, "validated": 0, "errors": 0}
        
        print_stage_box([
            f"📊 Found {len(all_threats)} total threats to validate",
            f"   • Correlated: {len(correlated)}",
            f"   • Individual: {len(individual)}"
        ], Colors.CYAN)
        
        validated_alerts = []
        errors = 0
        
        # ✅ VALIDATE EACH THREAT
        for idx, threat in enumerate(all_threats, 1):
            # Ensure threat is a dictionary
            if not isinstance(threat, dict):
                errors += 1
                logger.warning(f"Skipping invalid threat #{idx}: {type(threat)}")
                continue
            
            try:
                # Call validate_threat on the instance
                result = validator.validate_threat(threat)
                validated_alerts.append(result)
                
                ip = threat.get("ip", "unknown")
                classification = result.get("classification", "UNKNOWN")
                logger.info(f"✅ Threat #{idx} validated: {ip} -> {classification}")
                
            except Exception as e:
                errors += 1
                ip = threat.get("ip", "unknown")
                logger.error(f"Error validating threat #{idx} ({ip}): {e}")
        
        # Build stats
        stats = {
            "total_threats": len(all_threats),
            "validated": len(validated_alerts),
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }
        
        # ✅ SAVE VALIDATED RESULTS TO FILE
        validated_output = {
            "summary": stats,
            "detailed_results": validated_alerts
        }
        
        output_path = Path(VALIDATED_LOG_LOCATION)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(validated_output, f, indent=2, default=str)
        
        logger.info(f"💾 Validated threats saved to: {output_path}")
        
        print_stage_box([
            f"✅ Validation complete",
            f"   • Total: {len(all_threats)}",
            f"   • Validated: {len(validated_alerts)}",
            f"   • Errors: {errors}",
            f"   • Saved to: {output_path}"
        ], Colors.GREEN)
        
        return validated_alerts, stats
        
    except Exception as e:
        logger.error(f"❌ Error in Stage 0 (Validation): {e}", exc_info=True)
        return [], {"error": str(e)}

def process_validated_threats(validated_data: dict) -> list:
    """Return validated results directly"""
    try:
        detailed_results = validated_data.get("detailed_results", [])
        
        logs = [
            f"✅ Loaded {len(detailed_results)} validated results",
            f"   • Ready for hierarchical analysis"
        ]
        print_stage_box(logs, Colors.YELLOW)
        
        return detailed_results

    except Exception as e:
        logger.error(f"❌ Error processing validated threats: {e}", exc_info=True)
        return []

def stage_3_analyst_review(batching_analysis: list):
    """Stage 3: Run analyst agent with hierarchical clustering"""
    try:
        if not batching_analysis:
            logger.warning("⚠️  No batched analysis provided to Stage 3")
            return {}

        logger.info(f"👨‍💼 Running hierarchical cluster analysis for {len(batching_analysis)} threats...")
        
        analyst_report = analyze_all_threats_batch(batching_analysis)
        
        try:
            import chromadb
            CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
            CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
            client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            history_col = client.get_or_create_collection("analyst_reports")
            
            history_col.add(
                ids=[f"report_{datetime.now().timestamp()}"],
                documents=[json.dumps(analyst_report, indent=2, default=str)],
                metadatas={
                    "report_type": "hierarchical_cluster_analysis",
                    "total_threats": analyst_report.get("threat_statistics", {}).get("total_threats", 0),
                    "overall_risk": analyst_report.get("risk_assessment", {}).get("overall_risk", "UNKNOWN"),
                    "timestamp": str(datetime.now())
                }
            )
            logger.info("✅ Report stored in ChromaDB history")
                    
        except Exception as e:
            logger.warning(f"⚠️  Could not store in ChromaDB: {e}")

        logs = [
            f"✅ Hierarchical cluster analysis complete",
            f"   • Threats analyzed: {analyst_report.get('threat_statistics', {}).get('total_threats', 0)}",
            f"   • Risk level: {analyst_report.get('risk_assessment', {}).get('overall_risk', 'UNKNOWN')}"
        ]
        print_stage_box(logs, Colors.BLUE)
        
        return analyst_report

    except Exception as e:
        logger.error(f"❌ Error in Stage 3 (Analyst Review): {e}", exc_info=True)
        return {
            "executive_summary": "Analysis failed - manual review required",
            "threat_statistics": {
                "total_threats": len(batching_analysis),
                "unique_attackers": 0,
                "attack_categories": [],
                "severity_breakdown": {}
            },
            "key_findings": ["Analysis pipeline encountered an error"],
            "threat_actors": [],
            "iocs": {"malicious_ips": [], "signature_ids": [], "attack_patterns": []},
            "immediate_actions": ["Manual review required", "Escalate to SOC"],
            "strategic_recommendations": ["Investigate pipeline failure", "Review threat data manually"],
            "risk_assessment": {
                "overall_risk": "UNKNOWN",
                "confidence": 0.0,
                "reasoning": "Pipeline failure prevented analysis"
            }
        }

def save_results(final_report, output_dir: str = OUTPUT_DIR):
    """Save final report to JSON file"""
    try:
        output_path = Path(output_dir) / "final_report.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(final_report, f, indent=2, default=str)
        
        logs = [
            f"💾 Final report saved successfully",
            f"   • Location: {output_path}"
        ]
        print_stage_box(logs, Colors.GREEN)
        
        return str(output_path)
    except Exception as e:
        logger.error(f"❌ Error saving results: {e}", exc_info=True)
        raise

def send_email_report(final_report: dict):
    """Send email notification if enabled"""
    if not ENABLE_EMAIL:
        return
    
    try:
        from analyst_agent import send_alert_email
        logger.info("📧 Sending email report...")
        send_alert_email(final_report)
        logger.info("✅ Email report sent")
    
    except Exception as e:
        logger.error(f"⚠️  Error sending email: {e}")

def ensure_directories():
    """Create necessary directories"""
    directories = [
        Path("/app/logs"),
        Path(OUTPUT_DIR),
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

def run_full_pipeline():
    """Execute the complete security monitoring pipeline"""
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'█' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.GREEN}█ SECURITY MONITORING PIPELINE STARTED{' ' * (39)}{Colors.ENDC}{Colors.GREEN}█{Colors.ENDC}{Colors.BOLD}")
    print(f"{Colors.GREEN}{'█' * 80}{Colors.ENDC}\n")

    try:
        ensure_directories()

        # STAGE 0: VALIDATION
        print_stage_header(0, "DATA LOADING", Colors.CYAN)
        
        validated_alerts, validation_stats = stage_0_validation(RAW_LOG_LOCATION)
        validated_data = {
            "summary": validation_stats,
            "detailed_results": validated_alerts
        }

        if not validated_data.get("detailed_results"):
            logger.error("❌ No validated data available to process")
            return {"error": "No validated data", "status": "failed"}

        # STAGE 1: BATCHING
        print_stage_header(1, "BATCHING", Colors.YELLOW)
        batched_data = process_validated_threats(validated_data)
        
        if not batched_data:
            logger.error("❌ No batched data available")
            return {"error": "No batched data", "status": "failed"}
        
        # STAGE 2: ANALYST REVIEW
        print_stage_header(2, "ANALYST REVIEW", Colors.BLUE)
        analyst_report = stage_3_analyst_review(batched_data)

        # STAGE 3: SAVE RESULTS
        print_stage_header(3, "RESULTS", Colors.GREEN)
        output_file = save_results(analyst_report)

        final_output = {
            "status": "success",
            "pipeline_stages": {
                "validation": validation_stats,
                "threats_analyzed": len(batched_data),
            },
            "output_file": output_file,
            "results": analyst_report,
            "pipeline_completed_at": str(datetime.now())
        }

        send_email_report(final_output)

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'█' * 80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.GREEN}█ PIPELINE COMPLETED SUCCESSFULLY{' ' * (45)}{Colors.ENDC}{Colors.GREEN}█{Colors.ENDC}{Colors.BOLD}")
        print(f"{Colors.GREEN}{'█' * 80}{Colors.ENDC}\n")

        return final_output

    except Exception as e:
        print(f"\n{Colors.BOLD}{Colors.RED}{'█' * 80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.RED}█ PIPELINE FAILED{' ' * (61)}{Colors.ENDC}{Colors.RED}█{Colors.ENDC}{Colors.BOLD}")
        print(f"{Colors.RED}{'█' * 80}{Colors.ENDC}\n")
        logger.error(f"❌ Pipeline Error: {e}", exc_info=True)
        return {"error": str(e), "status": "failed"}

if __name__ == "__main__":
    result = run_full_pipeline()
    exit_code = 0 if result.get("status") == "success" else 1
    sys.exit(exit_code)