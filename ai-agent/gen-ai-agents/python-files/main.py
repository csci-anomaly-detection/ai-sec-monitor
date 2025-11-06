import sys
import os
import json
import logging
from pathlib import Path

# Add paths for imports
sys.path.insert(0, '/app')

# Suppress httpx and other verbose loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("chromadb.telemetry").setLevel(logging.WARNING)
logging.getLogger("chromadb").setLevel(logging.WARNING)

# Configure logging
class HttpxFilter(logging.Filter):
    def filter(self, record):
        # Exclude all httpx, chromadb, and telemetry logs
        excluded = ["httpx", "chromadb", "telemetry", "posthog"]
        return not any(exc in record.name for exc in excluded)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.expanduser('/app/logs/pipeline_user.log')),
        logging.StreamHandler()
    ]
)

# Apply filter to all handlers
logger = logging.getLogger(__name__)
for handler in logger.handlers:
    handler.addFilter(HttpxFilter())

# Import pipeline stages
from pre_batch import process_and_store_batches
from batching_agent import react_agent
from mitre_mapper import map_signatures_to_mitre, format_mitre_enriched_report
from analyst_agent import analyze_threat

# Configuration
LOG_LOCATION = os.getenv("LOG_LOCATION", "/app/logs/eve.json")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
ENABLE_EMAIL = os.getenv("ENABLE_EMAIL", "false").lower() == "true"

def ensure_directories():
    """Create necessary directories if they don't exist."""
    directories = [
        Path(LOG_LOCATION).parent,
        Path(OUTPUT_DIR),
        Path("/app/logs")
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    logger.info(f"✅ Directories ensured: {[str(d) for d in directories]}")

def stage_1_preprocessing(log_location: str) -> list:
    """
    Stage 1: Preprocess and batch logs.
    Returns: batched_data list
    """
    logger.info("="*70)
    logger.info("STAGE 1: PREPROCESSING & BATCHING")
    logger.info("="*70)
    
    try:
        if not os.path.exists(log_location):
            logger.error(f"❌ Log file not found: {log_location}")
            return []
        
        logger.info(f"📂 Processing logs from: {log_location}")
        batched_data = process_and_store_batches(log_location)
        
        # Log FULL data without truncation
        logger.info(f"📊 Stage 1 Output Data:")
        logger.info(json.dumps(batched_data, indent=2, default=str))
        
        if batched_data:
            logger.info(f"✅ Successfully batched {len(batched_data)} alert groups")
            return batched_data
        else:
            logger.warning("⚠️  No batched data returned from preprocessing")
            return []
    
    except Exception as e:
        logger.error(f"❌ Error in Stage 1 (Preprocessing): {e}", exc_info=True)
        raise

def stage_2_batching_analysis(batched_data: list) -> list:
    """Stage 2: Run ReAct agent on batched data for initial analysis."""
    logger.info("="*70)
    logger.info("STAGE 2: BATCHING AGENT ANALYSIS (ReAct)")
    logger.info("="*70)
    
    try:
        if not batched_data:
            logger.warning("⚠️  No batched data provided to Stage 2")
            return []
        
        logger.info(f"🤖 Running ReAct agent on {len(batched_data)} batches...")
        analysis_result = react_agent(batched_data=batched_data)
                
        # CLEAR OLLAMA CONTEXT before next stage
        logger.info("🧹 Clearing Ollama context...")
        _clear_ollama_context()
        
        # Continue with MITRE mapping...
        logger.info("🗺️  Mapping signatures to MITRE ATT&CK framework...")
        enriched_analysis = map_signatures_to_mitre(analysis_result)
        formatted_report = format_mitre_enriched_report(enriched_analysis)
        
        # Log FULL MITRE mapping output
        logger.info(f"📊 Stage 2 MITRE Mapping Output:")
        logger.info(json.dumps(formatted_report, indent=2, default=str))
        
        logger.info(f"✅ MITRE mapping complete - {len(formatted_report)} signatures enriched")
        
        return formatted_report
    
    except Exception as e:
        logger.error(f"❌ Error in Stage 2 (Batching Analysis): {e}", exc_info=True)
        raise

def _clear_ollama_context():
    """Force Ollama to clear conversation context."""
    import requests
    
    OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "ollama")
    
    try:
        # Send a reset/empty request to clear context
        url = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate"
        payload = {
            "model": "qwen2.5:7b",
            "prompt": "",
            "context": []  # Empty context clears memory
        }
        response = requests.post(url, json=payload, timeout=5)
        logger.info("✅ Ollama context cleared")
    except Exception as e:
        logger.warning(f"⚠️  Could not clear Ollama context: {e}")

def stage_3_analyst_review(batching_analysis: dict) -> dict:
    """
    Stage 3: Run analyst agent for deep-dive review and recommendations.
    Returns: final_report dict
    """
    logger.info("="*70)
    logger.info("STAGE 3: ANALYST AGENT REVIEW")
    logger.info("="*70)
    
    try:
        logger.info("👨‍💼 Running analyst agent for detailed review...")
        final_report = analyze_threat(batching_analysis)
                
        if final_report:
            logger.info("✅ Analyst agent review complete")
            return final_report
        else:
            logger.warning("⚠️  Analyst agent returned empty report")
            return batching_analysis
    
    except Exception as e:
        logger.error(f"❌ Error in Stage 3 (Analyst Review): {e}", exc_info=True)
        # Continue with batching analysis if analyst stage fails
        logger.warning("⚠️  Continuing with batching analysis output")
        return batching_analysis

def save_results(final_report: dict, output_dir: str = OUTPUT_DIR):
    """Save final report to JSON file."""
    try:
        output_path = Path(output_dir) / "final_report.json"
        with open(output_path, 'w') as f:
            json.dump(final_report, f, indent=2, default=str)
        logger.info(f"💾 Final report saved to: {output_path}")
        logger.info(f"📊 Final Report Saved Data:")
        logger.info(json.dumps(final_report, indent=2, default=str))
        return str(output_path)
    
    except Exception as e:
        logger.error(f"❌ Error saving results: {e}", exc_info=True)
        raise

def send_email_report(final_report: dict):
    """Send email notification if enabled."""
    if not ENABLE_EMAIL:
        logger.debug("📧 Email notifications disabled")
        return
    
    try:
        from analyst_agent.email_agent import send_alert_email
        logger.info("📧 Sending email report...")
        send_alert_email(final_report)
        logger.info("✅ Email report sent")
    
    except Exception as e:
        logger.error(f"⚠️  Error sending email: {e}")
        # Don't fail the pipeline for email errors

def run_full_pipeline(log_location: str = LOG_LOCATION) -> dict:
    """
    Execute the complete security monitoring pipeline.
    
    Pipeline stages:
      1. Preprocessing & Batching: Group related logs
      2. Batching Analysis: Initial pattern analysis with ReAct agent + MITRE mapping
      3. Analyst Review: Deep-dive analysis and recommendations
      4. Output & Notification: Save results and send alerts
    
    Returns: final_report dict
    """
    logger.info("\n" + "🔐 "*20)
    logger.info("SECURITY MONITORING PIPELINE STARTED")
    logger.info("🔐 "*20 + "\n")
    
    try:
        # Ensure output directories exist
        ensure_directories()
        
        # Stage 1: Preprocessing
        batched_data = stage_1_preprocessing(log_location)
        if not batched_data:
            logger.warning("Pipeline halting: No batched data from Stage 1")
            return {"error": "No batched data from preprocessing", "status": "failed"}
        
        # Stage 2: Batching Analysis + MITRE Mapping
        batching_analysis = stage_2_batching_analysis(batched_data)
        if not batching_analysis:
            logger.warning("Pipeline halting: No analysis from Stage 2")
            return {"error": "No analysis from batching agent", "status": "failed"}
        
        # Stage 3: Analyst Review
        analyst_report = stage_3_analyst_review(batching_analysis)
        
        # Save results (analyst_report could be list or dict)
        output_file = save_results(analyst_report)
        
        # Build final output structure
        final_output = {
            "status": "success",
            "output_file": output_file,
            "results": analyst_report,
            "signatures_analyzed": len(analyst_report) if isinstance(analyst_report, list) else "N/A",
            "mitre_techniques_mapped": len([s for s in analyst_report if isinstance(s, dict) and 'mitre_mapping' in s]) if isinstance(analyst_report, list) else "N/A"
        }
        
        # Send email if enabled
        send_email_report(final_output)
        
        # Summary
        logger.info("\n" + "="*70)
        logger.info("PIPELINE COMPLETED SUCCESSFULLY")
        logger.info("="*70)
        logger.info(f"📊 Final Report Summary:")
        logger.info(f"   - Output file: {output_file}")
        logger.info(f"   - Signatures analyzed: {final_output['signatures_analyzed']}")
        logger.info(f"   - MITRE techniques mapped: {final_output['mitre_techniques_mapped']}")
        
        return final_output
    
    except Exception as e:
        logger.error(f"\n❌ PIPELINE FAILED: {e}", exc_info=True)
        return {"error": str(e), "status": "failed"}

if __name__ == "__main__":
    # Parse command-line arguments
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_LOCATION
    
    # Run pipeline
    result = run_full_pipeline(log_file)
    
    # Print final result
    print("\n" + "="*70)
    print("FINAL PIPELINE OUTPUT")
    print("="*70)
    print(json.dumps(result, indent=2, default=str))
    
    # Exit with appropriate code
    exit_code = 0 if "error" not in result else 1
    sys.exit(exit_code)