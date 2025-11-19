"""
Validation Orchestrator - Integrates validation layer with the analysis pipeline.

This module coordinates the FeatureAnalyzer and LLMValidator to pre-filter
security alerts before they enter the batching and analysis stages.
"""

import json
import logging
import sys
from typing import List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime

from feature_analyzer import FeatureAnalyzer
from llm_validator import LLMValidator

# ============================================================================
# ANSI Color codes
# ============================================================================
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

# ============================================================================
# SETUP LOGGING
# ============================================================================
class StageFormatter(logging.Formatter):
    """Custom formatter - no level prefix, just message"""
    def format(self, record):
        return record.getMessage()

log_file = Path(__file__).parent.parent.parent / "logs" / "validated_threats.log"
log_file.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
for handler in logger.handlers:
    handler.setFormatter(StageFormatter())

# ============================================================================
# LOGGING UTILITIES
# ============================================================================
def print_validation_header(title):
    """Print validation section header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {title}{' ' * (74 - len(title))}{Colors.ENDC}{Colors.CYAN}  ║{Colors.ENDC}{Colors.BOLD}")
    print(f"{Colors.CYAN}{'═' * 80}{Colors.ENDC}\n")

def print_info_box(content_lines, color=Colors.BLUE):
    """Print info in a colored box"""
    print(f"{color}┌{'─' * 78}┐{Colors.ENDC}")
    for line in content_lines:
        line = str(line)[:76]
        print(f"{color}│{Colors.ENDC} {line:<76} {color}│{Colors.ENDC}")
    print(f"{color}└{'─' * 78}┘{Colors.ENDC}\n")

def print_stats_box(stats_dict, color=Colors.GREEN):
    """Print statistics in a formatted box"""
    print(f"{color}╔{'═' * 78}╗{Colors.ENDC}")
    print(f"{color}║{Colors.ENDC} {Colors.BOLD}VALIDATION STATISTICS{Colors.ENDC}{' ' * 56} {color}║{Colors.ENDC}")
    print(f"{color}╠{'─' * 78}╣{Colors.ENDC}")
    
    for key, value in stats_dict.items():
        display_key = key.replace('_', ' ').title()
        line = f"{display_key}: {value}"
        print(f"{color}║{Colors.ENDC} {line:<76} {color}║{Colors.ENDC}")
    
    print(f"{color}╚{'═' * 78}╝{Colors.ENDC}\n")

# ============================================================================
# DATE TIME ENCODER
# ============================================================================
class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# ============================================================================
# CHROMADB INTEGRATION
# ============================================================================
def store_threats_in_chroma(validated_threats: List[Dict], chroma_client=None):
    """
    Store validated threats in ChromaDB all_threats collection.
    
    Args:
        validated_threats: List of validated threat results
        chroma_client: Optional ChromaDB client (will create if None)
    """
    try:
        import chromadb
        from chromadb.utils import embedding_functions
        
        # Initialize ChromaDB client if not provided
        if chroma_client is None:
            chroma_host = "chroma"
            chroma_port = 8000
            chroma_client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
        
        # Get or create collection
        default_ef = embedding_functions.DefaultEmbeddingFunction()
        
        try:
            collection = chroma_client.get_collection(
                name="all_threats",
                embedding_function=default_ef
            )
        except:
            collection = chroma_client.create_collection(
                name="all_threats",
                embedding_function=default_ef,
                metadata={"hnsw:space": "cosine"}
            )
        
        # Prepare documents for storage
        documents = []
        metadatas = []
        ids = []
        
        for idx, result in enumerate(validated_threats):
            threat = result.get("threat", {})
            analysis = result.get("analysis", {})
            llm_validation = result.get("llm_validation", {})
            
            # Extract key fields
            ip = threat.get("ip", "unknown")
            attack_type = threat.get("attack_type", "unknown")
            severity = threat.get("severity", "LOW")
            total_events = threat.get("total_events", 0)
            
            classification = analysis.get("classification", "UNKNOWN")
            llm_decision = llm_validation.get("decision", "UNKNOWN")
            
            # Create document text for embedding
            doc_text = f"""
            IP: {ip}
            Attack Type: {attack_type}
            Severity: {severity}
            Total Events: {total_events}
            Classification: {classification}
            LLM Decision: {llm_decision}
            Heuristic Flags: {', '.join(analysis.get('heuristic_flags', []))}
            Destination IPs: {', '.join(map(str, threat.get('dest_ips', [])))}
            Ports Targeted: {', '.join(map(str, threat.get('ports', [])))}
            Rules Violated: {', '.join([r.get('rule_id', '') for r in threat.get('rules_violated', [])])}
            """
            
            # Create metadata
            metadata = {
                "ip": ip,
                "attack_type": attack_type,
                "severity": severity,
                "total_events": total_events,
                "classification": classification,
                "llm_decision": llm_decision,
                "confidence_score": float(threat.get("confidence_score", 0.5)),
                "timestamp": datetime.now().isoformat(),
                "source": "validation_orchestrator"
            }
            
            # Create unique ID
            threat_id = f"threat_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{idx}"
            
            documents.append(doc_text.strip())
            metadatas.append(metadata)
            ids.append(threat_id)
        
        # Store in ChromaDB (batch upsert)
        if documents:
            collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            print_info_box([
                f"✅ Stored {len(documents)} validated threats in ChromaDB",
                f"   • Collection: all_threats",
                f"   • Threats can now be queried by analyst agent"
            ], Colors.GREEN)
        
        return len(documents)
        
    except Exception as e:
        logger.error(f"❌ Failed to store threats in ChromaDB: {e}")
        print_info_box([
            f"⚠️  Failed to store threats in ChromaDB",
            f"   Error: {str(e)}",
            f"   Threats are still saved to JSON file"
        ], Colors.YELLOW)
        return 0

# ============================================================================
# VALIDATION ORCHESTRATOR
# ============================================================================
class ValidationOrchestrator:
    """
    Orchestrates validation of raw security alerts before analysis.
    
    Workflow:
    1. Raw alerts → FeatureAnalyzer (heuristic filtering)
    2. Ambiguous alerts → LLMValidator (contextual validation)
    3. Validated alerts → Pipeline (preprocessing & batching)
    4. Store validated threats → ChromaDB all_threats collection
    """
    
    def __init__(
        self,
        enable_llm_validation: bool = True,
        ollama_model: str = "llama3.1:8b",
        ollama_url: str = None,
        enable_logging: bool = False,
        chroma_client=None
    ):
        """
        Initialize ValidationOrchestrator.
        
        Args:
            enable_llm_validation: Whether to use LLM for ambiguous cases
            ollama_model: Ollama model name for LLM validation
            ollama_url: Ollama API endpoint (default: http://ollama:11434)
            enable_logging: Whether to enable verbose logging
            chroma_client: Optional ChromaDB client for storing threats
        """
        self.enable_llm_validation = enable_llm_validation
        self.enable_logging = enable_logging
        self.chroma_client = chroma_client
        
        # Initialize FeatureAnalyzer
        self.feature_analyzer = FeatureAnalyzer(enable_logging=False)
        
        # Initialize LLMValidator if enabled
        if enable_llm_validation:
            try:
                self.llm_validator = LLMValidator(
                    model=ollama_model,
                    base_url=ollama_url,
                    enable_logging=False,
                    timeout_seconds=10.0
                )
            except Exception as e:
                logger.warning(f"⚠️  Failed to initialize LLM Validator: {e}")
                self.llm_validator = None
                self.enable_llm_validation = False
        else:
            self.llm_validator = None
    
    def validate_eve_json(self, eve_json_path: str) -> Tuple[List[Dict], Dict[str, int]]:
        """
        Validate raw Suricata eve.json alerts before pipeline processing.
        
        Args:
            eve_json_path: Path to eve.json file with Suricata alerts
        
        Returns:
            Tuple of (validated_alerts, stats):
            - validated_alerts: List of enriched alerts with validation results
            - stats: Dict with validation statistics
        """
        print_validation_header("🔍 AGGREGATION & FEATURE ANALYSIS PHASE")
        
        # Read raw eve.json
        try:
            with open(eve_json_path, 'r') as f:
                raw_alerts = [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            print_info_box([f"❌ Failed to read {eve_json_path}: {e}"], Colors.RED)
            return [], {"error": 1}
        
        print_info_box([f"📊 Processing {len(raw_alerts)} raw alerts"], Colors.CYAN)
        
        # ========================================================================
        # STEP 1: AGGREGATE ALERTS BY SOURCE IP (like api_response.json does)
        # ========================================================================
        aggregated_threats = self._aggregate_alerts_by_ip(raw_alerts)
        
        print_info_box([
            f"✅ Aggregated into {len(aggregated_threats)} unique threat sources",
            f"   • From {len(raw_alerts)} individual alerts"
        ], Colors.GREEN)
        
        # Statistics
        stats = {
            "total_alerts": len(raw_alerts),
            "validated": 0,
            "filtered_false_positive": 0,
            "filtered_benign": 0,
            "llm_validated": 0,
            "heuristic_validated": 0,
            "errors": 0,
            "stored_in_chromadb": 0
        }
        
        # Track classifications
        fa_classifications = {}
        llm_decisions = {}
        results = []
        
        # ========================================================================
        # STEP 2: RUN FEATURE ANALYZER ON AGGREGATED THREATS
        # ========================================================================
        for idx, threat in enumerate(aggregated_threats, 1):
            try:
                # Run FeatureAnalyzer
                fa_analysis = self.feature_analyzer.analyze_threat(threat)
                classification = fa_analysis.get("classification", "NEEDS_LLM_REVIEW")
                
                # Track classification
                fa_classifications[classification] = fa_classifications.get(classification, 0) + 1
                
                # Store result
                result = {
                    "threat": threat,
                    "analysis": fa_analysis
                }
                results.append(result)
                
            except Exception as e:
                stats["errors"] += 1
                logger.error(f"❌ Error analyzing threat {idx}: {e}")
                results.append({
                    "threat": threat,
                    "analysis": {"classification": "ERROR", "error": str(e)}
                })
        
        # Display Feature Analysis Results
        fa_stats = {
            "Total Threats": len(aggregated_threats),
            "False Positives": fa_classifications.get("FALSE_POSITIVE", 0),
            "Possible Threats": fa_classifications.get("POSSIBLE_THREAT", 0),
            "Needs LLM Review": fa_classifications.get("NEEDS_LLM_REVIEW", 0),
            "Errors": stats['errors']
        }
        print_stats_box(fa_stats, Colors.GREEN)
        
        # ========================================================================
        # STEP 3: LLM VALIDATION (if enabled and needed)
        # ========================================================================
        needs_llm_count = fa_classifications.get("NEEDS_LLM_REVIEW", 0)
        
        if needs_llm_count > 0:
            if self.enable_llm_validation and self.llm_validator:
                print_validation_header("🤖 LLM VALIDATION PHASE")
                print_info_box([
                    f"Running LLM validation on {needs_llm_count} ambiguous threats...",
                    f"Using model: {self.llm_validator.model}"
                ], Colors.YELLOW)
                
                llm_count = 0
                for result in results:
                    fa_classification = result['analysis'].get('classification')
                    
                    if fa_classification == "NEEDS_LLM_REVIEW":
                        try:
                            threat = result['threat']
                            fa_analysis = result['analysis']
                            
                            llm_count += 1
                            print(f"   🤖 Validating threat {llm_count}/{needs_llm_count}: {threat.get('ip', 'unknown')}")
                            
                            # Run LLM validation
                            llm_result = self.llm_validator.validate(threat, fa_analysis)
                            result['llm_validation'] = llm_result
                            
                            # Track decision
                            decision = llm_result.get('decision', 'UNKNOWN')
                            llm_decisions[decision] = llm_decisions.get(decision, 0) + 1
                            
                        except Exception as e:
                            logger.error(f"❌ LLM validation error: {e}")
                            result['llm_validation'] = {
                                "decision": "ERROR",
                                "error": str(e),
                                "validator_used": "fallback"
                            }
                
                # Calculate average latency
                valid_latencies = [
                    r['llm_validation']['latency_ms'] 
                    for r in results 
                    if 'llm_validation' in r and 'latency_ms' in r['llm_validation']
                ]
                avg_latency = sum(valid_latencies) / len(valid_latencies) if valid_latencies else 0
                
                llm_stats = {
                    "LLM Validations": len([r for r in results if 'llm_validation' in r]),
                    "Real Threats": llm_decisions.get("REAL_THREAT", 0),
                    "Suspicious": llm_decisions.get("SUSPICIOUS", 0),
                    "Benign": llm_decisions.get("BENIGN", 0),
                    "False Positives": llm_decisions.get("FALSE_POSITIVE", 0),
                    "Average Latency (ms)": round(avg_latency, 2)
                }
                print_stats_box(llm_stats, Colors.BLUE)
            else:
                print_info_box([
                    f"⚠️  {needs_llm_count} threats need LLM review",
                    f"   LLM validation is disabled or unavailable",
                    f"   Passing through conservatively"
                ], Colors.YELLOW)
        
        # ========================================================================
        # STEP 4: FINAL CLASSIFICATION
        # ========================================================================
        validated_threats = []
        
        for result in results:
            classification = result['analysis'].get('classification')
            llm_validation = result.get('llm_validation', {})
            llm_decision = llm_validation.get('decision', '')
            
            should_validate = False
            
            if classification == "POSSIBLE_THREAT":
                should_validate = True
                stats["heuristic_validated"] += 1
            
            elif classification == "FALSE_POSITIVE":
                should_validate = False
                stats["filtered_false_positive"] += 1
            
            elif classification == "NEEDS_LLM_REVIEW":
                if llm_decision in ["REAL_THREAT", "SUSPICIOUS"]:
                    should_validate = True
                    stats["llm_validated"] += 1
                elif llm_decision in ["BENIGN", "FALSE_POSITIVE"]:
                    should_validate = False
                    stats["filtered_benign"] += 1
                else:
                    should_validate = True
            
            elif classification == "ERROR":
                should_validate = True
            
            if should_validate:
                stats["validated"] += 1
                validated_threats.append(result)
        
        # ========================================================================
        # STEP 5: STORE IN CHROMADB
        # ========================================================================
        print_validation_header("💾 STORING IN CHROMADB")
        
        stored_count = store_threats_in_chroma(validated_threats, self.chroma_client)
        stats["stored_in_chromadb"] = stored_count
        
        # Final Summary
        final_stats = {
            "Total Alerts": stats['total_alerts'],
            "Aggregated Threats": len(aggregated_threats),
            "Validated": stats['validated'],
            "Filtered (False Positive)": stats['filtered_false_positive'],
            "Filtered (Benign)": stats['filtered_benign'],
            "Heuristic Validated": stats['heuristic_validated'],
            "LLM Validated": stats['llm_validated'],
            "Stored in ChromaDB": stats['stored_in_chromadb'],
            "Errors": stats['errors']
        }
        print_stats_box(final_stats, Colors.CYAN)
        
        return validated_threats, stats
    
    def _convert_eve_to_threat(self, eve_alert: Dict) -> Dict:
        """
        Convert Suricata eve.json alert to threat format for FeatureAnalyzer.
        
        Args:
            eve_alert: Single alert from eve.json
        
        Returns:
            Threat dictionary in FeatureAnalyzer format
        """
        alert_data = eve_alert.get("alert", {})
        timestamp = eve_alert.get("timestamp", "")
        src_ip = eve_alert.get("src_ip", "unknown")
        dest_ip = eve_alert.get("dest_ip", "unknown")
        dest_port = eve_alert.get("dest_port", 0)
        signature_id = alert_data.get("signature_id", 0)
        signature = alert_data.get("signature", "")
        severity = alert_data.get("severity", 3)
        
        # Map severity (1=high, 2=medium, 3=low in Suricata)
        severity_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
        severity_str = severity_map.get(severity, "MEDIUM")
        
        threat = {
            "ip": src_ip,
            "severity": severity_str,
            "severity_level": severity,
            "confidence_score": 0.5,
            "attack_type": signature,
            "total_events": 1,
            "rules_violated": [{
                "rule_id": signature_id,
                "rule_name": signature,
                "severity": severity_str
            }],
            "timestamps": [timestamp],
            "src_ips": [src_ip],
            "dest_ips": [dest_ip],
            "ports": [dest_port],
            "ml_anomalies": []
        }
        
        return threat
    
    def _aggregate_alerts_by_ip(self, raw_alerts: List[Dict]) -> List[Dict]:
        """
        Aggregate individual eve.json alerts into threat summaries by source IP.
        This mimics the format from api_response.json.
        
        Args:
            raw_alerts: List of individual eve.json alert records
        
        Returns:
            List of aggregated threat dictionaries
        """
        from collections import defaultdict
        from dateutil import parser as date_parser
        
        # Group by source IP
        ip_groups = defaultdict(lambda: {
            "alerts": [],
            "timestamps": [],
            "src_ips": set(),
            "dest_ips": set(),
            "ports": set(),
            "signature_ids": set(),
            "severities": [],
            "attack_types": set()
        })
        
        for alert in raw_alerts:
            src_ip = alert.get("src_ip", "unknown")
            
            group = ip_groups[src_ip]
            group["alerts"].append(alert)
            
            # Convert timestamp string to datetime object
            if alert.get("timestamp"):
                try:
                    # Parse ISO 8601 timestamp
                    timestamp_str = alert["timestamp"]
                    timestamp_dt = date_parser.parse(timestamp_str)
                    group["timestamps"].append(timestamp_dt)
                except Exception as e:
                    logger.warning(f"⚠️  Failed to parse timestamp: {timestamp_str}")
        
            group["src_ips"].add(src_ip)
            if alert.get("dest_ip"):
                group["dest_ips"].add(alert["dest_ip"])
            if alert.get("dest_port"):
                group["ports"].add(alert["dest_port"])
            
            alert_data = alert.get("alert", {})
            if alert_data.get("signature_id"):
                group["signature_ids"].add(str(alert_data["signature_id"]))
            if alert_data.get("severity"):
                group["severities"].append(alert_data["severity"])
            if alert_data.get("signature"):
                group["attack_types"].add(alert_data["signature"])
        
        # Convert to threat format
        aggregated_threats = []
        
        for ip, data in ip_groups.items():
            # Calculate severity (1=HIGH, 2=MEDIUM, 3=LOW in Suricata)
            avg_severity = sum(data["severities"]) / len(data["severities"]) if data["severities"] else 3
            
            if avg_severity <= 1.5:
                severity_str = "HIGH"
                severity_level = 1
            elif avg_severity <= 2.5:
                severity_str = "MEDIUM"
                severity_level = 2
            else:
                severity_str = "LOW"
                severity_level = 3
            
            # Determine attack type
            attack_type = "Reconnaissance / Scanning" if len(data["ports"]) > 3 else (
                list(data["attack_types"])[0] if data["attack_types"] else "Suspicious Activity"
            )
            
            # Build rules violated
            rules_violated = []
            if len(data["alerts"]) >= 10:
                rules_violated.append({
                    "rule_id": "suricata_alert_storm",
                    "description": f"High volume of Suricata alerts (>={len(data['alerts'])} in 4h)",
                    "severity": "high",
                    "count": len(data["alerts"]),
                    "threshold": 10,
                    "window": "4h"
                })
            
            if len(data["alerts"]) >= 5:
                rules_violated.append({
                    "rule_id": "suspicious_src_ip",
                    "description": "Single IP generating many alerts (>=5 in 4h)",
                    "severity": "high",
                    "group": ip,
                    "count": len(data["alerts"]),
                    "threshold": 5,
                    "window": "4h"
                })
            
            threat = {
                "ip": ip,
                "severity": severity_str,
                "severity_level": severity_level,
                "confidence_score": min(0.4 + (len(data["alerts"]) * 0.01), 1.0),
                "attack_type": attack_type,
                "total_events": len(data["alerts"]),
                "rules_violated": rules_violated,
                "ml_anomalies": [],
                "timestamps": sorted(data["timestamps"]),  # Now datetime objects
                "src_ips": list(data["src_ips"]),
                "dest_ips": list(data["dest_ips"]),
                "ports": list(data["ports"])
            }
            
            aggregated_threats.append(threat)
        
        # Sort by total_events descending
        aggregated_threats.sort(key=lambda x: x["total_events"], reverse=True)
        
        return aggregated_threats


# ============================================================================
# MAIN (for testing)
# ============================================================================
def main():
    """Test validation orchestrator."""
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'█' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.GREEN}█  🔐 SECURITY VALIDATION PIPELINE{' ' * (43)}{Colors.ENDC}{Colors.GREEN}█{Colors.ENDC}{Colors.BOLD}")
    print(f"{Colors.GREEN}{'█' * 80}{Colors.ENDC}\n")
    
    # Path to eve.json
    eve_json_path = Path(__file__).parent.parent.parent / "logs" / "eve.json"
    
    if not eve_json_path.exists():
        print_info_box([
            f"❌ eve.json not found",
            f"   Expected: {eve_json_path}"
        ], Colors.RED)
        return
    
    # Initialize orchestrator
    orchestrator = ValidationOrchestrator(
        enable_llm_validation=True,
        enable_logging=False
    )
    
    # Run validation
    try:
        validated_alerts, stats = orchestrator.validate_eve_json(str(eve_json_path))
        
        # Save results
        output_path = Path(__file__).parent.parent.parent / "logs" / "validated_threats.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump({
                "summary": stats,
                "detailed_results": validated_alerts
            }, f, indent=2, cls=DateTimeEncoder)
        
        print_info_box([
            f"✅ Validation complete",
            f"   • Results: {output_path}"
        ], Colors.GREEN)
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}{'█' * 80}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.GREEN}█  ✅ VALIDATION COMPLETE{' ' * (52)}{Colors.ENDC}{Colors.GREEN}█{Colors.ENDC}{Colors.BOLD}")
        print(f"{Colors.GREEN}{'█' * 80}{Colors.ENDC}\n")
        
    except Exception as e:
        print_info_box([f"❌ Validation failed: {e}"], Colors.RED)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
