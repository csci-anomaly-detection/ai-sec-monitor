"""
Validation Orchestrator - Integrates validation layer with the analysis pipeline.

This module coordinates the FeatureAnalyzer and LLMValidator to pre-filter
security alerts before they enter the batching and analysis stages.
"""

import json
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path


from feature_analyzer import FeatureAnalyzer
from llm_validator import LLMValidator

logger = logging.getLogger(__name__)


class ValidationOrchestrator:
    """
    Orchestrates validation of raw security alerts before analysis.
    
    Workflow:
    1. Raw alerts → FeatureAnalyzer (heuristic filtering)
    2. Ambiguous alerts → LLMValidator (contextual validation)
    3. Validated alerts → Pipeline (preprocessing & batching)
    """
    
    def __init__(
        self,
        enable_llm_validation: bool = True,
        ollama_model: str = "llama3.1:8b",
        ollama_url: str = None,
        enable_logging: bool = True
    ):
        """
        Initialize ValidationOrchestrator.
        
        Args:
            enable_llm_validation: Whether to use LLM for ambiguous cases
            ollama_model: Ollama model name for LLM validation
            ollama_url: Ollama API endpoint (default: http://ollama:11434)
            enable_logging: Whether to enable logging
        """
        self.enable_llm_validation = enable_llm_validation
        self.enable_logging = enable_logging
        
        # Initialize FeatureAnalyzer with default settings
        self.feature_analyzer = FeatureAnalyzer(enable_logging=enable_logging)
        
        # Initialize LLMValidator if enabled
        if enable_llm_validation:
            self.llm_validator = LLMValidator(
                model=ollama_model,
                base_url=ollama_url,
                enable_logging=enable_logging
            )
        else:
            self.llm_validator = None
            
        if self.enable_logging:
            logger.info(f"✅ ValidationOrchestrator initialized (LLM: {enable_llm_validation})")
    
    def validate_eve_json(self, eve_json_path: str) -> Tuple[List[Dict], Dict[str, int]]:
        """
        Validate raw Suricata eve.json alerts before pipeline processing.
        
        Args:
            eve_json_path: Path to eve.json file with Suricata alerts
        
        Returns:
            Tuple of (validated_alerts, stats):
            - validated_alerts: List of alerts that passed validation
            - stats: Dict with validation statistics
        """
        if self.enable_logging:
            logger.info(f"🔍 Validating alerts from: {eve_json_path}")
        
        # Read raw eve.json
        try:
            with open(eve_json_path, 'r') as f:
                raw_alerts = [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            logger.error(f"❌ Failed to read {eve_json_path}: {e}")
            return [], {"error": 1}
        
        if self.enable_logging:
            logger.info(f"📊 Processing {len(raw_alerts)} raw alerts")
        
        # Statistics
        stats = {
            "total_alerts": len(raw_alerts),
            "validated": 0,
            "filtered_false_positive": 0,
            "filtered_benign": 0,
            "llm_validated": 0,
            "heuristic_validated": 0,
            "errors": 0
        }
        
        validated_alerts = []
        
        for alert in raw_alerts:
            try:
                # Convert eve.json alert to threat format for FeatureAnalyzer
                threat = self._convert_eve_to_threat(alert)
                
                # Run FeatureAnalyzer
                fa_result = self.feature_analyzer.analyze_threat(threat)
                classification = fa_result.get("classification", "NEEDS_LLM_REVIEW")
                
                # Handle classification
                if classification == "FALSE_POSITIVE":
                    stats["filtered_false_positive"] += 1
                    if self.enable_logging:
                        logger.debug(f"⛔ Filtered false positive: {threat.get('ip')}")
                    continue
                
                elif classification == "POSSIBLE_THREAT":
                    # Pass through heuristic validation
                    stats["heuristic_validated"] += 1
                    stats["validated"] += 1
                    validated_alerts.append(alert)
                    if self.enable_logging:
                        logger.debug(f"✅ Heuristic validated: {threat.get('ip')}")
                
                elif classification == "NEEDS_LLM_REVIEW":
                    if self.enable_llm_validation and self.llm_validator:
                        # Use LLM for final decision
                        llm_result = self.llm_validator.validate(threat, fa_result)
                        decision = llm_result.get("decision", "SUSPICIOUS")
                        
                        if decision in ["REAL_THREAT", "SUSPICIOUS"]:
                            stats["llm_validated"] += 1
                            stats["validated"] += 1
                            validated_alerts.append(alert)
                            if self.enable_logging:
                                logger.debug(f"✅ LLM validated: {threat.get('ip')} ({decision})")
                        else:
                            stats["filtered_benign"] += 1
                            if self.enable_logging:
                                logger.debug(f"⛔ LLM filtered: {threat.get('ip')} ({decision})")
                    else:
                        # No LLM, pass through ambiguous cases
                        stats["validated"] += 1
                        validated_alerts.append(alert)
                        if self.enable_logging:
                            logger.debug(f"⚠️  Passed through (no LLM): {threat.get('ip')}")
            
            except Exception as e:
                logger.error(f"❌ Error validating alert: {e}")
                stats["errors"] += 1
                # Pass through on error (conservative approach)
                validated_alerts.append(alert)
                stats["validated"] += 1
        
        # Log summary
        if self.enable_logging:
            logger.info(f"✅ Validation complete:")
            logger.info(f"   - Total: {stats['total_alerts']}")
            logger.info(f"   - Validated: {stats['validated']}")
            logger.info(f"   - Filtered (FP): {stats['filtered_false_positive']}")
            logger.info(f"   - Filtered (Benign): {stats['filtered_benign']}")
            logger.info(f"   - Heuristic: {stats['heuristic_validated']}")
            logger.info(f"   - LLM: {stats['llm_validated']}")
            logger.info(f"   - Errors: {stats['errors']}")
        
        return validated_alerts, stats
    
    def _convert_eve_to_threat(self, eve_alert: Dict) -> Dict:
        """
        Convert Suricata eve.json alert to threat format for FeatureAnalyzer.
        
        Args:
            eve_alert: Single alert from eve.json
        
        Returns:
            Threat dictionary in FeatureAnalyzer format
        """
        # Extract fields from eve.json alert
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
        
        # Build threat dict
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
    
    def save_validated_alerts(self, validated_alerts: List[Dict], output_path: str):
        """
        Save validated alerts back to eve.json format.
        
        Args:
            validated_alerts: List of validated alerts
            output_path: Path to save validated eve.json
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                for alert in validated_alerts:
                    f.write(json.dumps(alert) + '\n')
            
            if self.enable_logging:
                logger.info(f"💾 Saved {len(validated_alerts)} validated alerts to: {output_path}")
        
        except Exception as e:
            logger.error(f"❌ Failed to save validated alerts: {e}")
            raise
