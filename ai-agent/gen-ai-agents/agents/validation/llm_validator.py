import os
import logging
import time
import json
import re
from typing import Dict, Any
import ollama

def build_validation_prompt(threat_data: dict, feature_analyzer_result: dict) -> str:
    """
    Build LLM validation prompt from FeatureAnalyzer results.
    
    Args:
        threat_data: Original threat dictionary with ip, severity, confidence_score, etc.
        feature_analyzer_result: Output from FeatureAnalyzer.analyze_threat() with:
            - classification: "FALSE_POSITIVE", "NEEDS_LLM_REVIEW", "POSSIBLE_THREAT"
            - ml_confidence_score: float
            - feature_analyzer_confidence_score: float
            - reasoning: str
            - heuristic_flags: List[str]
            - analysis_results: {timing, ip_reputation, traffic}
    
    Returns:
        Formatted prompt string for LLM validation
    """
    
    # Extract from FeatureAnalyzer result
    fa_classification = feature_analyzer_result.get("classification", "NEEDS_LLM_REVIEW")
    ml_confidence = feature_analyzer_result.get("ml_confidence_score", 0.5)
    fa_confidence = feature_analyzer_result.get("feature_analyzer_confidence_score", 0.5)
    fa_reasoning = feature_analyzer_result.get("reasoning", "")
    heuristic_flags = feature_analyzer_result.get("heuristic_flags", [])
    analysis_results = feature_analyzer_result.get("analysis_results", {})
    
    # Extract timing analysis
    timing = analysis_results.get("timing", {})
    ip_reputation = analysis_results.get("ip_reputation", {})
    traffic = analysis_results.get("traffic", {})
    
    # Extract original threat data
    ip = threat_data.get("ip", "unknown")
    severity = threat_data.get("severity", "UNKNOWN")
    attack_type = threat_data.get("attack_type", "Unknown")
    total_events = threat_data.get("total_events", 0)
    rules_violated = threat_data.get("rules_violated", [])
    
    # Build prompt sections
    timing_section = f"""
TIMING ANALYSIS:
- Business hours: {timing.get("is_business_hours", False)}
- Maintenance window: {timing.get("is_maintenance_window", False)}
- Weekday: {timing.get("is_weekday", False)}
- Weekend: {timing.get("is_weekend", False)}
- Business hours ratio: {timing.get("business_hours_ratio", 0.0):.2%}
- Activity window: {timing.get("earliest_timestamp", "N/A")} to {timing.get("latest_timestamp", "N/A")}
"""
    
    ip_section = f"""
IP REPUTATION ANALYSIS:
- Source IP: {ip}
- All source IPs internal: {ip_reputation.get("all_src_internal", False)}
- Has external source: {ip_reputation.get("has_external_src", False)}
- Internal-to-internal: {ip_reputation.get("internal_to_internal", False)}
- External-to-internal: {ip_reputation.get("external_to_internal", False)}
- Unique source IPs: {ip_reputation.get("unique_src_ips", 0)}
"""
    
    traffic_section = f"""
TRAFFIC PATTERN ANALYSIS:
- Total events: {total_events}
- High volume: {traffic.get("high_volume", False)}
- Very high volume: {traffic.get("very_high_volume", False)}
- Low volume: {traffic.get("low_volume", False)}
- High request rate: {traffic.get("high_request_rate", False)}
- Burst activity: {traffic.get("burst_activity", False)}
- Has high severity rules: {traffic.get("has_high_severity_rules", False)}
- Rule violation count: {traffic.get("rule_violation_count", 0)}
- High success rate: {traffic.get("high_success_rate", False)}
"""
    
    heuristic_section = f"""
HEURISTIC FLAGS DETECTED:
{chr(10).join(f"- {flag}" for flag in heuristic_flags) if heuristic_flags else "- None"}
"""
    
    prompt = f"""You are a cybersecurity anomaly validator. Your job is to make the final classification decision after heuristic pre-filtering.

═══════════════════════════════════════════════════════════════
ORIGINAL THREAT DATA
═══════════════════════════════════════════════════════════════

- IP Address: {ip}
- Attack Type: {attack_type}
- Severity: {severity}
- Total Events: {total_events}
- ML Confidence Score: {ml_confidence:.2f}
- Rules Violated: {len(rules_violated)} rule(s)

═══════════════════════════════════════════════════════════════
HEURISTIC ANALYSIS RESULTS
═══════════════════════════════════════════════════════════════

FeatureAnalyzer Classification: {fa_classification}
FeatureAnalyzer Confidence: {fa_confidence:.2f}
FeatureAnalyzer Reasoning: {fa_reasoning if fa_reasoning else "No specific reasoning provided"}
{timing_section}
{ip_section}
{traffic_section}
{heuristic_section}

═══════════════════════════════════════════════════════════════
YOUR TASK: FINAL CLASSIFICATION
═══════════════════════════════════════════════════════════════

The FeatureAnalyzer has classified this as "{fa_classification}". Your job is to review this classification and make the final decision.

Classify into ONE of these categories:

1. REAL_THREAT: Malicious activity requiring immediate analysis
   - Indicators: Attack signatures, malicious payloads, persistent suspicious behavior
   - Even if timing seems normal, if attack indicators are present, classify as REAL_THREAT
   
2. SUSPICIOUS: Ambiguous case needing closer examination
   - Indicators: Some concerning patterns but not clearly malicious
   - Default choice when uncertain - better safe than sorry
   
3. FALSE_POSITIVE: Benign anomaly incorrectly flagged by ML
   - Indicators: Maintenance windows, known safe patterns, honeypot noise
   - Clear benign explanation (e.g., scheduled backup, legitimate traffic spike)
   
4. BENIGN_ANOMALY: Unusual but legitimate behavior
   - Indicators: Traffic spike during expected times (login windows, business hours)
   - Log for trending but not a security concern

═══════════════════════════════════════════════════════════════
DECISION GUIDELINES
═══════════════════════════════════════════════════════════════

Consider the FeatureAnalyzer classification:

- If FeatureAnalyzer says "FALSE_POSITIVE": 
  → Confirm if reasoning is sound, or upgrade to BENIGN_ANOMALY/SUSPICIOUS if context suggests otherwise
  
- If FeatureAnalyzer says "POSSIBLE_THREAT":
  → Evaluate if indicators are strong enough for REAL_THREAT or should be SUSPICIOUS
  
- If FeatureAnalyzer says "NEEDS_LLM_REVIEW":
  → This is why you're here - make the final call based on all available context

TIMING FACTORS:
- Business hours + internal traffic = likely BENIGN_ANOMALY or FALSE_POSITIVE
- Off-hours + external IP = more suspicious
- Maintenance window activity = likely FALSE_POSITIVE

TRAFFIC FACTORS:
- High volume + high success rate (90%+) = likely legitimate traffic
- High volume + low success rate = likely attack
- External IP + high severity rules = likely REAL_THREAT

CONFIDENCE FACTORS:
- ML confidence < 0.2 AND clear benign indicators = FALSE_POSITIVE
- ML confidence > 0.7 AND attack indicators = REAL_THREAT
- Mixed signals = SUSPICIOUS

═══════════════════════════════════════════════════════════════
REQUIRED OUTPUT FORMAT
═══════════════════════════════════════════════════════════════

Respond with JSON only (no markdown, no explanation outside JSON):

{{
  "decision": "REAL_THREAT" | "SUSPICIOUS" | "FALSE_POSITIVE" | "BENIGN_ANOMALY",
  "confidence": 0.00-1.00,
  "reasoning": "Brief 2-3 sentence explanation of why this classification",
  "proceed_to_analysis": true | false
}}

IMPORTANT:
- "proceed_to_analysis": true only for REAL_THREAT and SUSPICIOUS
- "proceed_to_analysis": false for FALSE_POSITIVE and BENIGN_ANOMALY
- Be conservative: When in doubt, choose SUSPICIOUS (fail-open approach)
- Confidence should reflect certainty: 0.9+ = very sure, 0.5-0.7 = uncertain
- Consider both ML confidence ({ml_confidence:.2f}) and FeatureAnalyzer confidence ({fa_confidence:.2f}) when setting your confidence

Begin your analysis now. Return JSON only."""
    
    return prompt

class LLMValidator:
    """
    Single-agent LLM validator for anomaly classification.
    Uses LLM to provide contextual analysis of threats 
    that couldn't be confidently classified by FeatureAnalyzer heuristics.
    """
    
    def __init__(
        self,
        model: str = None,
        base_url: str = None,
        temperature: float = 0.0,
        max_retries: int = 2,
        timeout_seconds: float = 5.0,
        enable_logging: bool = True
    ):
        """
        Initialize LLMValidator with configuration.
        
        Args:
            model: Ollama model name (default: "llama3.1:8b" or OLLAMA_MODEL env var)
            base_url: Ollama API endpoint URL (default: None uses ollama library default)
            temperature: LLM temperature for deterministic output (default: 0.0)
            max_retries: Maximum retry attempts for LLM calls (default: 2)
            timeout_seconds: Timeout for LLM API calls in seconds (default: 5.0)
            enable_logging: Whether to enable logging (default: True)
        """
        # Load configuration from environment variables with fallback to defaults
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.base_url = base_url or os.getenv("OLLAMA_URL", None)
        self.temperature = float(os.getenv("OLLAMA_TEMPERATURE", temperature))
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", max_retries))
        self.timeout_seconds = float(os.getenv("LLM_TIMEOUT", timeout_seconds))
        self.enable_logging = enable_logging
        
        # Validate parameters
        if self.temperature < 0.0 or self.temperature > 1.0:
            raise ValueError(f"Temperature must be between 0.0 and 1.0, got {self.temperature}")
        
        if self.max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {self.max_retries}")
        
        if self.timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be > 0, got {self.timeout_seconds}")
        
        # Set up Ollama client
        # If base_url is provided, use custom client, otherwise use default ollama.chat()
        if self.base_url:
            self.client = ollama.Client(host=self.base_url)
        else:
            self.client = None  # Use default ollama.chat() method
        
        # Set up logging
        if self.enable_logging:
            self.logger = logging.getLogger(__name__)
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
                self.logger.setLevel(logging.INFO)
        else:
            self.logger = None
        
        # Log initialization (commented out for cleaner output)
        # if self.logger:
        #     self.logger.info(
        #         f"LLMValidator initialized: model={self.model}, "
        #         f"base_url={self.base_url or 'default'}, "
        #         f"temperature={self.temperature}, "
        #         f"max_retries={self.max_retries}, "
        #         f"timeout={self.timeout_seconds}s"
        #     )

    
    def validate(
        self,
        threat_data: Dict,
        feature_analyzer_result: Dict
    ) -> Dict[str, Any]:
        """
        Main validation method that orchestrates the LLM validation process.
        
        Args:
            threat_data: Original threat dictionary with:
                - ip: str
                - severity: str
                - attack_type: str
                - total_events: int
                - confidence_score: float
                - rules_violated: List[Dict]
                - timestamps: List[datetime]
                - src_ips: List[str]
                - dest_ips: List[str]
                - ports: List[int]
                - ml_anomalies: List[Dict]
                
            feature_analyzer_result: Output from FeatureAnalyzer.analyze_threat() with:
                - classification: str ("FALSE_POSITIVE", "NEEDS_LLM_REVIEW", "POSSIBLE_THREAT")
                - ml_confidence_score: float
                - feature_analyzer_confidence_score: float
                - reasoning: str
                - heuristic_flags: List[str]
                - analysis_results: Dict with timing, ip_reputation, traffic keys
        
        Returns:
            Dictionary with validation decision:
            {
                "decision": str,  # "REAL_THREAT", "SUSPICIOUS", "FALSE_POSITIVE", "BENIGN_ANOMALY"
                "confidence": float,  # 0.0-1.0
                "reasoning": str,
                "proceed_to_analysis": bool,
                "validator_used": str,  # "llm_validator" or "fallback"
                "llm_response_raw": str | None,  # Raw LLM response for debugging
                "errors": List[str],  # List of any warnings/errors
                "latency_ms": float  # Total validation latency
            }
        """
        start_time = time.time()
        errors = []
        
        # Input validation
        if not isinstance(threat_data, dict):
            raise ValueError(f"threat_data must be a dictionary, got {type(threat_data)}")
        
        if not isinstance(feature_analyzer_result, dict):
            raise ValueError(f"feature_analyzer_result must be a dictionary, got {type(feature_analyzer_result)}")
        
        # Check required fields in threat_data
        required_fields = ["ip"]
        missing_fields = [field for field in required_fields if field not in threat_data]
        if missing_fields:
            raise ValueError(f"threat_data missing required fields: {missing_fields}")
        
        # Check required fields in feature_analyzer_result
        if "classification" not in feature_analyzer_result:
            raise ValueError("feature_analyzer_result must contain 'classification' field")
        
        # Extract IP for logging
        ip = threat_data.get("ip", "unknown")
        
        # if self.logger:
        #     self.logger.info(
        #         f"Starting LLM validation for threat: IP={ip}, "
        #         f"FA_Classification={feature_analyzer_result.get('classification')}"
        #     )
        
        # Build validation prompt
        prompt = build_validation_prompt(threat_data, feature_analyzer_result)
        # Call LLM
        llm_result = self._call_llm(prompt)
        
        # Check if LLM call succeeded
        if not llm_result["success"]:
            error_msg = f"LLM call failed: {llm_result.get('error')}"
            errors.append(error_msg)
            # if self.logger:
            #     self.logger.error(
            #         f"LLM validation failed for IP={ip}: {error_msg}"
            #     )
            # Fail-open: return SUSPICIOUS to ensure threats are not missed
            return {
                "decision": "SUSPICIOUS",
                "confidence": 0.5,
                "reasoning": f"LLM validation failed: {error_msg}. Defaulting to SUSPICIOUS (fail-open approach).",
                "proceed_to_analysis": True,
                "validator_used": "error_fallback",
                "llm_response_raw": None,
                "errors": errors,
                "latency_ms": (time.time() - start_time) * 1000
            }
        
        # Parse LLM response
        response_text = llm_result["response_text"]
        # print(response_text)
        # Parse the JSON response
        try:
            parsed_result = self._parse_llm_response(response_text)
        except Exception as e:
            error_msg = f"Failed to parse LLM response: {e}"
            errors.append(error_msg)
            # if self.logger:
            #     self.logger.error(
            #         f"LLM response parsing failed for IP={ip}: {error_msg}"
            #     )
            # Fail-open: return SUSPICIOUS
            return {
                "decision": "SUSPICIOUS",
                "confidence": 0.5,
                "reasoning": f"Failed to parse LLM response: {error_msg}. Defaulting to SUSPICIOUS (fail-open approach).",
                "proceed_to_analysis": True,
                "validator_used": "error_fallback",
                "llm_response_raw": response_text,
                "errors": errors,
                "latency_ms": (time.time() - start_time) * 1000
            }
        
        # Validate parsed result
        if not isinstance(parsed_result, dict):
            error_msg = f"Parsed result is not a dictionary: {type(parsed_result)}"
            errors.append(error_msg)
            # if self.logger:
            #     self.logger.error(f"Invalid parsed result for IP={ip}: {error_msg}")
            # Fail-open: return SUSPICIOUS
            return {
                "decision": "SUSPICIOUS",
                "confidence": 0.5,
                "reasoning": f"Invalid parsed result: {error_msg}. Defaulting to SUSPICIOUS (fail-open approach).",
                "proceed_to_analysis": True,
                "validator_used": "error_fallback",
                "llm_response_raw": response_text,
                "errors": errors,
                "latency_ms": (time.time() - start_time) * 1000
            }
        
        # Ensure required fields exist and normalize values
        decision = parsed_result.get("decision", "").upper()
        valid_decisions = ["REAL_THREAT", "SUSPICIOUS", "FALSE_POSITIVE", "BENIGN_ANOMALY"]
        
        if decision not in valid_decisions:
            error_msg = f"Invalid decision '{decision}', must be one of {valid_decisions}"
            errors.append(error_msg)
            # if self.logger:
            #     self.logger.warning(f"Invalid decision for IP={ip}, defaulting to SUSPICIOUS")
            decision = "SUSPICIOUS"  # Fail-open approach
        
        # Normalize confidence (clamp to 0.0-1.0)
        confidence = parsed_result.get("confidence", 0.5)
        try:
            confidence = float(confidence)
            confidence = max(0.0, min(1.0, confidence))  # Clamp to [0.0, 1.0]
        except (ValueError, TypeError):
            error_msg = f"Invalid confidence value: {parsed_result.get('confidence')}"
            errors.append(error_msg)
            confidence = 0.5  # Default confidence
        
        # Get reasoning
        reasoning = parsed_result.get("reasoning", "")
        if not reasoning or not isinstance(reasoning, str):
            reasoning = "LLM classification (reasoning not provided)"
        
        # Determine proceed_to_analysis based on decision
        proceed_to_analysis = parsed_result.get("proceed_to_analysis")
        if proceed_to_analysis is None:
            # Infer from decision if not provided
            proceed_to_analysis = decision in ["REAL_THREAT", "SUSPICIOUS"]
        
        # Calculate total latency
        total_latency_ms = (time.time() - start_time) * 1000
        
        # Build final result
        result = {
            "decision": decision,
            "confidence": confidence,
            "reasoning": reasoning,
            "proceed_to_analysis": bool(proceed_to_analysis),
            "validator_used": "llm_validator",
            "llm_response_raw": response_text,
            "errors": errors,
            "latency_ms": total_latency_ms
        }
        
        # Log success (commented out for cleaner output)
        # if self.logger:
        #     self.logger.info(
        #         f"LLM validation completed for IP={ip}: decision={decision}, "
        #         f"confidence={confidence:.2f}, latency={total_latency_ms:.2f}ms"
        #     )
        
        return result
    
    def _call_llm(
        self,
        prompt: str
    ) -> Dict[str, Any]:
        """
        Call Ollama and get response text.
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            Dictionary with:
            {
                "success": bool,
                "response_text": str | None,
                "error": str | None,
                "latency_ms": float
            }
        """
        start_time = time.time()
        
        try:
            # Call Ollama
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={'temperature': self.temperature},
                format="json"
            )
            # print(response['message']['content'])
            # Extract response text
            response_text = response['message']['content']
            latency_ms = (time.time() - start_time) * 1000
            return {
                "success": True,
                "response_text": response_text,
                "error": None,
                "latency_ms": latency_ms
            }
            
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            
            return {
                "success": False,
                "response_text": None,
                "error": str(e),
                "latency_ms": latency_ms
            }
    
    def _parse_llm_response(
        self,
        response_text: str
    ) -> Dict[str, Any]:
        """
        Parse JSON response from LLM, handling various formats.
        
        LLMs often return JSON wrapped in markdown code blocks or with explanatory text.
        This function tries multiple strategies to extract valid JSON.
        
        Args:
            response_text: Raw response text from LLM
            
        Returns:
            Dictionary parsed from JSON response with keys:
            - decision: str
            - confidence: float
            - reasoning: str
            - proceed_to_analysis: bool (optional)
            
        Raises:
            ValueError: If no valid JSON can be extracted from response_text
        """
        if not response_text or not isinstance(response_text, str):
            raise ValueError(f"response_text must be a non-empty string, got {type(response_text)}")
        
        # Clean up response text
        response_text = response_text.strip()
        
        # Pattern: ```json ... ``` or ``` ... ```
        json_patterns = [
            r'```json\s*(\{.*?\})\s*```',  # ```json { ... } ```
            r'```\s*(\{.*?\})\s*```',      # ``` { ... } ```
            r'```json\s*(\[.*?\])\s*```',  # ```json [ ... ] ``` (if array)
            r'```\s*(\[.*?\])\s*```',     # ``` [ ... ] ``` (if array)
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
            if match:
                try:
                    json_str = match.group(1).strip()
                    parsed = json.loads(json_str)
                    if isinstance(parsed, dict):
                        # if self.logger:
                        #     self.logger.debug(f"Extracted JSON from markdown code block")
                        return parsed
                except json.JSONDecodeError as e:
                    # if self.logger:
                    #     self.logger.debug(f"Failed to parse JSON from markdown: {e}")
                    continue
        
        # Look for { ... } pattern with balanced braces (handles nested objects)
        start_idx = response_text.find('{')
        if start_idx != -1:
            # Find matching closing brace by counting braces
            brace_count = 0
            end_idx = start_idx
            for i in range(start_idx, len(response_text)):
                if response_text[i] == '{':
                    brace_count += 1
                elif response_text[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
            
            if brace_count == 0 and end_idx > start_idx:
                try:
                    json_str = response_text[start_idx:end_idx]
                    parsed = json.loads(json_str)
                    if isinstance(parsed, dict):
                        # if self.logger:
                        #     self.logger.debug(f"Extracted JSON object from text")
                        return parsed
                except json.JSONDecodeError:
                    pass
        
        # Strategy 3: Try parsing entire response as JSON (if LLM returned pure JSON)
        try:
            parsed = json.loads(response_text)
            if isinstance(parsed, dict):
                # if self.logger:
                #     self.logger.debug(f"Parsed entire response as JSON")
                return parsed
        except json.JSONDecodeError:
            pass
        
        # Strategy 4: Try to find JSON-like structure with more lenient pattern
        # Look for text that looks like JSON but might have minor formatting issues
        json_like_pattern = r'\{[^}]*"decision"[^}]*"confidence"[^}]*"reasoning"[^}]*\}'
        match = re.search(json_like_pattern, response_text, re.DOTALL | re.IGNORECASE)
        if match:
            json_str = match.group(0)
            # Try to fix common issues
            # Remove trailing commas before closing braces
            json_str = re.sub(r',\s*}', '}', json_str)
            json_str = re.sub(r',\s*]', ']', json_str)
            try:
                parsed = json.loads(json_str)
                if isinstance(parsed, dict):
                    # if self.logger:
                    #     self.logger.debug(f"Extracted JSON-like structure after cleanup")
                    return parsed
            except json.JSONDecodeError:
                pass
        
        # All strategies failed
        error_msg = (
            f"Could not extract valid JSON from LLM response. "
            f"Response preview: {response_text[:200]}..."
        )
        # if self.logger:
        #     self.logger.error(error_msg)
        raise ValueError(error_msg)