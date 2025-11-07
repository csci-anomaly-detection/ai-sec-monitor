import os
import logging
import time
import json
import re
from typing import Dict, Any
import ollama

from .validating_prompt import build_validation_prompt

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