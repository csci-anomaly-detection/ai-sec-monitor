

import os
import time
import logging
import json
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import ollama

from feature_analyzer import FeatureAnalyzer
from context_agent import ContextAgent


class ValidationOrchestrator:
    """
    Orchestrates multi-agent threat validation combining heuristic and contextual analysis.

    The ValidationOrchestrator coordinates two specialized agents:
    1. Feature Analyzer Agent: Fast heuristic-based pre-filtering
    2. Context Agent: Deep historical pattern analysis with RAG

    It uses weighted voting and conflict resolution to produce unified classifications.
    """

    # Classification constants
    REAL_THREAT = "REAL_THREAT"
    SUSPICIOUS = "SUSPICIOUS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_ANOMALY = "BENIGN_ANOMALY"

    # Recommendation constants
    FILTER = "filter"
    REVIEW = "review"
    ESCALATE = "escalate"

    def __init__(
        self,
        feature_analyzer: Optional[FeatureAnalyzer] = None,
        context_agent: Optional[ContextAgent] = None,
        confidence_weights: Optional[Dict[str, float]] = None,
        fast_path_threshold: float = 0.8,
        use_llm_consensus: bool = True,
        consensus_model: str = "llama3.1:8b",
        enable_logging: bool = True
    ):
        """
        Initialize ValidationOrchestrator with agent instances.

        Args:
            feature_analyzer: FeatureAnalyzer instance (creates default if None)
            context_agent: ContextAgent instance (creates default if None)
            confidence_weights: Custom confidence weights for each component (used for rule-based fallback)
                Default: {"ml_model": 0.2, "feature_analyzer": 0.3, "context_agent": 0.5}
            fast_path_threshold: Confidence threshold for fast-path optimization (default: 0.8)
            use_llm_consensus: Whether to use LLM for consensus decision (default: True)
            consensus_model: Ollama model for LLM consensus (default: "llama3.1:8b")
            enable_logging: Enable detailed logging (default: True)
        """
        # Initialize agents
        self.feature_analyzer = feature_analyzer or FeatureAnalyzer(enable_logging=enable_logging)
        self.context_agent = context_agent or ContextAgent(enable_logging=enable_logging)

        # Set confidence weights (used for rule-based fallback when LLM unavailable)
        self.confidence_weights = confidence_weights or {
            "ml_model": 0.2,
            "feature_analyzer": 0.3,
            "context_agent": 0.5
        }

        # Validate weights sum to 1.0
        weight_sum = sum(self.confidence_weights.values())
        if abs(weight_sum - 1.0) > 0.01:
            raise ValueError(f"Confidence weights must sum to 1.0 (got {weight_sum})")

        self.fast_path_threshold = fast_path_threshold
        self.use_llm_consensus = use_llm_consensus
        self.consensus_model = consensus_model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.enable_logging = enable_logging

        # Load consensus prompt template
        self.consensus_prompt_template = self._load_consensus_prompt()

        if enable_logging:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            logging.info(
                f"ValidationOrchestrator initialized with agents "
                f"(LLM consensus: {use_llm_consensus}, model: {self.consensus_model})"
            )

    def validate_threat(self, threat_data: Dict) -> Dict[str, Any]:
        """
        Main validation orchestration method.

        Coordinates validation through both agents and aggregates their decisions
        using weighted voting and conflict resolution logic.

        Args:
            threat_data (Dict): Threat data containing:
                - ip: Source IP address (required)
                - attack_type: Type of attack (required)
                - severity: Threat severity (required)
                - confidence_score: ML model confidence (required)
                - description: Threat description (optional)
                - timestamp: When occurred (optional)
                - total_events: Event count (optional)
                - timestamps: List of event timestamps (optional)
                - src_ips, dest_ips, ports: Traffic data (optional)

        Returns:
            Dict: Unified validation result containing:
            {
                "classification": str,
                "confidence": float,
                "recommendation": str,
                "reasoning": str,
                "agent_opinions": Dict,
                "confidence_breakdown": Dict,
                "decision_path": str,
                "latency_ms": int
            }
        """
        start_time = time.time()

        try:
            if self.enable_logging:
                logging.info(f"Starting validation for IP: {threat_data.get('ip', 'unknown')}")

            # Step 1: Run Feature Analyzer (Fast heuristic pre-filter)
            if self.enable_logging:
                logging.info("Running Feature Analyzer (heuristic pre-filter)")

            fa_result = self._run_feature_analyzer(threat_data)
            fa_classification = fa_result.get("classification")
            fa_confidence = fa_result.get("feature_analyzer_confidence_score", 0.5)

            # Step 2: Fast-path optimization for high-confidence Feature Analyzer decisions
            if fa_classification == "FALSE_POSITIVE" and fa_confidence >= self.fast_path_threshold:
                # High confidence false positive - skip Context Agent
                if self.enable_logging:
                    logging.info(f"Fast-path: FALSE_POSITIVE (confidence: {fa_confidence:.2f})")

                latency_ms = int((time.time() - start_time) * 1000)
                return self._build_fast_path_result(
                    threat_data, fa_result, self.FALSE_POSITIVE, latency_ms
                )

            elif fa_classification == "POSSIBLE_THREAT" and fa_confidence >= self.fast_path_threshold:
                # High confidence threat - map to SUSPICIOUS for review
                if self.enable_logging:
                    logging.info(f"Fast-path: SUSPICIOUS (confidence: {fa_confidence:.2f})")

                latency_ms = int((time.time() - start_time) * 1000)
                return self._build_fast_path_result(
                    threat_data, fa_result, self.SUSPICIOUS, latency_ms
                )

            # Step 3: Run Context Agent for ambiguous cases
            if self.enable_logging:
                logging.info("Running Context Agent (historical RAG analysis)")

            context_result = self._run_context_agent(threat_data)

            # Step 4: Aggregate decisions from both agents
            if self.enable_logging:
                logging.info("Aggregating decisions from both agents")

            unified_result = self._aggregate_decisions(
                threat_data,
                fa_result,
                context_result
            )

            # Add latency
            latency_ms = int((time.time() - start_time) * 1000)
            unified_result["latency_ms"] = latency_ms

            if self.enable_logging:
                logging.info(
                    f"Validation complete: {unified_result['classification']} "
                    f"(confidence: {unified_result['confidence']:.2f}, latency: {latency_ms}ms)"
                )

            return unified_result

        except Exception as e:
            logging.error(f"Error during validation: {str(e)}")
            latency_ms = int((time.time() - start_time) * 1000)

            # Return conservative fallback
            return {
                "classification": self.SUSPICIOUS,
                "confidence": 0.0,
                "recommendation": self.REVIEW,
                "reasoning": f"Validation error: {str(e)}",
                "agent_opinions": {},
                "confidence_breakdown": {
                    "ml_confidence": threat_data.get("confidence_score", 0.0),
                    "feature_analyzer_confidence": 0.0,
                    "context_agent_confidence": 0.0,
                    "combined_confidence": 0.0
                },
                "decision_path": "error_fallback",
                "latency_ms": latency_ms
            }

    def _run_feature_analyzer(self, threat_data: Dict) -> Dict:
        """Run Feature Analyzer and handle errors gracefully."""
        try:
            return self.feature_analyzer.analyze_threat(threat_data)
        except Exception as e:
            logging.error(f"Feature Analyzer error: {str(e)}")
            # Return neutral result
            return {
                "classification": "NEEDS_LLM_REVIEW",
                "ml_confidence_score": threat_data.get("confidence_score", 0.5),
                "feature_analyzer_confidence_score": 0.0,
                "reasoning": f"Feature Analyzer error: {str(e)}",
                "heuristic_flags": [],
                "analysis_results": {}
            }

    def _run_context_agent(self, threat_data: Dict) -> Dict:
        """Run Context Agent and handle errors gracefully."""
        try:
            # Map threat_data to Context Agent expected format
            context_threat_data = {
                "ip": threat_data.get("ip"),
                "attack_type": threat_data.get("attack_type"),
                "severity": threat_data.get("severity", "unknown").lower(),
                "description": threat_data.get("description", ""),
                "timestamp": threat_data.get("timestamp", datetime.now().isoformat())
            }

            return self.context_agent.analyze_context(context_threat_data)

        except Exception as e:
            logging.error(f"Context Agent error: {str(e)}")
            # Return neutral result
            return {
                "classification": self.SUSPICIOUS,
                "confidence": 0.0,
                "reasoning": f"Context Agent error: {str(e)}",
                "recommendation": self.REVIEW,
                "key_evidence": [],
                "context_summary": {}
            }

    def _aggregate_decisions(
        self,
        threat_data: Dict,
        fa_result: Dict,
        context_result: Dict
    ) -> Dict[str, Any]:
        """
        Aggregate decisions from both agents using LLM-based consensus or rule-based fallback.

        Args:
            threat_data: Original threat data
            fa_result: Feature Analyzer result
            context_result: Context Agent result

        Returns:
            Unified validation result with aggregated decision
        """
        # Extract confidences
        ml_confidence = threat_data.get("confidence_score", 0.5)
        fa_confidence = fa_result.get("feature_analyzer_confidence_score", 0.5)
        context_confidence = context_result.get("confidence", 0.5)

        # Map Feature Analyzer classification to unified scheme
        fa_unified_class = self._map_fa_classification(fa_result.get("classification"))

        # Context Agent already uses unified scheme
        context_class = context_result.get("classification", self.SUSPICIOUS)

        # Try LLM-based consensus first
        if self.use_llm_consensus:
            try:
                llm_decision = self._llm_consensus_decision(
                    threat_data, fa_result, fa_unified_class, fa_confidence,
                    context_result, context_class, context_confidence, ml_confidence
                )

                if llm_decision:
                    return llm_decision

            except Exception as e:
                if self.enable_logging:
                    logging.warning(f"LLM consensus failed: {e}. Falling back to rule-based aggregation.")

        # Fallback to rule-based aggregation
        return self._rule_based_aggregation(
            threat_data, fa_result, fa_unified_class, fa_confidence,
            context_result, context_class, context_confidence, ml_confidence
        )

    def _rule_based_aggregation(
        self,
        threat_data: Dict,
        fa_result: Dict,
        fa_unified_class: str,
        fa_confidence: float,
        context_result: Dict,
        context_class: str,
        context_confidence: float,
        ml_confidence: float
    ) -> Dict[str, Any]:
        """
        Rule-based decision aggregation (fallback when LLM unavailable).

        Args:
            threat_data: Original threat data
            fa_result: Feature Analyzer result
            fa_unified_class: Mapped Feature Analyzer classification
            fa_confidence: Feature Analyzer confidence
            context_result: Context Agent result
            context_class: Context Agent classification
            context_confidence: Context Agent confidence
            ml_confidence: ML model confidence

        Returns:
            Unified validation result
        """
        # Check for agreement
        if fa_unified_class == context_class:
            # Agents agree - combine confidences
            final_classification = fa_unified_class
            combined_confidence = self._calculate_combined_confidence(
                ml_confidence, fa_confidence, context_confidence
            )
            reasoning = self._combine_reasoning(
                fa_result.get("reasoning", ""),
                context_result.get("reasoning", ""),
                agreement=True
            )

        else:
            # Agents disagree - resolve conflict
            final_classification, combined_confidence, reasoning = self._resolve_conflict(
                fa_unified_class, fa_confidence,
                context_class, context_confidence,
                fa_result.get("reasoning", ""),
                context_result.get("reasoning", "")
            )

        # Determine recommendation
        recommendation = self._get_recommendation(final_classification, combined_confidence)

        return {
            "classification": final_classification,
            "confidence": round(combined_confidence, 3),
            "recommendation": recommendation,
            "reasoning": reasoning,
            "agent_opinions": {
                "feature_analyzer": {
                    "classification": fa_result.get("classification"),
                    "unified_classification": fa_unified_class,
                    "confidence": fa_confidence,
                    "reasoning": fa_result.get("reasoning", ""),
                    "flags": fa_result.get("heuristic_flags", [])
                },
                "context_agent": {
                    "classification": context_class,
                    "confidence": context_confidence,
                    "reasoning": context_result.get("reasoning", ""),
                    "evidence": context_result.get("key_evidence", [])
                }
            },
            "confidence_breakdown": {
                "ml_confidence": round(ml_confidence, 3),
                "feature_analyzer_confidence": round(fa_confidence, 3),
                "context_agent_confidence": round(context_confidence, 3),
                "combined_confidence": round(combined_confidence, 3),
                "weights": self.confidence_weights
            },
            "decision_path": "rule_based_aggregation"
        }

    def _map_fa_classification(self, fa_class: str) -> str:
        """
        Map Feature Analyzer classification to unified scheme.

        Feature Analyzer classes:
            FALSE_POSITIVE, POSSIBLE_THREAT, NEEDS_LLM_REVIEW

        Unified classes:
            REAL_THREAT, SUSPICIOUS, FALSE_POSITIVE, BENIGN_ANOMALY
        """
        mapping = {
            "FALSE_POSITIVE": self.FALSE_POSITIVE,
            "POSSIBLE_THREAT": self.SUSPICIOUS,  # Ambiguous, needs review
            "NEEDS_LLM_REVIEW": self.SUSPICIOUS  # Uncertain, needs review
        }
        return mapping.get(fa_class, self.SUSPICIOUS)

    def _calculate_combined_confidence(
        self,
        ml_confidence: float,
        fa_confidence: float,
        context_confidence: float
    ) -> float:
        """
        Calculate weighted combined confidence score.

        Uses configured weights:
            - ML Model: 20%
            - Feature Analyzer: 30%
            - Context Agent: 50%

        Returns:
            Combined confidence score (0.0 to 1.0)
        """
        combined = (
            ml_confidence * self.confidence_weights["ml_model"] +
            fa_confidence * self.confidence_weights["feature_analyzer"] +
            context_confidence * self.confidence_weights["context_agent"]
        )

        return max(0.0, min(1.0, combined))

    def _resolve_conflict(
        self,
        fa_class: str,
        fa_conf: float,
        context_class: str,
        context_conf: float,
        fa_reasoning: str,
        context_reasoning: str
    ) -> Tuple[str, float, str]:
        """
        Resolve conflicts when agents disagree.

        Conflict resolution strategy:
        1. If confidence difference > 0.3: Trust higher confidence agent
        2. If Context Agent says REAL_THREAT with confidence > 0.7: Escalate
        3. If Feature Analyzer says FALSE_POSITIVE with confidence > 0.7: Filter
        4. Otherwise: Mark as SUSPICIOUS (requires manual review)

        Returns:
            Tuple of (classification, confidence, reasoning)
        """
        confidence_diff = abs(fa_conf - context_conf)

        # Rule 1: Large confidence difference - trust higher confidence agent
        if confidence_diff > 0.3:
            if fa_conf > context_conf:
                return fa_class, fa_conf, f"Feature Analyzer (high confidence): {fa_reasoning}"
            else:
                return context_class, context_conf, f"Context Agent (high confidence): {context_reasoning}"

        # Rule 2: Context Agent says REAL_THREAT with high confidence - escalate
        if context_class == self.REAL_THREAT and context_conf > 0.7:
            return self.REAL_THREAT, context_conf, f"Context Agent detected threat (overriding heuristic): {context_reasoning}"

        # Rule 3: Feature Analyzer says FALSE_POSITIVE with high confidence - filter
        if fa_class == self.FALSE_POSITIVE and fa_conf > 0.7:
            return self.FALSE_POSITIVE, fa_conf, f"Feature Analyzer filtered (overriding context): {fa_reasoning}"

        # Rule 4: Conflicting signals with similar confidence - mark as SUSPICIOUS
        avg_confidence = (fa_conf + context_conf) / 2.0
        return (
            self.SUSPICIOUS,
            avg_confidence,
            f"Conflicting signals (FA: {fa_class}, Context: {context_class}). Manual review recommended."
        )

    def _combine_reasoning(self, fa_reasoning: str, context_reasoning: str, agreement: bool) -> str:
        """Combine reasoning from both agents into unified explanation."""
        if agreement:
            return f"Both agents agree. Heuristic: {fa_reasoning} | Context: {context_reasoning}"
        else:
            return f"Agents disagree. Heuristic: {fa_reasoning} | Context: {context_reasoning}"

    def _get_recommendation(self, classification: str, confidence: float) -> str:
        """
        Determine recommendation based on classification and confidence.

        Returns:
            "filter", "review", or "escalate"
        """
        if classification == self.FALSE_POSITIVE and confidence > 0.7:
            return self.FILTER

        elif classification == self.REAL_THREAT and confidence > 0.7:
            return self.ESCALATE

        elif classification == self.BENIGN_ANOMALY:
            return self.FILTER  # Log but don't alert

        else:
            # SUSPICIOUS or low confidence - requires manual review
            return self.REVIEW

    def _build_fast_path_result(
        self,
        threat_data: Dict,
        fa_result: Dict,
        classification: str,
        latency_ms: int
    ) -> Dict[str, Any]:
        """Build result for fast-path optimization (skipping Context Agent)."""
        ml_confidence = threat_data.get("confidence_score", 0.5)
        fa_confidence = fa_result.get("feature_analyzer_confidence_score", 0.5)

        # For fast path, combine only ML and Feature Analyzer confidence
        # (no Context Agent contribution)
        combined_confidence = (
            ml_confidence * self.confidence_weights["ml_model"] +
            fa_confidence * self.confidence_weights["feature_analyzer"]
        ) / (self.confidence_weights["ml_model"] + self.confidence_weights["feature_analyzer"])

        recommendation = self._get_recommendation(classification, combined_confidence)

        return {
            "classification": classification,
            "confidence": round(combined_confidence, 3),
            "recommendation": recommendation,
            "reasoning": f"Fast-path decision: {fa_result.get('reasoning', '')}",
            "agent_opinions": {
                "feature_analyzer": {
                    "classification": fa_result.get("classification"),
                    "unified_classification": classification,
                    "confidence": fa_confidence,
                    "reasoning": fa_result.get("reasoning", ""),
                    "flags": fa_result.get("heuristic_flags", [])
                },
                "context_agent": {
                    "classification": "SKIPPED",
                    "confidence": None,
                    "reasoning": "Skipped due to high-confidence fast-path decision",
                    "evidence": []
                }
            },
            "confidence_breakdown": {
                "ml_confidence": round(ml_confidence, 3),
                "feature_analyzer_confidence": round(fa_confidence, 3),
                "context_agent_confidence": None,
                "combined_confidence": round(combined_confidence, 3),
                "weights": self.confidence_weights
            },
            "decision_path": "fast_filter" if classification == self.FALSE_POSITIVE else "heuristic_pass",
            "latency_ms": latency_ms
        }

    def get_stats(self) -> Dict[str, Any]:
        """
        Get orchestrator statistics and configuration.

        Returns:
            Dictionary with orchestrator configuration and agent info
        """
        return {
            "agents": {
                "feature_analyzer": "FeatureAnalyzer (heuristic)",
                "context_agent": "ContextAgent (RAG + LLM)"
            },
            "confidence_weights": self.confidence_weights,
            "fast_path_threshold": self.fast_path_threshold,
            "use_llm_consensus": self.use_llm_consensus,
            "consensus_model": self.consensus_model,
            "classification_scheme": {
                "categories": [self.REAL_THREAT, self.SUSPICIOUS, self.FALSE_POSITIVE, self.BENIGN_ANOMALY],
                "recommendations": [self.FILTER, self.REVIEW, self.ESCALATE]
            }
        }

    def _load_consensus_prompt(self) -> str:
        """Load consensus prompt template from file."""
        try:
            prompt_path = Path(__file__).parent / "prompts" / "consensus_prompt.md"
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            if self.enable_logging:
                logging.warning(f"Failed to load consensus prompt template: {e}")
            # Return minimal fallback template
            return """You are a Consensus Agent. Analyze the following agent opinions and make a final decision.

Threat: {ip} - {attack_type} (Severity: {severity}, ML Confidence: {ml_confidence})

Feature Analyzer: {fa_classification} (confidence: {fa_confidence})
Reasoning: {fa_reasoning}

Context Agent: {context_classification} (confidence: {context_confidence})
Reasoning: {context_reasoning}

Provide your decision in JSON format:
{
  "classification": "REAL_THREAT | SUSPICIOUS | FALSE_POSITIVE | BENIGN_ANOMALY",
  "confidence": 0.0-1.0,
  "recommendation": "escalate | review | filter",
  "reasoning": "your explanation",
  "decision_factors": ["factor1", "factor2"],
  "agent_agreement": "agreed | disagreed",
  "primary_influence": "feature_analyzer | context_agent | both | conservative_fallback"
}"""

    def _llm_consensus_decision(
        self,
        threat_data: Dict,
        fa_result: Dict,
        fa_unified_class: str,
        fa_confidence: float,
        context_result: Dict,
        context_class: str,
        context_confidence: float,
        ml_confidence: float
    ) -> Optional[Dict[str, Any]]:
        """
        Use LLM to make consensus decision by analyzing both agents' opinions.

        Args:
            threat_data: Original threat data
            fa_result: Feature Analyzer result
            fa_unified_class: Unified Feature Analyzer classification
            fa_confidence: Feature Analyzer confidence
            context_result: Context Agent result
            context_class: Context Agent classification
            context_confidence: Context Agent confidence
            ml_confidence: ML model confidence

        Returns:
            Unified validation result from LLM consensus, or None if LLM call fails
        """
        # Build prompt with agent opinions
        prompt = self.consensus_prompt_template.format(
            ip=threat_data.get("ip", "unknown"),
            attack_type=threat_data.get("attack_type", "unknown"),
            severity=threat_data.get("severity", "unknown"),
            ml_confidence=f"{ml_confidence:.2f}",
            description=threat_data.get("description", ""),
            timestamp=threat_data.get("timestamp", ""),
            total_events=threat_data.get("total_events", 0),
            fa_classification=fa_unified_class,
            fa_confidence=f"{fa_confidence:.2f}",
            fa_reasoning=fa_result.get("reasoning", ""),
            fa_flags=", ".join(fa_result.get("heuristic_flags", [])),
            context_classification=context_class,
            context_confidence=f"{context_confidence:.2f}",
            context_reasoning=context_result.get("reasoning", ""),
            context_evidence=", ".join(context_result.get("key_evidence", []))
        )

        if self.enable_logging:
            logging.info("Calling LLM for consensus decision")

        # Call LLM
        try:
            response = ollama.chat(
                model=self.consensus_model,
                messages=[{"role": "user", "content": prompt}],
                format="json",
                options={"temperature": 0.1, "top_p": 0.9}
            )

            llm_output = response["message"]["content"]
            consensus_result = json.loads(llm_output)

            # Validate and normalize LLM response
            classification = consensus_result.get("classification", "").upper()
            valid_classes = [self.REAL_THREAT, self.SUSPICIOUS, self.FALSE_POSITIVE, self.BENIGN_ANOMALY]

            if classification not in valid_classes:
                if self.enable_logging:
                    logging.warning(f"Invalid LLM classification: {classification}. Falling back to rule-based.")
                return None

            # Normalize confidence
            confidence = float(consensus_result.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            # Build result
            return {
                "classification": classification,
                "confidence": round(confidence, 3),
                "recommendation": consensus_result.get("recommendation", self._get_recommendation(classification, confidence)),
                "reasoning": consensus_result.get("reasoning", "LLM consensus decision"),
                "agent_opinions": {
                    "feature_analyzer": {
                        "classification": fa_result.get("classification"),
                        "unified_classification": fa_unified_class,
                        "confidence": fa_confidence,
                        "reasoning": fa_result.get("reasoning", ""),
                        "flags": fa_result.get("heuristic_flags", [])
                    },
                    "context_agent": {
                        "classification": context_class,
                        "confidence": context_confidence,
                        "reasoning": context_result.get("reasoning", ""),
                        "evidence": context_result.get("key_evidence", [])
                    }
                },
                "confidence_breakdown": {
                    "ml_confidence": round(ml_confidence, 3),
                    "feature_analyzer_confidence": round(fa_confidence, 3),
                    "context_agent_confidence": round(context_confidence, 3),
                    "combined_confidence": round(confidence, 3),
                    "llm_consensus": True
                },
                "decision_path": "llm_consensus",
                "consensus_metadata": {
                    "decision_factors": consensus_result.get("decision_factors", []),
                    "agent_agreement": consensus_result.get("agent_agreement", "unknown"),
                    "primary_influence": consensus_result.get("primary_influence", "unknown")
                }
            }

        except Exception as e:
            if self.enable_logging:
                logging.error(f"LLM consensus error: {e}")
            return None
