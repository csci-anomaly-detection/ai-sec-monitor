import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import ollama
import chromadb

class ContextAgent:
    """
    Context Agent analyzes historical and temporal patterns for anomaly validation.
    
    Uses RAG to query historical threat data and identify:
    - Recurring false positive patterns
    - Historical IP behavior
    - Temporal correlations (same time-of-day patterns)
    - Known benign activity patterns
    """

    def __init__(
        self,
        model: str = "llama3.1:8b",
        chroma_client = None,
        enable_logging: bool = True
    ):
        """
        Initialize ContextAgent.

        Args:
            model: Ollama model name for LLM analysis (default: "llama3.1:8b")
            chroma_client: ChromaDB client instance (optional, will create if not provided)
            enable_logging: Enable logging for debugging (default: True)
        """
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.chroma_client = chroma_client
        self.enable_logging = enable_logging

        if enable_logging:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )

    def analyze_context(self, threat_data: Dict) -> Dict:
        """
        Main orchestration function for context-based threat classification.

        Coordinates all context analysis steps:
        1. Gather IP history from ChromaDB
        2. Analyze IP reputation based on historical behavior
        3. Find similar threats using semantic search
        4. Build comprehensive prompt with all context
        5. Send to LLM for final classification decision

        Args:
            threat_data (Dict): Current threat data containing:
                - ip: Source IP address (required)
                - attack_type: Type of attack detected (required)
                - severity: Threat severity level (required)
                - description: Threat description (optional)
                - timestamp: When threat occurred (optional)

        Returns:
            Dict: Classification decision containing:
            {
                "classification": str,  # REAL_THREAT, SUSPICIOUS, FALSE_POSITIVE, or BENIGN_ANOMALY
                "confidence": float,    # 0.0 to 1.0
                "reasoning": str,       # Detailed explanation of decision
                "recommendation": str,  # filter, review, or escalate
                "key_evidence": List[str],  # Key factors in decision
                "context_summary": Dict  # Raw context data for debugging
            }

        Raises:
            ValueError: If required fields missing from threat_data
            Exception: If LLM analysis fails (returns error context)
        """
        try:
            # Validate required fields
            if not threat_data.get("ip"):
                raise ValueError("threat_data must contain 'ip' field")
            if not threat_data.get("attack_type"):
                raise ValueError("threat_data must contain 'attack_type' field")
            if not threat_data.get("severity"):
                raise ValueError("threat_data must contain 'severity' field")

            ip = threat_data["ip"]

            if self.enable_logging:
                logging.info(f"Starting context analysis for IP: {ip}")

            # Step 1: Gather IP historical context
            if self.enable_logging:
                logging.info(f"Gathering IP history for {ip}")
            ip_history = self._gather_ip_history(ip)

            # Step 2: Analyze IP reputation
            if self.enable_logging:
                logging.info(f"Analyzing IP reputation for {ip}")
            ip_reputation = self._analyze_ip_reputation(ip, ip_history)

            # Step 3: Query similar threats
            if self.enable_logging:
                logging.info(f"Querying similar threats for {ip}")
            similar_threats = self._query_similar_threats(threat_data)

            # Step 4: Build context summary
            context_summary = {
                "ip_history": ip_history,
                "ip_reputation": ip_reputation,
                "similar_threats": similar_threats
            }

            # Step 5: Build prompt with all context
            if self.enable_logging:
                logging.info(f"Building context prompt for {ip}")
            prompt = self._build_context_prompt(threat_data, context_summary)

            # Step 6: Send to LLM for classification
            if self.enable_logging:
                logging.info(f"Sending to LLM for classification (model: {self.model})")

            response = ollama.chat(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                format="json",  # Enforce JSON output
                options={
                    "temperature": 0.1,  # Low temperature for consistent, deterministic output
                    "top_p": 0.9
                }
            )

            # Step 7: Parse LLM response
            llm_output = response["message"]["content"]
            classification_result = json.loads(llm_output)

            # Step 8: Add context summary for debugging/auditing
            classification_result["context_summary"] = context_summary

            if self.enable_logging:
                logging.info(
                    f"Classification complete for {ip}: "
                    f"{classification_result.get('classification', 'UNKNOWN')} "
                    f"(confidence: {classification_result.get('confidence', 0.0):.2f})"
                )

            return classification_result

        except ValueError as ve:
            logging.error(f"Validation error: {str(ve)}")
            raise

        except json.JSONDecodeError as je:
            logging.error(f"Failed to parse LLM response as JSON: {str(je)}")
            # Return error classification
            return {
                "classification": "SUSPICIOUS",
                "confidence": 0.0,
                "reasoning": f"LLM response parsing failed: {str(je)}",
                "recommendation": "review",
                "key_evidence": ["Error during LLM analysis"],
                "context_summary": context_summary if 'context_summary' in locals() else {}
            }

        except Exception as e:
            logging.error(f"Error during context analysis for {threat_data.get('ip', 'unknown')}: {str(e)}")
            # Return conservative classification on error
            return {
                "classification": "SUSPICIOUS",
                "confidence": 0.0,
                "reasoning": f"Context analysis error: {str(e)}",
                "recommendation": "review",
                "key_evidence": ["Error during context analysis"],
                "context_summary": {}
            }

    def _gather_ip_history(self, ip: str) -> Dict:
        """
        Retrieve historical context for a given IP address from ChromaDB.

        Args:
            ip (str): The IP address to look up history for.

        Returns:
            Dict: Dictionary containing:
            {
                "ip": str,
                "threat_count": int,
                "threats": List[Dict],  # Recent threats
                "classification_counts": Dict[str, int],  # Count by classification
                "recurring_false_positive": bool,
                "most_common_classification": str,
                "has_history": bool,
                "novel_ip": bool
            }
        """
        try:
            chroma_host = os.getenv("CHROMA_HOST", "localhost")
            chroma_port = int(os.getenv("CHROMA_PORT", "8000"))
            client = chromadb.HttpClient(host=chroma_host, port=chroma_port)

            col = client.get_collection("all_threats")
            results = col.get(where={"ip": ip})

            # Parse results
            threat_count = len(results.get("ids", []))
            has_history = threat_count > 0
            novel_ip = not has_history

            # Build threats list from metadata
            threats = []
            if results.get("metadatas"):
                for metadata in results["metadatas"]:
                    threats.append(metadata)

            # Count classifications
            classification_counts = {}
            for threat in threats:
                classification = threat.get("classification", "unknown")
                classification_counts[classification] = classification_counts.get(classification, 0) + 1

            # Determine most common classification
            most_common_classification = None
            if classification_counts:
                most_common_classification = max(classification_counts, key=classification_counts.get)

            # Check for recurring false positives
            # Consider it recurring if more than 50% are false positives
            fp_count = classification_counts.get("false_positive", 0)
            recurring_false_positive = (fp_count / threat_count) > 0.5 if threat_count > 0 else False

            return {
                "ip": ip,
                "threat_count": threat_count,
                "threats": threats,
                "classification_counts": classification_counts,
                "recurring_false_positive": recurring_false_positive,
                "most_common_classification": most_common_classification,
                "has_history": has_history,
                "novel_ip": novel_ip
            }

        except Exception as e:
            logging.error(f"Error gathering IP history for {ip}: {str(e)}")
            # Return empty history on error
            return {
                "ip": ip,
                "threat_count": 0,
                "threats": [],
                "classification_counts": {},
                "recurring_false_positive": False,
                "most_common_classification": None,
                "has_history": False,
                "novel_ip": True
            }

    def _analyze_ip_reputation(self, ip: str, history: Dict) -> Dict:
        """
        Analyze IP reputation based on historical behavior.

        Synthesizes raw IP history into actionable reputation signals:
        - Identifies IPs with consistent false positive patterns
        - Detects escalation patterns (severity increasing over time)
        - Provides confidence scoring based on historical behavior
        - Flags novel IPs (no history = higher suspicion)

        Args:
            ip (str): The IP address to analyze.
            history (Dict): Result from _gather_ip_history().

        Returns:
            Dict: Dictionary containing:
            {
                "ip": str,
                "reputation_score": float,  # 0.0 (very bad) to 1.0 (very good)
                "reputation_category": str,  # "malicious", "suspicious", "neutral", "trusted"
                "confidence": float,  # 0.0 to 1.0 based on data quality
                "is_novel_ip": bool,
                "has_fp_pattern": bool,  # True if 3+ false positives
                "fp_rate": float,  # Percentage of threats that are FPs
                "escalation_detected": bool,  # True if severity increasing
                "risk_factors": List[str],  # Human-readable risk indicators
                "trust_factors": List[str],  # Human-readable trust indicators
                "recommendation": str,  # "filter", "review", "escalate"
            }
        """
        try:
            threat_count = history.get("threat_count", 0)
            classification_counts = history.get("classification_counts", {})
            threats = history.get("threats", [])
            is_novel = history.get("novel_ip", True)

            # Initialize analysis results
            risk_factors = []
            trust_factors = []
            reputation_score = 0.5  # Start neutral

            # --- Novel IP Analysis ---
            if is_novel:
                risk_factors.append("Novel IP (no historical data)")
                reputation_score -= 0.15  # Slightly suspicious
                confidence = 0.3  # Low confidence due to lack of data

                return {
                    "ip": ip,
                    "reputation_score": max(0.0, reputation_score),
                    "reputation_category": "neutral",
                    "confidence": confidence,
                    "is_novel_ip": True,
                    "has_fp_pattern": False,
                    "fp_rate": 0.0,
                    "escalation_detected": False,
                    "risk_factors": risk_factors,
                    "trust_factors": [],
                    "recommendation": "review"
                }

            # --- False Positive Pattern Analysis ---
            fp_count = classification_counts.get("false_positive", 0)
            fp_rate = (fp_count / threat_count) if threat_count > 0 else 0.0
            has_fp_pattern = fp_count >= 3  # Threshold: 3+ false positives

            if has_fp_pattern:
                trust_factors.append(f"Recurring false positive pattern ({fp_count} FPs)")
                reputation_score += 0.3

                if fp_rate > 0.7:  # >70% false positives
                    trust_factors.append(f"High FP rate ({fp_rate:.0%})")
                    reputation_score += 0.2

            # --- Real Threat Pattern Analysis ---
            real_threat_count = classification_counts.get("REAL_THREAT", 0)
            real_threat_rate = (real_threat_count / threat_count) if threat_count > 0 else 0.0

            if real_threat_count >= 3:
                risk_factors.append(f"Multiple real threats ({real_threat_count})")
                reputation_score -= 0.25

                if real_threat_rate > 0.6:  # >60% real threats
                    risk_factors.append(f"High threat rate ({real_threat_rate:.0%})")
                    reputation_score -= 0.15

            # --- Escalation Detection ---
            escalation_detected = False
            if len(threats) >= 3:
                # Check if severity is increasing (requires timestamp sorting)
                severities = []
                for threat in threats:
                    severity = threat.get("severity", "low")
                    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                    severities.append(severity_map.get(severity, 1))

                # Simple escalation check: last 3 threats have increasing severity
                if len(severities) >= 3:
                    recent_severities = severities[-3:]
                    if recent_severities == sorted(recent_severities) and len(set(recent_severities)) > 1:
                        escalation_detected = True
                        risk_factors.append("Severity escalation pattern detected")
                        reputation_score -= 0.20

            # --- Activity Volume Analysis ---
            if threat_count > 10:
                risk_factors.append(f"High activity volume ({threat_count} threats)")
                reputation_score -= 0.10
            elif threat_count >= 5:
                risk_factors.append(f"Moderate activity volume ({threat_count} threats)")
                reputation_score -= 0.05

            # --- Classification Consistency ---
            if len(classification_counts) == 1:  # Only one type of classification
                most_common = history.get("most_common_classification")
                if most_common == "false_positive":
                    trust_factors.append("Consistent false positive pattern")
                    reputation_score += 0.15
                elif most_common == "REAL_THREAT":
                    risk_factors.append("Consistent real threat pattern")
                    reputation_score -= 0.20

            # --- Confidence Calculation ---
            # Confidence increases with data quantity
            if threat_count >= 10:
                confidence = 0.9
            elif threat_count >= 5:
                confidence = 0.75
            elif threat_count >= 3:
                confidence = 0.6
            else:
                confidence = 0.4

            # --- Final Score Normalization ---
            reputation_score = max(0.0, min(1.0, reputation_score))

            # --- Reputation Category ---
            if reputation_score >= 0.7:
                reputation_category = "trusted"
            elif reputation_score >= 0.5:
                reputation_category = "neutral"
            elif reputation_score >= 0.3:
                reputation_category = "suspicious"
            else:
                reputation_category = "malicious"

            # --- Recommendation ---
            if has_fp_pattern and fp_rate > 0.6:
                recommendation = "filter"  # High confidence false positive
            elif reputation_category == "malicious" or escalation_detected:
                recommendation = "escalate"  # High risk, needs immediate attention
            else:
                recommendation = "review"  # Requires manual analysis

            return {
                "ip": ip,
                "reputation_score": round(reputation_score, 3),
                "reputation_category": reputation_category,
                "confidence": round(confidence, 2),
                "is_novel_ip": False,
                "has_fp_pattern": has_fp_pattern,
                "fp_rate": round(fp_rate, 3),
                "escalation_detected": escalation_detected,
                "risk_factors": risk_factors,
                "trust_factors": trust_factors,
                "recommendation": recommendation
            }

        except Exception as e:
            logging.error(f"Error analyzing IP reputation for {ip}: {str(e)}")
            # Return neutral reputation on error
            return {
                "ip": ip,
                "reputation_score": 0.5,
                "reputation_category": "neutral",
                "confidence": 0.0,
                "is_novel_ip": True,
                "has_fp_pattern": False,
                "fp_rate": 0.0,
                "escalation_detected": False,
                "risk_factors": ["Error during reputation analysis"],
                "trust_factors": [],
                "recommendation": "review"
            }

    def _query_similar_threats(
        self,
        threat_data: Dict,
        top_k: int = 5,
        filter_classification: Optional[str] = None
    ) -> Dict:
        """
        Use ChromaDB semantic search to find similar threats globally.

        Searches across all IPs to find threats with similar characteristics.
        This provides pattern discovery beyond single-IP analysis.

        Args:
            threat_data (Dict): Current threat data containing:
                - ip: Source IP address
                - attack_type: Type of attack detected
                - severity: Threat severity level
                - description: Threat description (used for semantic search)
            top_k (int): Number of similar threats to return (default: 5)
            filter_classification (Optional[str]): Filter results by classification
                (e.g., "false_positive", "REAL_THREAT")

        Returns:
            Dict: Dictionary containing:
            {
                "similar_threats": List[Dict],  # Most similar threats
                "similarity_scores": List[float],  # Similarity scores (0.0-1.0)
                "has_similar_fps": bool,  # True if similar false positives found
                "has_similar_threats": bool,  # True if similar real threats found
                "pattern_summary": str,  # Human-readable pattern description
                "confidence": float,  # Confidence in similarity results (0.0-1.0)
            }
        """
        try:
            chroma_host = os.getenv("CHROMA_HOST", "localhost")
            chroma_port = int(os.getenv("CHROMA_PORT", "8000"))
            client = chromadb.HttpClient(host=chroma_host, port=chroma_port)

            col = client.get_collection("all_threats")

            # Build query text for semantic search
            # Combine key threat characteristics for better matching
            query_parts = []

            if threat_data.get("attack_type"):
                query_parts.append(f"Attack type: {threat_data['attack_type']}")

            if threat_data.get("description"):
                query_parts.append(threat_data["description"])

            if threat_data.get("severity"):
                query_parts.append(f"Severity: {threat_data['severity']}")

            # Fallback query if no description provided
            if not query_parts:
                query_parts.append(f"IP: {threat_data.get('ip', 'unknown')}")

            query_text = " ".join(query_parts)

            # Build filter for ChromaDB query
            where_filter = None
            if filter_classification:
                where_filter = {"classification": filter_classification}

            # Perform semantic search
            results = col.query(
                query_texts=[query_text],
                n_results=top_k,
                where=where_filter
            )

            # Parse results
            similar_threats = []
            similarity_scores = []

            if results.get("metadatas") and len(results["metadatas"]) > 0:
                metadatas = results["metadatas"][0]  # First query result
                distances = results.get("distances", [[]])[0]  # Distance scores

                for i, metadata in enumerate(metadatas):
                    # Convert distance to similarity (0.0 = identical, higher = more different)
                    # ChromaDB uses L2 distance, convert to similarity score
                    distance = distances[i] if i < len(distances) else 1.0
                    similarity = max(0.0, 1.0 - (distance / 2.0))  # Normalize to 0-1

                    similar_threats.append(metadata)
                    similarity_scores.append(round(similarity, 3))

            # Analyze patterns in similar threats
            has_similar_fps = False
            has_similar_threats = False
            fp_count = 0
            threat_count = 0

            for threat in similar_threats:
                classification = threat.get("classification", "unknown")
                if classification == "false_positive":
                    fp_count += 1
                elif classification == "REAL_THREAT":
                    threat_count += 1

            has_similar_fps = fp_count >= 2  # At least 2 similar FPs
            has_similar_threats = threat_count >= 2  # At least 2 similar real threats

            # Build pattern summary
            pattern_summary = self._build_pattern_summary(
                similar_threats,
                fp_count,
                threat_count
            )

            # Calculate confidence based on result quality
            confidence = self._calculate_similarity_confidence(
                similar_threats,
                similarity_scores,
                top_k
            )

            return {
                "similar_threats": similar_threats,
                "similarity_scores": similarity_scores,
                "has_similar_fps": has_similar_fps,
                "has_similar_threats": has_similar_threats,
                "pattern_summary": pattern_summary,
                "confidence": round(confidence, 2)
            }

        except Exception as e:
            logging.error(f"Error querying similar threats: {str(e)}")
            # Return empty results on error
            return {
                "similar_threats": [],
                "similarity_scores": [],
                "has_similar_fps": False,
                "has_similar_threats": False,
                "pattern_summary": "No similar threats found (error during search)",
                "confidence": 0.0
            }

    def _build_pattern_summary(
        self,
        similar_threats: list,
        fp_count: int,
        threat_count: int
    ) -> str:
        """
        Build human-readable summary of pattern detected in similar threats.

        Args:
            similar_threats: List of similar threat metadata
            fp_count: Number of false positives in results
            threat_count: Number of real threats in results

        Returns:
            str: Human-readable pattern summary
        """
        if not similar_threats:
            return "No similar threats found in historical data"

        total = len(similar_threats)

        # Classification distribution
        if fp_count > threat_count:
            primary_pattern = f"{fp_count}/{total} similar threats were false positives"
        elif threat_count > fp_count:
            primary_pattern = f"{threat_count}/{total} similar threats were real attacks"
        else:
            primary_pattern = f"Mixed pattern: {fp_count} FPs, {threat_count} real threats"

        # Attack type patterns
        attack_types = {}
        for threat in similar_threats:
            attack_type = threat.get("attack_type", "unknown")
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        if attack_types:
            most_common_attack = max(attack_types, key=attack_types.get)
            if most_common_attack != "unknown":
                primary_pattern += f", mostly {most_common_attack}"

        return primary_pattern

    def _calculate_similarity_confidence(
        self,
        similar_threats: list,
        similarity_scores: list,
        requested_k: int
    ) -> float:
        """
        Calculate confidence in similarity search results.

        Confidence is based on:
        - Number of results found (more results = higher confidence)
        - Average similarity score (higher similarity = higher confidence)
        - Result quality (how many results we got vs requested)

        Args:
            similar_threats: List of similar threats found
            similarity_scores: List of similarity scores
            requested_k: Number of results requested

        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        if not similar_threats or not similarity_scores:
            return 0.0

        # Factor 1: Result completeness (did we get enough results?)
        result_completeness = len(similar_threats) / requested_k

        # Factor 2: Average similarity score
        avg_similarity = sum(similarity_scores) / len(similarity_scores)

        # Factor 3: Minimum similarity threshold (at least one good match?)
        has_good_match = any(score > 0.7 for score in similarity_scores)
        good_match_bonus = 0.2 if has_good_match else 0.0

        # Weighted combination
        confidence = (
            result_completeness * 0.4 +  # 40% weight on getting enough results
            avg_similarity * 0.4 +        # 40% weight on similarity quality
            good_match_bonus              # 20% bonus for at least one good match
        )

        return min(1.0, confidence)

    def _build_context_prompt(
        self,
        threat_data: Dict,
        context_summary: Dict
    ) -> str:
        """
        Build structured prompt for LLM analysis using context data.

        Formats all gathered context (IP history, reputation, similar threats)
        into a comprehensive prompt for the LLM to make classification decisions.

        Args:
            threat_data (Dict): Current threat data containing:
                - ip: Source IP address
                - attack_type: Type of attack detected
                - severity: Threat severity level
                - description: Threat description
                - timestamp: When threat occurred
            context_summary (Dict): Aggregated context from analyze_context():
                - ip_history: Result from _gather_ip_history()
                - ip_reputation: Result from _analyze_ip_reputation()
                - similar_threats: Result from _query_similar_threats()

        Returns:
            str: Formatted prompt ready for LLM input
        """
        try:
            # Load prompt template
            template_path = os.path.join(
                os.path.dirname(__file__),
                "prompts",
                "context_analysis_prompt.md"
            )

            with open(template_path, "r") as f:
                prompt_template = f.read()

            # Extract context data
            ip_history = context_summary.get("ip_history", {})
            ip_reputation = context_summary.get("ip_reputation", {})
            similar_threats = context_summary.get("similar_threats", {})

            # Format IP reputation summary
            ip_reputation_summary = self._format_ip_reputation_summary(ip_reputation)

            # Format risk factors
            risk_factors = ip_reputation.get("risk_factors", [])
            risk_factors_text = "\n".join([f"- {factor}" for factor in risk_factors]) if risk_factors else "- None identified"

            # Format trust factors
            trust_factors = ip_reputation.get("trust_factors", [])
            trust_factors_text = "\n".join([f"- {factor}" for factor in trust_factors]) if trust_factors else "- None identified"

            # Format similarity analysis
            similarity_analysis_summary = self._format_similarity_summary(similar_threats)
            similar_threats_details = self._format_similar_threats_details(similar_threats)

            # Fill in template variables
            prompt = prompt_template.format(
                # Current threat details
                ip=threat_data.get("ip", "unknown"),
                attack_type=threat_data.get("attack_type", "unknown"),
                severity=threat_data.get("severity", "unknown"),
                description=threat_data.get("description", "No description provided"),
                timestamp=threat_data.get("timestamp", "unknown"),

                # IP reputation
                ip_reputation_summary=ip_reputation_summary,
                reputation_score=ip_reputation.get("reputation_score", 0.5),
                reputation_category=ip_reputation.get("reputation_category", "neutral"),
                ip_recommendation=ip_reputation.get("recommendation", "review"),
                risk_factors=risk_factors_text,
                trust_factors=trust_factors_text,

                # Similar threats
                similarity_analysis_summary=similarity_analysis_summary,
                pattern_summary=similar_threats.get("pattern_summary", "No pattern identified"),
                similarity_confidence=similar_threats.get("confidence", 0.0),
                similar_threats_details=similar_threats_details,

                # IP history
                threat_count=ip_history.get("threat_count", 0),
                is_novel_ip="Yes" if ip_history.get("novel_ip", True) else "No",
                fp_rate=f"{ip_reputation.get('fp_rate', 0.0):.0%}",
                has_fp_pattern="Yes" if ip_reputation.get("has_fp_pattern", False) else "No",
                escalation_detected="Yes" if ip_reputation.get("escalation_detected", False) else "No"
            )

            return prompt

        except Exception as e:
            logging.error(f"Error building context prompt: {str(e)}")
            # Return minimal prompt on error
            return self._build_fallback_prompt(threat_data)

    def _format_ip_reputation_summary(self, ip_reputation: Dict) -> str:
        """Format IP reputation data into readable summary."""
        if not ip_reputation:
            return "No IP reputation data available."

        is_novel = ip_reputation.get("is_novel_ip", True)
        if is_novel:
            return "This is a novel IP with no historical data in our system."

        score = ip_reputation.get("reputation_score", 0.5)
        category = ip_reputation.get("reputation_category", "neutral")
        confidence = ip_reputation.get("confidence", 0.0)

        return f"IP has a reputation score of {score:.2f} (category: {category}) with {confidence:.0%} confidence based on historical data."

    def _format_similarity_summary(self, similar_threats: Dict) -> str:
        """Format similar threats analysis into readable summary."""
        if not similar_threats or not similar_threats.get("similar_threats"):
            return "No similar threats found in historical data."

        threat_count = len(similar_threats.get("similar_threats", []))
        confidence = similar_threats.get("confidence", 0.0)
        has_similar_fps = similar_threats.get("has_similar_fps", False)
        has_similar_threats = similar_threats.get("has_similar_threats", False)

        summary = f"Found {threat_count} similar threats with {confidence:.0%} confidence. "

        if has_similar_fps and has_similar_threats:
            summary += "Mixed pattern: both false positives and real threats detected."
        elif has_similar_fps:
            summary += "Pattern suggests false positive (multiple similar FPs found)."
        elif has_similar_threats:
            summary += "Pattern suggests real threat (multiple similar real threats found)."
        else:
            summary += "Insufficient pattern to determine classification."

        return summary

    def _format_similar_threats_details(self, similar_threats: Dict) -> str:
        """Format detailed list of similar threats."""
        if not similar_threats or not similar_threats.get("similar_threats"):
            return "No similar threats to display."

        threats_list = similar_threats.get("similar_threats", [])
        scores = similar_threats.get("similarity_scores", [])

        details = "**Top Similar Threats:**\n\n"
        for i, (threat, score) in enumerate(zip(threats_list[:5], scores[:5]), 1):
            ip = threat.get("ip", "unknown")
            attack_type = threat.get("attack_type", "unknown")
            classification = threat.get("classification", "unknown")
            severity = threat.get("severity", "unknown")

            details += f"{i}. IP: {ip} | Attack: {attack_type} | Classification: {classification} | "
            details += f"Severity: {severity} | Similarity: {score:.0%}\n"

        return details

    def _build_fallback_prompt(self, threat_data: Dict) -> str:
        """Build minimal prompt when template loading fails."""
        return f"""Analyze this security threat:

IP: {threat_data.get('ip', 'unknown')}
Attack Type: {threat_data.get('attack_type', 'unknown')}
Severity: {threat_data.get('severity', 'unknown')}
Description: {threat_data.get('description', 'No description')}

Classify as: REAL_THREAT, SUSPICIOUS, FALSE_POSITIVE, or BENIGN_ANOMALY

Provide response in JSON format with classification, confidence, and reasoning.
"""

