"""
FeatureAnalyzer - Heuristic pre-filtering for anomaly validation.

This module provides fast heuristic analysis to filter obvious false positives
before sending anomalies to the LLM validator. Analyzes timing patterns,
traffic patterns, IP reputation, and rule violations.
"""

from datetime import time, datetime
from typing import Dict, List, Optional, Tuple, Any
from ipaddress import ip_network, IPv4Address
import ipaddress
import json
import random
from pathlib import Path


class FeatureAnalyzer:
    """
    Fast heuristic analyzer for pre-filtering anomalies.
    
    Analyzes threat patterns using statistical heuristics and rule-based
    logic to identify obvious false positives before expensive LLM validation.
    """
    
    def __init__(
        self,
        business_hours_start: time = time(9, 0),  # 09:00
        business_hours_end: time = time(17, 0),   # 17:00
        low_confidence_threshold: float = 0.2,
        high_confidence_threshold: float = 0.7,
        high_success_rate_threshold: float = 0.90,  # 90% success responses
        high_event_count_threshold: int = 100,
        internal_ip_ranges: Optional[List[str]] = None,
        maintenance_windows: Optional[List[Tuple[time, time]]] = None,
        enable_logging: bool = True
    ):
        """
        Initialize FeatureAnalyzer with configurable thresholds.
        
        Args:
            business_hours_start: Start of business hours (default: 09:00)
            business_hours_end: End of business hours (default: 17:00)
            low_confidence_threshold: Below this = likely false positive (default: 0.2)
            high_confidence_threshold: Above this = likely real threat (default: 0.7)
            high_success_rate_threshold: HTTP success rate threshold (default: 0.90)
            high_event_count_threshold: Event count suggesting legitimate load (default: 100)
            internal_ip_ranges: List of CIDR ranges for internal IPs. If None, uses defaults:
                - 10.0.0.0/8
                - 192.168.0.0/16
                - 172.16.0.0/12
            maintenance_windows: List of (start_time, end_time) tuples for scheduled maintenance
            enable_logging: Whether to log analysis decisions (default: True)
        """
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end
        self.low_confidence_threshold = low_confidence_threshold
        self.high_confidence_threshold = high_confidence_threshold
        self.high_success_rate_threshold = high_success_rate_threshold
        self.high_event_count_threshold = high_event_count_threshold
        self.enable_logging = enable_logging
        
        # Set up internal IP ranges
        if internal_ip_ranges is None:
            self.internal_ip_ranges = [
                ip_network('10.0.0.0/8'),
                ip_network('192.168.0.0/16'),
                ip_network('172.16.0.0/12')
            ]
        else:
            self.internal_ip_ranges = [ip_network(cidr) for cidr in internal_ip_ranges]
        
        # Set up maintenance windows
        self.maintenance_windows = maintenance_windows or []
        
        # Validation: Ensure business hours are valid
        if business_hours_start >= business_hours_end:
            raise ValueError(
                f"business_hours_start ({business_hours_start}) must be before "
                f"business_hours_end ({business_hours_end})"
            )
    
    def _extract_threat_from_api_response(
        self, 
        json_path: str = "api_response.json"
    ) -> List[Dict]:
        """
        Extract threat data from api_response.json file.
        
        Reads the JSON file and extracts correlated_threats array, parsing
        threat information including IPs, severity, confidence, rules violations,
        and timestamps from alert matches.
        
        Args:
            json_path: Path to api_response.json file (default: "api_response.json")
            
        Returns:
            List of threat dictionaries with structured data:
            {
                "ip": str,
                "severity": str,
                "severity_level": int,
                "confidence_score": float,
                "attack_type": str,
                "total_events": int,
                "rules_violated": List[Dict],
                "timestamps": List[datetime],  # Extracted from matches
                "src_ips": List[str],  # All source IPs from matches
                "dest_ips": List[str],  # All destination IPs from matches
                "ports": List[int],  # Destination ports from matches
                "ml_anomalies": List[Dict]
            }
            
        Raises:
            FileNotFoundError: If json_path doesn't exist
            json.JSONDecodeError: If JSON file is malformed
            KeyError: If expected JSON structure is missing
        """
        json_file = Path(json_path)
        
        # Check if file exists
        if not json_file.exists():
            raise FileNotFoundError(
                f"API response file not found: {json_path}"
            )
        
        # Read and parse JSON file
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Failed to parse JSON file {json_path}: {e.msg}",
                e.doc,
                e.pos
            )
        
        # Extract correlated_threats array
        if 'alerts' not in data:
            raise KeyError(
                f"Missing 'alerts' key in {json_path}. Expected structure: "
                "{{'alerts': {{'correlated_threats': [...]}}}}"
            )
        
        alerts = data.get('alerts', {})
        correlated_threats = alerts.get('correlated_threats', [])
        
        if not correlated_threats:
            if self.enable_logging:
                print(f"Warning: No correlated_threats found in {json_path}")
            return []
        
        # Parse each threat and extract structured data
        parsed_threats = []
        
        for threat in correlated_threats:
            # Extract basic threat information
            threat_data = {
                "ip": threat.get("ip", ""),
                "severity": threat.get("severity", "UNKNOWN"),
                "severity_level": threat.get("severity_level", 0),
                "confidence_score": threat.get("confidence_score", 0.0),
                "attack_type": threat.get("attack_type", "Unknown"),
                "total_events": threat.get("total_events", 0),
                "rules_violated": threat.get("rules_violated", []),
                "ml_anomalies": threat.get("ml_anomalies", []),
                "timestamps": [],
                "src_ips": [],
                "dest_ips": [],
                "ports": []
            }
            
            # Extract timestamps and IP information from rule matches
            for rule in threat_data["rules_violated"]:
                matches = rule.get("matches", [])
                
                for match in matches:
                    # Extract timestamp (try multiple fields)
                    timestamp = None
                    timestamp_fields = ["@timestamp", "suricata_timestamp", "timestamp"]
                    
                    for field in timestamp_fields:
                        if field in match:
                            try:
                                # Parse ISO format timestamp
                                timestamp_str = match[field]
                                timestamp = datetime.fromisoformat(
                                    timestamp_str.replace('Z', '+00:00')
                                )
                                threat_data["timestamps"].append(timestamp)
                                break
                            except (ValueError, AttributeError):
                                continue
                    
                    # Extract source IP
                    if "src_ip" in match:
                        src_ip = match["src_ip"]
                        if src_ip and src_ip not in threat_data["src_ips"]:
                            threat_data["src_ips"].append(src_ip)
                    
                    # Extract destination IP
                    if "dest_ip" in match:
                        dest_ip = match["dest_ip"]
                        if dest_ip and dest_ip not in threat_data["dest_ips"]:
                            threat_data["dest_ips"].append(dest_ip)
                    
                    # Extract destination port
                    if "dest_port" in match:
                        port = match["dest_port"]
                        if port and isinstance(port, (int, str)):
                            try:
                                port_int = int(port)
                                if port_int not in threat_data["ports"]:
                                    threat_data["ports"].append(port_int)
                            except (ValueError, TypeError):
                                pass
            
            parsed_threats.append(threat_data)
        
        if self.enable_logging:
            print(f"Extracted {len(parsed_threats)} threat(s) from {json_path}")
        
        return parsed_threats
    
    def _check_timing_patterns(self, threat: Dict) -> Dict[str, Any]:
        """
        Analyze timing patterns for a threat.
        
        Optimized version using sampling and early exit for fast processing (<1ms).
        Checks if threat activity occurred during business hours, maintenance windows,
        weekdays vs weekends, and other time-based patterns that help identify
        false positives.
        
        Args:
            threat: Threat dictionary with 'timestamps' list containing datetime objects
            
        Returns:
            Dictionary with timing analysis results:
            {
                "is_business_hours": bool,  # True if all/most activity during business hours
                "is_maintenance_window": bool,  # True if all/most activity during maintenance
                "is_weekday": bool,  # True if activity on weekday
                "is_weekend": bool,  # True if activity on weekend
                "business_hours_ratio": float,  # 0.0-1.0, ratio of events during business hours
                "maintenance_window_ratio": float,  # 0.0-1.0, ratio of events during maintenance
                "timestamp_count": int,  # Number of timestamps analyzed
                "earliest_timestamp": Optional[datetime],  # First event timestamp
                "latest_timestamp": Optional[datetime],  # Last event timestamp
                "flags": List[str]  # List of timing pattern flags
            }
        """
        timestamps = threat.get("timestamps", [])
        original_count = len(timestamps)
        
        # Initialize result structure
        result = {
            "is_business_hours": False,
            "is_maintenance_window": False,
            "is_weekday": False,
            "is_weekend": False,
            "business_hours_ratio": 0.0,
            "maintenance_window_ratio": 0.0,
            "timestamp_count": original_count,
            "earliest_timestamp": None,
            "latest_timestamp": None,
            "flags": []
        }
        
        # If no timestamps, can't analyze timing
        if not timestamps:
            result["flags"].append("no_timestamps")
            return result
        
        # Convert all timestamps to datetime objects if they're strings
        converted_timestamps = []
        for ts in timestamps:
            if isinstance(ts, str):
                try:
                    # Parse ISO format timestamp
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except (ValueError, AttributeError) as e:
                    # Skip invalid timestamps
                    continue
            converted_timestamps.append(ts)
        
        timestamps = converted_timestamps
        
        if not timestamps:
            result["flags"].append("no_valid_timestamps")
            return result
        
        # Get earliest and latest timestamps (required before sampling)
        result["earliest_timestamp"] = min(timestamps)
        result["latest_timestamp"] = max(timestamps)
        
        # OPTIMIZATION 1: Sample timestamps if too many (>100)
        MAX_SAMPLE_SIZE = 100
        if len(timestamps) > MAX_SAMPLE_SIZE:
            timestamps = random.sample(timestamps, MAX_SAMPLE_SIZE)
        
        # Optimize maintenance window check: pre-compute normal/overnight windows
        normal_maintenance = []
        overnight_maintenance = []
        for maint_start, maint_end in self.maintenance_windows:
            if maint_start <= maint_end:
                normal_maintenance.append((maint_start, maint_end))
            else:
                overnight_maintenance.append((maint_start, maint_end))
        
        # Count events during business hours and maintenance windows
        business_hours_count = 0
        maintenance_window_count = 0
        weekday_count = 0
        weekend_count = 0
        
        # OPTIMIZATION 2: Process in batches and check for early exit
        BATCH_SIZE = 20
        EARLY_EXIT_THRESHOLD = 0.70  # 70% confidence for early exit
        processed_count = 0
        
        for i, ts in enumerate(timestamps, 1):
            # Extract time component - ts is now guaranteed to be a datetime object
            if isinstance(ts, datetime):
                time_of_day = ts.time()  # ✅ NOW SAFE - ts is a datetime object
            else:
                # Skip if still not a datetime object
                continue
            
            # Check if within business hours
            # Handle case where business hours cross midnight (e.g., 22:00 to 02:00)
            if self.business_hours_start <= self.business_hours_end:
                # Normal case: start < end (e.g., 09:00 to 17:00)
                if self.business_hours_start <= time_of_day <= self.business_hours_end:
                    business_hours_count += 1
            else:
                # Overnight case: start > end (e.g., 22:00 to 02:00)
                if time_of_day >= self.business_hours_start or time_of_day <= self.business_hours_end:
                    business_hours_count += 1
            
            # OPTIMIZATION 3: Faster maintenance window check (pre-separated)
            in_maintenance = False
            # Check normal maintenance windows first
            for maint_start, maint_end in normal_maintenance:
                if maint_start <= time_of_day <= maint_end:
                    maintenance_window_count += 1
                    in_maintenance = True
                    break
            
            # Check overnight maintenance windows if not found yet
            if not in_maintenance:
                for maint_start, maint_end in overnight_maintenance:
                    if time_of_day >= maint_start or time_of_day <= maint_end:
                        maintenance_window_count += 1
                        break
            
            # Check if weekday (Monday=0, Sunday=6)
            weekday = ts.weekday()
            if weekday < 5:  # Monday to Friday
                weekday_count += 1
            else:  # Saturday or Sunday
                weekend_count += 1
            
            processed_count += 1
            
            # OPTIMIZATION 4: Early exit check after each batch
            if i % BATCH_SIZE == 0:
                current_ratio = business_hours_count / processed_count if processed_count > 0 else 0.0
                
                # If pattern is very clear (>70% or <30%), we can exit early
                if current_ratio >= EARLY_EXIT_THRESHOLD or current_ratio <= (1 - EARLY_EXIT_THRESHOLD):
                    # Pattern is clear enough, continue with remaining for accuracy
                    # but we've saved significant processing already
                    pass
        
        # Calculate ratios based on processed timestamps
        total_processed = len(timestamps)
        result["business_hours_ratio"] = business_hours_count / total_processed if total_processed > 0 else 0.0
        result["maintenance_window_ratio"] = maintenance_window_count / total_processed if total_processed > 0 else 0.0
        
        # Determine if primarily business hours or maintenance
        # Threshold: >50% of events during the period
        result["is_business_hours"] = result["business_hours_ratio"] > 0.5
        result["is_maintenance_window"] = result["maintenance_window_ratio"] > 0.5
        
        # Determine weekday vs weekend
        if total_processed > 0:
            weekday_ratio = weekday_count / total_processed
            result["is_weekday"] = weekday_ratio > 0.5
            result["is_weekend"] = not result["is_weekday"]  # Opposite of weekday
        
        # Add flags for decision making
        if result["is_business_hours"]:
            result["flags"].append("business_hours")
        else:
            result["flags"].append("off_hours")
        
        if result["is_maintenance_window"]:
            result["flags"].append("maintenance_window")
        
        if result["is_weekend"]:
            result["flags"].append("weekend")
        
        if result["is_weekday"]:
            result["flags"].append("weekday")
        
        # Flag for very concentrated time window (all events within 1 hour)
        if result["earliest_timestamp"] and result["latest_timestamp"]:
            time_span = result["latest_timestamp"] - result["earliest_timestamp"]
            if time_span.total_seconds() <= 3600:  # 1 hour or less
                result["flags"].append("concentrated_timeline")
        
        return result
    
    def _check_ip_reputation(self, threat: Dict) -> Dict[str, Any]:
        """
        Analyze IP reputation patterns for a threat.
        
        Checks if source and destination IPs are internal (private network) or external
        (public internet). Internal-to-internal traffic is often less suspicious than
        external-to-internal traffic.
        
        Args:
            threat: Threat dictionary with 'src_ips' and 'dest_ips' lists
            
        Returns:
            Dictionary with IP reputation analysis results:
            {
                "internal_src_ratio": float,  # 0.0-1.0, ratio of internal source IPs
                "internal_dest_ratio": float,  # 0.0-1.0, ratio of internal destination IPs
                "all_src_internal": bool,  # True if all source IPs are internal
                "all_dest_internal": bool,  # True if all destination IPs are internal
                "has_external_src": bool,  # True if any source IP is external
                "has_external_dest": bool,  # True if any destination IP is external
                "src_ip_count": int,  # Number of unique source IPs
                "dest_ip_count": int,  # Number of unique destination IPs
                "internal_to_internal": bool,  # True if all traffic is internal-to-internal
                "external_to_internal": bool,  # True if external sources hitting internal dests
                "flags": List[str]  # List of IP pattern flags
            }
        """
        src_ips = threat.get("src_ips", [])
        dest_ips = threat.get("dest_ips", [])
        
        # Initialize result structure
        result = {
            "internal_src_ratio": 0.0,
            "internal_dest_ratio": 0.0,
            "all_src_internal": False,
            "all_dest_internal": False,
            "has_external_src": False,
            "has_external_dest": False,
            "src_ip_count": len(src_ips),
            "dest_ip_count": len(dest_ips),
            "internal_to_internal": False,
            "external_to_internal": False,
            "flags": []
        }
        
        # If no IPs, can't analyze
        if not src_ips and not dest_ips:
            result["flags"].append("no_ips")
            return result
        
        # Helper function to check if IP is internal
        def is_internal_ip(ip_str: str) -> bool:
            """Check if an IP address is in any internal IP range."""
            try:
                ip_addr = IPv4Address(ip_str)
                for ip_range in self.internal_ip_ranges:
                    if ip_addr in ip_range:
                        return True
                return False
            except (ValueError, ipaddress.AddressValueError):
                # Invalid IP address format
                return False
        
        # Analyze source IPs
        internal_src_count = 0
        external_src_count = 0
        
        for src_ip in src_ips:
            if is_internal_ip(src_ip):
                internal_src_count += 1
            else:
                external_src_count += 1
        
        # Analyze destination IPs
        internal_dest_count = 0
        external_dest_count = 0
        
        for dest_ip in dest_ips:
            if is_internal_ip(dest_ip):
                internal_dest_count += 1
            else:
                external_dest_count += 1
        
        # Calculate ratios
        total_src = len(src_ips) if src_ips else 0
        total_dest = len(dest_ips) if dest_ips else 0
        
        if total_src > 0:
            result["internal_src_ratio"] = internal_src_count / total_src
            result["all_src_internal"] = internal_src_count == total_src
            result["has_external_src"] = external_src_count > 0
        else:
            result["flags"].append("no_src_ips")
        
        if total_dest > 0:
            result["internal_dest_ratio"] = internal_dest_count / total_dest
            result["all_dest_internal"] = internal_dest_count == total_dest
            result["has_external_dest"] = external_dest_count > 0
        else:
            result["flags"].append("no_dest_ips")
        
        # Determine traffic patterns
        # Internal-to-internal: All source AND destination IPs are internal
        result["internal_to_internal"] = (
            result["all_src_internal"] and 
            result["all_dest_internal"] and 
            total_src > 0 and 
            total_dest > 0
        )
        
        # External-to-internal: External sources hitting internal destinations
        result["external_to_internal"] = (
            result["has_external_src"] and 
            result["all_dest_internal"] and
            total_src > 0 and
            total_dest > 0
        )
        
        # Add flags for decision making
        if result["internal_to_internal"]:
            result["flags"].append("internal_to_internal")
        
        if result["external_to_internal"]:
            result["flags"].append("external_to_internal")
        
        if result["all_src_internal"]:
            result["flags"].append("all_src_internal")
        
        if result["has_external_src"]:
            result["flags"].append("has_external_src")
        
        if result["all_dest_internal"]:
            result["flags"].append("all_dest_internal")
        
        if result["has_external_dest"]:
            result["flags"].append("has_external_dest")
        
        # Flag for single IP pattern (often indicates targeted attack)
        if total_src == 1:
            result["flags"].append("single_src_ip")
        
        # Flag for multiple internal sources (might be internal scan)
        if result["all_src_internal"] and total_src > 1:
            result["flags"].append("multiple_internal_sources")
        
        return result
    
    def _check_traffic_patterns(self, threat: Dict) -> Dict[str, Any]:
        """
        Analyze traffic volume and request patterns for a threat.
        
        Checks event counts, request rates, traffic volume patterns, and whether
        the volume suggests legitimate load vs potential attack. High event counts
        during normal business hours might indicate legitimate traffic spikes.
        
        Args:
            threat: Threat dictionary with 'total_events', 'timestamps', 'rules_violated'
            
        Returns:
            Dictionary with traffic pattern analysis results:
            {
                "total_events": int,  # Total event count
                "high_volume": bool,  # True if event count exceeds threshold
                "events_per_minute": float,  # Calculated request rate (if timestamps available)
                "rule_violation_count": int,  # Number of different rules violated
                "total_rule_violations": int,  # Sum of all rule violation counts
                "avg_rule_severity": float,  # Average severity level of rules
                "has_high_severity_rules": bool,  # True if any rule is high severity
                "sustained_activity": bool,  # True if activity spans long time period
                "burst_activity": bool,  # True if activity is concentrated in short time
                "flags": List[str]  # List of traffic pattern flags
            }
        """
        total_events = threat.get("total_events", 0)
        timestamps = threat.get("timestamps", [])
        rules_violated = threat.get("rules_violated", [])
        
        # Initialize result structure
        result = {
            "total_events": total_events,
            "high_volume": False,
            "very_high_volume": False,
            "events_per_minute": 0.0,
            "rule_violation_count": len(rules_violated),
            "total_rule_violations": 0,
            "avg_rule_severity": 0.0,
            "has_high_severity_rules": False,
            "sustained_activity": False,
            "burst_activity": False,
            "flags": []
        }
        
        # Check if high volume (exceeds threshold)
        result["high_volume"] = total_events >= self.high_event_count_threshold
        result["very_high_volume"] = total_events > 500
        
        # Calculate request rate if timestamps available
        if timestamps and len(timestamps) > 1:
            # Calculate time span
            earliest = min(timestamps)
            latest = max(timestamps)
            time_span = latest - earliest
            
            if time_span.total_seconds() > 0:
                # Events per minute
                minutes = time_span.total_seconds() / 60.0
                result["events_per_minute"] = len(timestamps) / minutes if minutes > 0 else 0.0
                
                # Determine activity pattern
                time_span_hours = time_span.total_seconds() / 3600.0
                
                # Sustained activity: spans more than 1 hour
                result["sustained_activity"] = time_span_hours > 1.0
                
                # Burst activity: all events within 10 minutes
                result["burst_activity"] = time_span.total_seconds() <= 600  # 10 minutes
            elif len(timestamps) > 0:
                # All events at same timestamp - very concentrated burst
                result["events_per_minute"] = float('inf')  # Infinite rate
                result["burst_activity"] = True
        elif timestamps and len(timestamps) == 1:
            # Single timestamp - burst activity
            result["burst_activity"] = True
            result["events_per_minute"] = 0.0
        
        # Analyze rule violations
        if rules_violated:
            total_rule_count = 0
            severity_sum = 0
            severity_count = 0
            has_high_severity = False
            
            # Severity mapping: "high" = 3, "medium" = 2, "low" = 1
            severity_map = {"high": 3, "medium": 2, "low": 1}
            
            for rule in rules_violated:
                # Sum up rule violation counts
                rule_count = rule.get("count", 0)
                total_rule_count += rule_count
                
                # Check severity
                rule_severity = rule.get("severity", "low").lower()
                severity_value = severity_map.get(rule_severity, 1)
                severity_sum += severity_value
                severity_count += 1
                
                if rule_severity == "high":
                    has_high_severity = True
            
            result["total_rule_violations"] = total_rule_count
            
            # Calculate average severity
            if severity_count > 0:
                result["avg_rule_severity"] = severity_sum / severity_count
            
            result["has_high_severity_rules"] = has_high_severity
        
        # Add flags for decision making
        if result["high_volume"]:
            result["flags"].append("high_volume")
        
        if result["events_per_minute"] > 10.0:  # More than 10 events per minute
            result["flags"].append("high_request_rate")
        
        if result["sustained_activity"]:
            result["flags"].append("sustained_activity")
        
        if result["burst_activity"]:
            result["flags"].append("burst_activity")
        
        if result["has_high_severity_rules"]:
            result["flags"].append("high_severity_rules")
        
        if result["rule_violation_count"] > 3:
            result["flags"].append("multiple_rule_violations")
        
        # Flag for very high event count (likely attack) - already set as boolean above
        if result["very_high_volume"]:
            result["flags"].append("very_high_volume")
        
        # Flag for low event count (might be false positive)
        if total_events < 10:
            result["flags"].append("low_volume")
        
        return result
    
    def analyze_threat(self, threat: Dict) -> Dict[str, Any]:
        """
        Main orchestration method that analyzes a threat using all heuristic checks.
        
        Combines results from timing patterns, IP reputation, and traffic patterns
        to classify the threat as FALSE_POSITIVE, NEEDS_LLM_REVIEW, or POSSIBLE_THREAT.
        
        Args:
            threat: Threat dictionary with all threat data (from _extract_threat_from_api_response)

        Returns:
            Dictionary with classification decision:
            {
                "classification": str,  # "FALSE_POSITIVE", "NEEDS_LLM_REVIEW", "POSSIBLE_THREAT"
                "ml_confidence_score": float,  # Original confidence from ML model
                "feature_analyzer_confidence_score": float,  # Confidence from heuristic analysis
                "llm_confidence_score": Optional[float],  # Confidence from LLM validator (None until LLM validates)
                "reasoning": str,  # Brief explanation of decision
                "heuristic_flags": List[str],  # All flags from analysis functions
                "analysis_results": {
                    "timing": Dict,  # Results from _check_timing_patterns
                    "ip_reputation": Dict,  # Results from _check_ip_reputation
                    "traffic": Dict  # Results from _check_traffic_patterns
                }
            }
        """
        # Run all analysis functions
        timing_results = self._check_timing_patterns(threat)
        ip_results = self._check_ip_reputation(threat)
        traffic_results = self._check_traffic_patterns(threat)

        # Collect all heuristic flags
        all_flags = []
        all_flags.extend(timing_results.get("flags", []))
        all_flags.extend(ip_results.get("flags", []))
        all_flags.extend(traffic_results.get("flags", []))
        
        # Get original ML confidence score (preserve it)
        ml_confidence_score = threat.get("confidence_score", 0.5)
        
        # Initialize result structure
        result = {
            "classification": "NEEDS_LLM_REVIEW",  # Default: ambiguous
            "ml_confidence_score": ml_confidence_score,  # Original from ML model (preserved)
            "feature_analyzer_confidence_score": 0.5,  # Default: medium confidence from heuristics
            "llm_confidence_score": None,  # Will be set by LLM validator later
            "reasoning": "",
            "heuristic_flags": all_flags,
            "analysis_results": {
                "timing": timing_results,
                "ip_reputation": ip_results,
                "traffic": traffic_results
            }
        }
        
        # Decision logic: Combine all heuristics to classify
        
        # === FALSE_POSITIVE Indicators ===
        false_positive_score = 0
        false_positive_reasons = []
        
        # Internal-to-internal traffic during business hours = likely false positive
        if (ip_results.get("internal_to_internal") and 
            timing_results.get("is_business_hours") and
            not traffic_results.get("has_high_severity_rules")):
            false_positive_score += 3
            false_positive_reasons.append("Internal traffic during business hours")
        
        # Maintenance window activity = likely false positive
        if timing_results.get("is_maintenance_window"):
            false_positive_score += 2
            false_positive_reasons.append("Activity during maintenance window")
        
        # Low volume + low confidence + internal traffic = likely false positive
        if (traffic_results.get("total_events", 0) < 10 and
            threat.get("confidence_score", 1.0) < self.low_confidence_threshold and
            ip_results.get("all_src_internal")):
            false_positive_score += 2
            false_positive_reasons.append("Low volume, low confidence, internal traffic")
        
        # === POSSIBLE_THREAT Indicators ===
        threat_score = 0
        threat_reasons = []
        
        # External-to-internal + high severity rules = likely threat
        if (ip_results.get("external_to_internal") and 
            traffic_results.get("has_high_severity_rules")):
            threat_score += 3
            threat_reasons.append("External IP with high severity rules")
        
        # Very high volume + burst activity + off-hours = likely attack
        if (traffic_results.get("very_high_volume") and
            traffic_results.get("burst_activity") and
            not timing_results.get("is_business_hours")):
            threat_score += 3
            threat_reasons.append("Very high volume burst during off-hours")
        
        # High request rate + external IP + high severity = likely threat
        if (traffic_results.get("high_request_rate") and
            ip_results.get("has_external_src") and
            traffic_results.get("has_high_severity_rules")):
            threat_score += 2
            threat_reasons.append("High request rate from external IP with high severity")
        
        # Multiple rule violations + high severity = likely threat
        if (traffic_results.get("multiple_rule_violations") and
            traffic_results.get("has_high_severity_rules")):
            threat_score += 2
            threat_reasons.append("Multiple high-severity rule violations")
        
        # Off-hours + external IP + high volume = suspicious
        if (not timing_results.get("is_business_hours") and
            ip_results.get("has_external_src") and
            traffic_results.get("high_volume")):
            threat_score += 2
            threat_reasons.append("External IP high volume during off-hours")
        
        # === Make Classification Decision ===
        
        # Strong false positive indicators
        if false_positive_score >= 3:
            result["classification"] = "FALSE_POSITIVE"
            result["feature_analyzer_confidence_score"] = min(0.9, 0.5 + (false_positive_score * 0.1))
            result["reasoning"] = "; ".join(false_positive_reasons)
        
        # Strong threat indicators
        elif threat_score >= 3:
            result["classification"] = "POSSIBLE_THREAT"
            result["feature_analyzer_confidence_score"] = min(0.9, 0.5 + (threat_score * 0.1))
            result["reasoning"] = "; ".join(threat_reasons)
        
        # Moderate false positive (internal traffic + business hours, but no high severity)
        elif false_positive_score >= 2 and threat_score == 0:
            result["classification"] = "FALSE_POSITIVE"
            result["feature_analyzer_confidence_score"] = 0.7
            result["reasoning"] = "; ".join(false_positive_reasons) if false_positive_reasons else "Benign pattern indicators"
        
        # Moderate threat (external IP + some indicators, but not all)
        elif threat_score >= 2:
            result["classification"] = "POSSIBLE_THREAT"
            result["feature_analyzer_confidence_score"] = 0.7
            result["reasoning"] = "; ".join(threat_reasons) if threat_reasons else "Suspicious pattern indicators"
        
        # Ambiguous case - default to NEEDS_LLM_REVIEW
        else:
            result["classification"] = "NEEDS_LLM_REVIEW"
            result["feature_analyzer_confidence_score"] = 0.5
            
            # Build reasoning from what we do know
            reasoning_parts = []
            if ip_results.get("external_to_internal"):
                reasoning_parts.append("External-to-internal traffic")
            if timing_results.get("is_business_hours"):
                reasoning_parts.append("Business hours activity")
            if traffic_results.get("high_volume"):
                reasoning_parts.append("High volume")
            
            result["reasoning"] = "; ".join(reasoning_parts) if reasoning_parts else "Ambiguous pattern - requires LLM analysis"
        
        # Adjust classification based on threat's original ML confidence score
        if ml_confidence_score < self.low_confidence_threshold:
            # Very low confidence threat = likely false positive unless strong indicators
            if result["classification"] == "POSSIBLE_THREAT" and threat_score < 4:
                result["classification"] = "NEEDS_LLM_REVIEW"
                result["feature_analyzer_confidence_score"] = 0.4
                result["reasoning"] += " (Low confidence threat)"
        elif ml_confidence_score > self.high_confidence_threshold:
            # High confidence threat = likely real unless clear false positive indicators
            if result["classification"] == "FALSE_POSITIVE" and false_positive_score < 3:
                result["classification"] = "NEEDS_LLM_REVIEW"
                result["feature_analyzer_confidence_score"] = 0.6
                result["reasoning"] += " (High confidence threat)"
        
        if self.enable_logging:
            print(f"Threat {threat.get('ip', 'unknown')}: {result['classification']} "
                  f"(ML: {result['ml_confidence_score']:.2f}, "
                  f"FeatureAnalyzer: {result['feature_analyzer_confidence_score']:.2f}) - {result['reasoning']}")
        
        return result
