from typing import Dict, List, Any
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

class ThreatSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatIndicator:
    ip: str
    rules_violated: List[Dict[str, Any]]
    ml_anomalies: List[Dict[str, Any]]
    severity: ThreatSeverity
    confidence_score: float
    attack_type: str
    recommendation: str
    total_events: int

class ThreatCorrelator:
    def __init__(self):
        self.threat_thresholds = {
            'rules_count': 2,      # 2+ rules = elevated threat
            'anomaly_score': -0.5, # ML confidence threshold
            'event_volume': 50     # High volume threshold
        }
    
    def correlate_threats(self, rule_alerts: List[Dict], ml_results: List[Dict], logs: List[Dict]) -> List[ThreatIndicator]:
        """Correlate rule violations and ML anomalies by IP address"""
        
        # Group everything by IP
        ip_threats = defaultdict(lambda: {
            'rules': [],
            'anomalies': [],
            'event_count': 0,
            'logs': []
        })
        
        # Collect rule violations by IP
        for alert in rule_alerts:
            affected_ips = self._extract_ips_from_alert(alert, logs)
            for ip in affected_ips:
                ip_threats[ip]['rules'].append(alert)
        
        # Collect ML anomalies by IP
        for anomaly in ml_results:
            if anomaly:  # ML detected something
                affected_ips = self._extract_ips_from_logs(logs)
                for ip in affected_ips:
                    ip_threats[ip]['anomalies'].append(anomaly)
        
        # Count events per IP
        for log in logs:
            if 'src_ip' in log:
                ip = log['src_ip']
                ip_threats[ip]['event_count'] += 1
                ip_threats[ip]['logs'].append(log)
        
        # Generate threat indicators
        threats = []
        for ip, data in ip_threats.items():
            if self._is_significant_threat(data):
                threat = self._create_threat_indicator(ip, data)
                threats.append(threat)
        
        # Sort by severity and confidence
        return sorted(threats, key=lambda t: (t.severity.value, t.confidence_score), reverse=True)
    
    def _extract_ips_from_alert(self, alert: Dict, logs: List[Dict]) -> List[str]:
        """Extract IP addresses affected by this alert"""
        ips = set()
        
        # If alert has matches, extract IPs from them
        if 'matches' in alert:
            for match in alert['matches']:
                if 'src_ip' in match:
                    ips.add(match['src_ip'])
        
        # If it's a group alert, the group key might be an IP
        if 'group' in alert:
            if self._is_valid_ip(alert['group']):
                ips.add(alert['group'])
        
        return list(ips)
    
    def _extract_ips_from_logs(self, logs: List[Dict]) -> List[str]:
        """Extract all unique IPs from logs"""
        ips = set()
        for log in logs:
            if 'src_ip' in log:
                ips.add(log['src_ip'])
        return list(ips)
    
    def _is_significant_threat(self, data: Dict) -> bool:
        """Determine if this IP represents a significant threat"""
        rules_count = len(data['rules'])
        has_ml_anomaly = len(data['anomalies']) > 0
        high_volume = data['event_count'] >= self.threat_thresholds['event_volume']
        
        # Threat if: multiple rules violated OR rule + ML anomaly OR very high volume
        return (
            rules_count >= self.threat_thresholds['rules_count'] or
            (rules_count >= 1 and has_ml_anomaly) or
            high_volume
        )
    
    def _create_threat_indicator(self, ip: str, data: Dict) -> ThreatIndicator:
        """Create a comprehensive threat indicator"""
        
        # Calculate confidence score
        confidence = self._calculate_confidence(data)
        
        # Determine severity
        severity = self._determine_severity(data, confidence)
        
        # Classify attack type
        attack_type = self._classify_attack_type(data)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(severity, attack_type, data)
        
        return ThreatIndicator(
            ip=ip,
            rules_violated=data['rules'],
            ml_anomalies=data['anomalies'],
            severity=severity,
            confidence_score=confidence,
            attack_type=attack_type,
            recommendation=recommendation,
            total_events=data['event_count']
        )
    
    def _calculate_confidence(self, data: Dict) -> float:
        """Calculate threat confidence score (0.0 to 1.0)"""
        score = 0.0
        
        # Rule violations contribute to confidence
        score += min(len(data['rules']) * 0.2, 0.6)  # Max 0.6 from rules
        
        # ML anomalies contribute to confidence
        if data['anomalies']:
            ml_scores = [abs(a.get('anomaly_score', 0)) for a in data['anomalies'] if 'anomaly_score' in a]
            if ml_scores:
                avg_ml_score = sum(ml_scores) / len(ml_scores)
                score += min(avg_ml_score, 0.4)  # Max 0.4 from ML
        
        # Event volume contributes
        if data['event_count'] > 100:
            score += 0.1
        if data['event_count'] > 1000:
            score += 0.1
        
        return min(score, 1.0)
    
    def _determine_severity(self, data: Dict, confidence: float) -> ThreatSeverity:
        """Determine threat severity based on indicators"""
        
        rules_count = len(data['rules'])
        event_count = data['event_count']
        has_critical_rule = any(r.get('severity') == 'critical' for r in data['rules'])
        
        if has_critical_rule or (rules_count >= 3 and confidence > 0.8):
            return ThreatSeverity.CRITICAL
        elif rules_count >= 2 or event_count > 1000:
            return ThreatSeverity.HIGH
        elif rules_count >= 1 or confidence > 0.6:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _classify_attack_type(self, data: Dict) -> str:
        """Classify the type of attack based on indicators"""
        
        rule_ids = [r['rule_id'] for r in data['rules']]
        
        # Pattern matching for attack classification
        if 'metadata_service_alerts' in rule_ids:
            return "SSH Brute Force / Honeypot Probe"
        elif 'suricata_alert_storm' in rule_ids and data['event_count'] > 1000:
            return "Coordinated Attack / Botnet Activity"
        elif 'suspicious_src_ip' in rule_ids:
            return "Reconnaissance / Scanning"
        elif len(data['anomalies']) > 1:
            return "Behavioral Anomaly / Advanced Persistent Threat"
        else:
            return "Suspicious Activity"
    
    def _generate_recommendation(self, severity: ThreatSeverity, attack_type: str, data: Dict) -> str:
        """Generate actionable recommendations"""
        
        if severity == ThreatSeverity.CRITICAL:
            return "IMMEDIATE ACTION: Block IP, isolate affected systems, investigate network segment"
        elif severity == ThreatSeverity.HIGH:
            return "Block IP, monitor for lateral movement, check other systems"
        elif severity == ThreatSeverity.MEDIUM:
            return "Rate limit IP, increase monitoring, analyze attack patterns"
        else:
            return "Monitor closely, log for trend analysis"
    
    def _is_valid_ip(self, value: str) -> bool:
        """Simple IP validation"""
        try:
            parts = value.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except Exception:
            return False

def format_threat_report(threats: List[ThreatIndicator]) -> str:
    """Format threats into a readable report"""
    
    if not threats:
        return "NO SIGNIFICANT THREATS DETECTED"
    
    report = []
    report.append("=" * 50)
    
    for i, threat in enumerate(threats, start=1):
        
        report.append(f"\n THREAT #{i}: {threat.ip}")
        report.append(f"   Severity: {threat.severity.name} | Confidence: {threat.confidence_score:.2f}")
        report.append(f"   Attack Type: {threat.attack_type}")
        report.append(f"   Total Events: {threat.total_events}")
        
        if threat.rules_violated:
            report.append("   Rules Violated:")
            for rule in threat.rules_violated:
                report.append(f"     • {rule['rule_id']} ({rule.get('severity', 'unknown')})")
        
        if threat.ml_anomalies:
            report.append("   ML Anomalies:")
            for anomaly in threat.ml_anomalies:
                score = anomaly.get('anomaly_score', 0)
                report.append(f"     • {anomaly.get('rule_id', 'unknown')} (score: {score:.3f})")
        
        report.append(f"   Recommendation: {threat.recommendation}")
        report.append("-" * 50)
    
    return "\n".join(report)

def threat_to_dict(threat: 'ThreatIndicator') -> Dict[str, Any]:
    """Convert ThreatIndicator to JSON-serializable dictionary"""
    return {
        'ip': threat.ip,
        'rules_violated': threat.rules_violated,
        'ml_anomalies': threat.ml_anomalies,
        'severity': threat.severity.name,  # Convert enum to string
        'severity_level': threat.severity.value,  # Numeric value
        'confidence_score': threat.confidence_score,
        'attack_type': threat.attack_type,
        'recommendation': threat.recommendation,
        'total_events': threat.total_events
    }