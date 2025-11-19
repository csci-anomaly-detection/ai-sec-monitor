import logging
import os
import re
import json
from langchain_ollama import ChatOllama
from chroma import query_chroma, query_chroma_semantic, query_chroma_advanced
from websearch import websearch
from collections import Counter, defaultdict

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

log_file = os.path.expanduser('~/pipeline.log')
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
def print_tier_header(tier_num, tier_name):
    """Print tier header with color"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}  TIER {tier_num}: {tier_name}{' ' * (58 - len(tier_name))}{Colors.ENDC}{Colors.CYAN}  ║{Colors.ENDC}{Colors.BOLD}")
    print(f"{Colors.CYAN}{'═' * 80}{Colors.ENDC}\n")

def print_info_box(content_lines, color=Colors.BLUE):
    """Print info in a colored box"""
    print(f"{color}┌{'─' * 78}┐{Colors.ENDC}")
    for line in content_lines:
        line = str(line)[:76]
        print(f"{color}│{Colors.ENDC} {line:<76} {color}│{Colors.ENDC}")
    print(f"{color}└{'─' * 78}┘{Colors.ENDC}\n")

def print_analysis_box(title, content_lines, color=Colors.GREEN):
    """Print titled analysis box"""
    print(f"{color}╔{'═' * 78}╗{Colors.ENDC}")
    print(f"{color}║{Colors.ENDC} {Colors.BOLD}{title}{Colors.ENDC}{' ' * (74 - len(title))} {color}║{Colors.ENDC}")
    print(f"{color}╠{'─' * 78}╣{Colors.ENDC}")
    for line in content_lines:
        line = str(line)[:76]
        print(f"{color}║{Colors.ENDC} {line:<76} {color}║{Colors.ENDC}")
    print(f"{color}╚{'═' * 78}╝{Colors.ENDC}\n")

# ============================================================================

port = os.getenv("OLLAMA_PORT", "11434")
llm = ChatOllama(
    model="qwen2.5:32b",
    base_url=f"http://ollama:{port}",
    temperature=0,
    num_ctx=8192,
    stop=["Observation:", "\nObservation"]
)

def trim_messages(messages, max_messages=10):
    """Keep system prompt + last N user/assistant pairs"""
    if len(messages) <= max_messages + 2: 
        return messages
    
    system_msg = messages[0]
    recent_messages = messages[-(max_messages):]
    
    return [system_msg] + recent_messages


# ============================================================================
# EXTRACT THREAT DATA FROM VALIDATION FORMAT
# ============================================================================

def extract_threat_from_validation_result(validation_result: dict) -> dict:
    """
    Extract threat data from validation orchestrator result format.
    
    Args:
        validation_result: Dict with 'threat', 'analysis', 'llm_validation' keys
    
    Returns:
        Normalized threat dict for analysis
    """
    threat_data = validation_result.get("threat", {})
    analysis = validation_result.get("analysis", {})
    llm_validation = validation_result.get("llm_validation", {})
    
    # Extract key fields
    ip = threat_data.get("ip", "unknown")
    attack_type = threat_data.get("attack_type", "unknown")
    severity = threat_data.get("severity", "LOW")
    total_events = threat_data.get("total_events", 0)
    
    # Get classification info
    fa_classification = analysis.get("classification", "UNKNOWN")
    llm_decision = llm_validation.get("decision", "UNKNOWN")
    
    # Extract IPs and ports
    src_ips = threat_data.get("src_ips", [ip])
    dest_ips = threat_data.get("dest_ips", [])
    ports = threat_data.get("ports", [])
    
    # Extract signature IDs from rules violated
    signature_ids = []
    for rule in threat_data.get("rules_violated", []):
        if "rule_id" in rule:
            signature_ids.append(str(rule["rule_id"]))
    
    # Determine if this should be analyzed
    proceed_to_analysis = llm_validation.get("proceed_to_analysis", True)
    if fa_classification == "FALSE_POSITIVE":
        proceed_to_analysis = False
    
    return {
        "ip": ip,
        "attack_type": attack_type,
        "severity": severity,
        "total_events": total_events,
        "classification": fa_classification,
        "llm_decision": llm_decision,
        "proceed_to_analysis": proceed_to_analysis,
        "src_ips": src_ips,
        "dest_ips": dest_ips,
        "ports": ports,
        "signature_ids": signature_ids,
        "rules_violated": threat_data.get("rules_violated", []),
        "confidence_score": threat_data.get("confidence_score", 0.5),
        "timestamps": threat_data.get("timestamps", []),
        "heuristic_flags": analysis.get("heuristic_flags", []),
        "llm_reasoning": llm_validation.get("reasoning", ""),
        "validation_result": validation_result  # Keep original for reference
    }


# ============================================================================
# HIERARCHICAL CLUSTERING APPROACH
# ============================================================================

def analyze_all_threats_batch(validated_results, max_retries=20):
    """
    Three-tier hierarchical analysis: Cluster → Investigate → Synthesize
    
    Args:
        validated_results: List of validation results from ValidationOrchestrator
    """
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'█' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.GREEN}█  🎯 HIERARCHICAL THREAT ANALYSIS STARTED{' ' * (35)}{Colors.ENDC}{Colors.GREEN}█{Colors.ENDC}{Colors.BOLD}")
    print(f"{Colors.GREEN}{'█' * 80}{Colors.ENDC}\n")
    
    # Extract threats from validation results
    all_threats = []
    for result in validated_results:
        threat = extract_threat_from_validation_result(result)
        # Only analyze threats that passed validation
        if threat["proceed_to_analysis"]:
            all_threats.append(threat)
    
    print_info_box([
        f"📊 Total validated results: {len(validated_results)}",
        f"📊 Threats for analysis: {len(all_threats)}"
    ], Colors.CYAN)
    
    if not all_threats:
        print_info_box([
            f"⚠️  No threats require analysis",
            f"   All alerts were filtered as false positives or benign"
        ], Colors.YELLOW)
        return build_empty_report()
    
    # ========================================================================
    # TIER 1: CLUSTERING - Group similar threats (NO LLM)
    # ========================================================================
    print_tier_header(1, "CLUSTERING THREATS BY PATTERN")
    
    clusters = cluster_threats_by_pattern(all_threats)
    
    # ========================================================================
    # TIER 2: INVESTIGATION - Deep dive on each cluster (WITH TOOLS)
    # ========================================================================
    print_tier_header(2, "INVESTIGATING TOP CLUSTERS")
    
    cluster_analyses = []
    for idx, (cluster_key, cluster_threats) in enumerate(list(clusters.items())[:10]):  # Top 10 clusters
        print(f"{Colors.YELLOW}▶ Analyzing cluster {idx+1}/{min(10, len(clusters))}: {cluster_key}{Colors.ENDC}")
        analysis = investigate_cluster(cluster_key, cluster_threats, max_tools=3)
        cluster_analyses.append(analysis)
    
    # ========================================================================
    # TIER 3: SYNTHESIS - Generate final consolidated report (WITH LLM)
    # ========================================================================
    print_tier_header(3, "SYNTHESIZING FINAL REPORT")
    
    final_report = synthesize_final_report(cluster_analyses, all_threats, clusters)
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}{'█' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.GREEN}█  ✅ HIERARCHICAL ANALYSIS COMPLETE{' ' * (41)}{Colors.ENDC}{Colors.GREEN}█{Colors.ENDC}{Colors.BOLD}")
    print(f"{Colors.GREEN}{'█' * 80}{Colors.ENDC}\n")
    
    return final_report


def cluster_threats_by_pattern(all_threats):
    """
    Group threats by IP + Attack Type (no LLM needed)
    Returns: dict of {cluster_key: [threats]}
    """
    clusters = defaultdict(list)
    
    for threat in all_threats:
        ip = threat.get("ip", "unknown")
        attack_type = threat.get("attack_type", "unknown")
        
        # Normalize attack type for better clustering
        attack_type_normalized = attack_type.lower().strip().replace(" ", "_")
        
        # Cluster key: IP + primary attack type
        cluster_key = f"{ip}_{attack_type_normalized}"
        clusters[cluster_key].append(threat)
    
    # Sort by cluster size (largest first)
    sorted_clusters = dict(sorted(
        clusters.items(), 
        key=lambda x: len(x[1]), 
        reverse=True
    ))
    
    # Log cluster statistics
    cluster_sizes = [len(threats) for threats in sorted_clusters.values()]
    
    stats = [
        f"✅ Identified {len(sorted_clusters)} unique threat clusters",
        "",
        f"📈 Cluster Statistics:",
        f"   • Total clusters: {len(sorted_clusters)}",
        f"   • Largest cluster: {max(cluster_sizes)} threats",
        f"   • Smallest cluster: {min(cluster_sizes)} threats",
        f"   • Average cluster size: {sum(cluster_sizes) / len(cluster_sizes):.1f} threats",
    ]
    print_info_box(stats, Colors.GREEN)
    
    # Show top 5 clusters
    top_clusters = []
    for idx, (key, threats) in enumerate(list(sorted_clusters.items())[:5]):
        ip, attack = key.split("_", 1)
        top_clusters.append(f"   {idx+1}. {ip} - {attack}: {len(threats)} threats")
    
    print_analysis_box("🔝 TOP 5 CLUSTERS", top_clusters, Colors.YELLOW)
    
    return sorted_clusters


def investigate_cluster(cluster_key, cluster_threats, max_tools=3):
    """
    Use tools to investigate ONE cluster (2-3 tool calls per cluster)
    """
    ip, attack_type = cluster_key.split("_", 1)
    
    # Aggregate severity (use highest)
    severity_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_severity = max(
        (severity_map.get(t.get("severity", "LOW"), 1) for t in cluster_threats),
        default=1
    )
    
    # Collect all signature IDs
    all_signature_ids = set()
    for t in cluster_threats:
        all_signature_ids.update(t.get("signature_ids", []))
    
    # Count total events
    total_events = sum(t.get("total_events", 1) for t in cluster_threats)
    
    investigation = {
        "cluster_id": cluster_key,
        "ip": ip,
        "attack_type": attack_type.replace("_", " "),
        "threat_count": len(cluster_threats),
        "total_events": total_events,
        "severity": max_severity,
        "signature_ids": list(all_signature_ids),
        "tool_findings": []
    }
    
    findings = [
        f"IP: {ip}",
        f"Attack Type: {attack_type.replace('_', ' ')}",
        f"Threat Count: {len(cluster_threats)}",
        f"Total Events: {total_events}"
    ]
    
    # Tool 1: Check historical data for this IP
    try:
        chroma_result = query_chroma(f"all_threats {ip}")
        finding = {
            "tool": "ChromaQuery",
            "query": f"IP {ip}",
            "result": chroma_result[:500] if chroma_result else "No historical data found"
        }
        investigation["tool_findings"].append(finding)
        findings.append(f"🔧 Tool 1 (ChromaQuery): ✓ Success")
    except Exception as e:
        findings.append(f"🔧 Tool 1 (ChromaQuery): ✗ Failed")
    
    # Tool 2: Semantic search for similar attacks (only for significant clusters)
    if len(cluster_threats) >= 1 or total_events > 10:
        try:
            semantic_result = query_chroma_semantic(
                f"{attack_type.replace('_', ' ')} attack pattern", 
                collection_name="attack_mitigation_knowledge", 
                top_k=3
            )
            finding = {
                "tool": "SemanticSearch",
                "query": attack_type.replace("_", " "),
                "result": semantic_result[:500] if semantic_result else "No similar patterns found"
            }
            investigation["tool_findings"].append(finding)
            findings.append(f"🔧 Tool 2 (SemanticSearch): ✓ Success")
        except Exception as e:
            findings.append(f"🔧 Tool 2 (SemanticSearch): ✗ Failed")
    
    # Tool 3: Web research (only for top clusters)
    if total_events > 50 or max_severity >= 3:
        try:
            web_result = websearch(f"{attack_type.replace('_', ' ')} CVE mitigation strategies")
            finding = {
                "tool": "WebSearch",
                "query": f"{attack_type.replace('_', ' ')} mitigation",
                "result": web_result[:500] if web_result else "No CVE data found"
            }
            investigation["tool_findings"].append(finding)
            findings.append(f"🔧 Tool 3 (WebSearch): ✓ Success")
        except Exception as e:
            findings.append(f"🔧 Tool 3 (WebSearch): ✗ Failed")
    
    print_info_box(findings, Colors.BLUE)
    
    return investigation


def sanitize_json_string(json_str):
    """
    Convert single quotes to double quotes in JSON strings
    Handles common JSON formatting issues from LLM output
    """
    import re
    
    # Pattern 1: ['item1', 'item2'] -> ["item1", "item2"]
    json_str = re.sub(r"\['([^']*?)'\]", r'["\1"]', json_str)
    json_str = re.sub(r"\['([^']*?)',\s*'([^']*?)'\]", r'["\1", "\2"]', json_str)
    
    # Pattern 2: Single quotes around keys and values
    json_str = re.sub(r"'([^']*?)'\s*:\s*'([^']*?)'", r'"\1": "\2"', json_str)
    
    # Pattern 3: Arrays with single quotes
    json_str = re.sub(r":\s*\['([^']*?)'\]", r': ["\1"]', json_str)
    json_str = re.sub(r":\s*\['([^']*?)',\s*'([^']*?)'\]", r': ["\1", "\2"]', json_str)
    json_str = re.sub(r":\s*\['([^']*?)',\s*'([^']*?)',\s*'([^']*?)'\]", r': ["\1", "\2", "\3"]', json_str)
    
    # Pattern 4: Dict with single quotes
    json_str = re.sub(r"\{'([^']*?)'\s*:\s*(\d+)\}", r'{"\1": \2}', json_str)
    json_str = re.sub(r"\{'([^']*?)'\s*:\s*(\d+),\s*'([^']*?)'\s*:\s*(\d+)\}", r'{"\1": \2, "\3": \4}', json_str)
    
    return json_str


def synthesize_final_report(cluster_analyses, all_threats, clusters):
    """
    Use LLM ONCE to synthesize all cluster investigations into final report
    """
    print_info_box([f"📝 Synthesizing report from {len(cluster_analyses)} cluster analyses..."], Colors.CYAN)
    
    # Build consolidated summary
    total_threats = len(all_threats)
    unique_ips = set()
    attack_types = Counter()
    severity_distribution = Counter()
    all_signature_ids = set()
    llm_decisions = Counter()
    
    for cluster_key, cluster_threats in clusters.items():
        ip, attack_type = cluster_key.split("_", 1)
        unique_ips.add(ip)
        attack_types[attack_type.replace("_", " ")] += len(cluster_threats)
        
        for threat in cluster_threats:
            # Map severity to categories
            severity = threat.get("severity", "LOW")
            severity_distribution[severity] += 1
            
            # Track LLM decisions
            llm_decision = threat.get("llm_decision", "UNKNOWN")
            if llm_decision != "UNKNOWN":
                llm_decisions[llm_decision] += 1
            
            # Collect signature IDs
            for sid in threat.get("signature_ids", []):
                all_signature_ids.add(str(sid))
    
    # Prepare cluster summary for LLM
    cluster_summary = []
    for analysis in cluster_analyses[:5]:  # Top 5 for LLM context
        cluster_summary.append({
            "cluster_id": analysis["cluster_id"],
            "ip": analysis["ip"],
            "attack_type": analysis["attack_type"],
            "threat_count": analysis["threat_count"],
            "total_events": analysis["total_events"],
            "severity": analysis["severity"],
            "findings": [f["result"][:200] for f in analysis["tool_findings"]]
        })
    
    synthesis_prompt = f"""You are a senior cybersecurity analyst. Based on the cluster investigations below, produce ONE comprehensive security report.

THREAT LANDSCAPE SUMMARY:
- Total Threats: {total_threats}
- Unique Attackers: {len(unique_ips)}
- Attack Categories: {len(attack_types)}
- Severity Distribution: {dict(severity_distribution)}
- LLM Validation Decisions: {dict(llm_decisions)}

TOP CLUSTER INVESTIGATIONS:
{json.dumps(cluster_summary, indent=2)}

THREAT STATISTICS:
- Top Attack Types: {dict(attack_types.most_common(5))}
- Unique IPs: {list(unique_ips)[:5]}
- Signature IDs: {list(all_signature_ids)[:10]}

Provide your analysis as valid JSON (with DOUBLE QUOTES) in this format:
{{
  "executive_summary": "High-level overview of the threat landscape based on cluster analysis",
  "threat_statistics": {{
    "total_threats": {total_threats},
    "unique_attackers": {len(unique_ips)},
    "attack_categories": {list(attack_types.keys())},
    "severity_breakdown": {dict(severity_distribution)},
    "clusters_analyzed": {len(cluster_analyses)}
  }},
  "key_findings": [
    "Finding 1: Pattern observed across multiple clusters",
    "Finding 2: Evidence from tool investigations"
  ],
  "threat_actors": [
    {{
      "ip": "10.77.0.20",
      "attack_types": ["attack1", "attack2"],
      "threat_count": 100,
      "sophistication": "MEDIUM|HIGH|LOW",
      "threat_level": "HIGH|MEDIUM|LOW"
    }}
  ],
  "attack_timeline": "Description of attack progression based on clusters",
  "iocs": {{
    "malicious_ips": {list(unique_ips)[:10]},
    "signature_ids": {list(all_signature_ids)[:20]},
    "attack_patterns": {list(attack_types.keys())[:10]}
  }},
  "immediate_actions": [
    "List of immediate actions that can be taken"
  ],
  "strategic_recommendations": [
     "List of long term strategic recommendations"
  ],
  "risk_assessment": {{
    "overall_risk": "HIGH|MEDIUM|LOW",
    "confidence": 0.9,
    "reasoning": "Based on cluster analysis and tool investigation findings"
  }}
}}

CRITICAL: Output MUST be valid JSON starting with {{ and ending with }}. No markdown, no code blocks, just JSON."""

    messages = [
        {"role": "system", "content": "You are a senior cybersecurity analyst synthesizing threat intelligence from cluster analysis. Output MUST be valid JSON with DOUBLE QUOTES. Start with { and end with }. No markdown or extra text."},
        {"role": "user", "content": synthesis_prompt}
    ]
    
    try:
        print_info_box([f"🤖 Invoking LLM for synthesis..."], Colors.YELLOW)
        response = llm.invoke(messages)
        content = response.content.strip()
        
        # Try to extract JSON from response
        final = None
        
        if "Final Answer:" in content:
            final = content.split("Final Answer:")[-1].strip()
        elif "```json" in content:
            final = content.split("```json")[-1].split("```")[0].strip()
        elif content.strip().startswith("{"):
            final = content.strip()
        else:
            start_idx = content.find("{")
            end_idx = content.rfind("}")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                final = content[start_idx:end_idx+1]
        
        if not final:
            print_info_box([f"❌ Could not extract JSON from LLM output"], Colors.RED)
            return build_report_from_clusters(cluster_analyses, total_threats, unique_ips, attack_types, severity_distribution, all_signature_ids)
        
        # Clean up JSON
        final = final.strip('`').strip()
        if final.startswith('json'):
            final = final[4:].strip()
        
        # SANITIZE JSON
        final = sanitize_json_string(final)
        
        # Parse JSON
        final_json = json.loads(final)
        
        # Validate required fields
        required_fields = ['executive_summary', 'threat_statistics', 'key_findings', 
                         'threat_actors', 'iocs', 'immediate_actions', 
                         'strategic_recommendations', 'risk_assessment']
        
        missing_fields = [f for f in required_fields if f not in final_json]
        
        if missing_fields:
            if 'attack_timeline' not in final_json:
                final_json['attack_timeline'] = f"Attack campaign spanning {total_threats} events from {len(unique_ips)} sources"
        
        print_info_box([f"✅ LLM synthesis successful"], Colors.GREEN)
        return final_json
            
    except json.JSONDecodeError as e:
        print_info_box([
            f"❌ JSON parsing failed: {e}",
            f"Error at position {e.pos}: {e.msg}"
        ], Colors.RED)
        return build_report_from_clusters(cluster_analyses, total_threats, unique_ips, attack_types, severity_distribution, all_signature_ids)
    except Exception as e:
        print_info_box([
            f"❌ Synthesis failed: {e}"
        ], Colors.RED)
        return build_report_from_clusters(cluster_analyses, total_threats, unique_ips, attack_types, severity_distribution, all_signature_ids)


def build_report_from_clusters(cluster_analyses, total_threats, unique_ips, attack_types, severity_distribution, all_signature_ids):
    """
    Build structured report from cluster investigations (no LLM - pure data aggregation)
    """
    print_info_box([f"📊 Building report from cluster data (fallback mode)"], Colors.YELLOW)
    
    top_clusters = cluster_analyses[:5]
    
    return {
        "executive_summary": f"Analyzed {total_threats} security threats across {len(cluster_analyses)} distinct attack patterns. Top threats from {', '.join(list(unique_ips)[:3])}. Primary vectors: {', '.join(list(attack_types.keys())[:3])}.",
        "threat_statistics": {
            "total_threats": total_threats,
            "unique_attackers": len(unique_ips),
            "attack_categories": list(attack_types.keys()),
            "severity_breakdown": dict(severity_distribution),
            "clusters_analyzed": len(cluster_analyses)
        },
        "key_findings": [
            f"Cluster {idx+1}: {c['total_events']} events ({c['attack_type']} from {c['ip']})"
            for idx, c in enumerate(top_clusters)
        ] + [
            f"Total {len(unique_ips)} unique attacker IPs",
            f"Most common: {attack_types.most_common(1)[0][0]} ({attack_types.most_common(1)[0][1]} threats)"
        ],
        "threat_actors": [
            {
                "ip": c["ip"],
                "attack_types": [c["attack_type"]],
                "threat_count": c["threat_count"],
                "total_events": c["total_events"],
                "sophistication": "HIGH" if c["total_events"] > 100 else "MEDIUM",
                "threat_level": "HIGH" if c["severity"] >= 3 else "MEDIUM"
            }
            for c in top_clusters
        ],
        "iocs": {
            "malicious_ips": list(unique_ips),
            "signature_ids": list(all_signature_ids),
            "attack_patterns": list(attack_types.keys())
        },
        "immediate_actions": [
            f"🚨 Block {c['ip']} ({c['total_events']} events)"
            for c in top_clusters[:3]
        ] + [
            "Enable WAF rules",
            "Isolate affected systems",
            "Escalate to SOC"
        ],
        "strategic_recommendations": [
            "Deploy IPS to block patterns",
            "Implement rate limiting",
            "Security audit of systems",
            f"Strengthen defenses: {', '.join(list(attack_types.keys())[:3])}"
        ],
        "risk_assessment": {
            "overall_risk": "HIGH" if severity_distribution.get('HIGH', 0) > 10 else "MEDIUM",
            "confidence": 0.85,
            "reasoning": f"Hierarchical cluster analysis of {len(cluster_analyses)} patterns with tool investigation"
        }
    }


def build_empty_report():
    """Build report when no threats require analysis"""
    return {
        "executive_summary": "All alerts were filtered during validation. No actionable threats detected.",
        "threat_statistics": {
            "total_threats": 0,
            "unique_attackers": 0,
            "attack_categories": [],
            "severity_breakdown": {},
            "clusters_analyzed": 0
        },
        "key_findings": [
            "All alerts classified as false positives or benign",
            "No immediate threat response required"
        ],
        "threat_actors": [],
        "iocs": {
            "malicious_ips": [],
            "signature_ids": [],
            "attack_patterns": []
        },
        "immediate_actions": [
            "No immediate actions required",
            "Continue monitoring"
        ],
        "strategic_recommendations": [
            "Review validation rules if false positive rate seems high",
            "Maintain current security posture"
        ],
        "risk_assessment": {
            "overall_risk": "LOW",
            "confidence": 0.95,
            "reasoning": "Validation layer successfully filtered all non-threatening alerts"
        }
    }
