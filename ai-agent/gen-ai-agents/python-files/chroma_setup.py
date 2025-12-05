"""
This file sets up chromaDB along with suricata rule, mitre attack mappings,
and loads demo threats from demo.json
"""
import chromadb
import os
from datetime import datetime
import PyPDF2
from pathlib import Path
from typing import List

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)

# ============================================================================
# CREATE COLLECTIONS
# ============================================================================
suricata_col = client.get_or_create_collection("suricata_rules")
all_threats_col = client.get_or_create_collection("all_threats")

# ============================================================================
# ADD SURICATA RULES
# ============================================================================
suricata_rules = [
    # HTTP SYN to DMZ web
    {"sid": "990101", "msg": "DEMO HTTP SYN to DMZ web", "content": "HTTP SYN", "mitre_id": "T1046"},  # Network Service Scanning

    # SSH SYN to Cowrie
    {"sid": "990102", "msg": "DEMO SSH SYN to Cowrie :2222", "content": "SSH SYN", "mitre_id": "T1046"},  # Network Service Scanning

    # Nmap Scan Detected
    {"sid": "1000001", "msg": "Nmap Scan Detected", "content": "Nmap Scan", "mitre_id": "T1046"},  # Network Service Scanning

    # SQL Injection Attempts
    {"sid": "1000010", "msg": "SQL Injection Attempt - UNION", "content": "SQL Injection UNION", "mitre_id": "T1190"},  # Exploit Public-Facing Application
    {"sid": "1000011", "msg": "SQL Injection Attempt - OR 1=1", "content": "SQL Injection OR 1=1", "mitre_id": "T1190"},
    {"sid": "1000012", "msg": "SQL Injection Attempt - Single Quote", "content": "SQL Injection Single Quote", "mitre_id": "T1190"},

    # XSS Attempts
    {"sid": "1000020", "msg": "XSS Attempt - Script Tag", "content": "XSS Script Tag", "mitre_id": "T1059"},  # Command and Scripting Interpreter
    {"sid": "1000021", "msg": "XSS Attempt - JavaScript Event", "content": "XSS JavaScript Event", "mitre_id": "T1059"},
    {"sid": "1000022", "msg": "XSS Attempt - IMG Tag", "content": "XSS IMG Tag", "mitre_id": "T1059"},

    # Command Injection
    {"sid": "1000030", "msg": "Command Injection - Linux Commands", "content": "Linux Command Injection", "mitre_id": "T1059"},
    {"sid": "1000031", "msg": "Command Injection - Pipe Command", "content": "Pipe Command Injection", "mitre_id": "T1059"},
    {"sid": "1000032", "msg": "Command Injection - System Files", "content": "System File Injection", "mitre_id": "T1059"},

    # Directory Traversal
    {"sid": "1000040", "msg": "Directory Traversal Attempt", "content": "Directory Traversal", "mitre_id": "T1006"},  # File and Directory Discovery
    {"sid": "1000041", "msg": "Directory Traversal - etc/passwd", "content": "Directory Traversal /etc/passwd", "mitre_id": "T1006"},

    # Malicious File Upload
    {"sid": "1000050", "msg": "Malicious File Upload - PHP", "content": "Malicious PHP Upload", "mitre_id": "T1105"},  # Ingress Tool Transfer

    # Web Shell Upload
    {"sid": "1000051", "msg": "Web Shell Upload Attempt", "content": "Web Shell Upload", "mitre_id": "T1505"},  # Web Shell

    # HTTP Brute Force Login Attempt
    {"sid": "1000060", "msg": "HTTP Brute Force Login Attempt", "content": "HTTP Brute Force", "mitre_id": "T1110"},  # Brute Force
]

suricata_col.add(
    ids=[r["sid"] for r in suricata_rules],
    documents=[r["msg"] for r in suricata_rules],
    metadatas=suricata_rules
)

# ============================================================================
# ADD ATTACK MITIGATION KNOWLEDGE
# ============================================================================
knowledge_col = client.get_or_create_collection("attack_mitigation_knowledge")

attack_mitigation_docs = [
    {
        "id": "mitigation_http_syn_scan",
        "attack": "HTTP SYN Scan / Service Probing",
        "description": "Multiple repeated SYN packets sent to TCP port 80 of the DMZ web server, indicating reconnaissance or a pre-attack scan to enumerate open services.",
        "mitigation": [
            "Enable SYN flood protection on the firewall or IPS",
            "Rate-limit repeated SYN packets from the same source",
            "Block or alert on abnormal connection attempts from the suspicious host",
            "Ensure web server is behind a reverse proxy or WAF",
            "Monitor logs for early reconnaissance behaviors"
        ]
    },
    {
        "id": "mitigation_sql_union",
        "attack": "SQL Injection Attempt - UNION operator",
        "description": "Attacker attempted to extract or modify database content using SQL UNION-based injection techniques.",
        "mitigation": [
            "Use parameterized queries or prepared statements",
            "Enable strict input validation and sanitization",
            "Deploy a Web Application Firewall (WAF) with SQLi signatures enabled",
            "Conduct code reviews for vulnerable database calls",
            "Enable least-privilege permissions for database accounts"
        ]
    },
    {
        "id": "mitigation_sql_or_true",
        "attack": "SQL Injection Attempt - OR 1=1",
        "description": "Attacker attempted authentication bypass or data extraction using always-true SQL logic ('OR 1=1').",
        "mitigation": [
            "Implement server-side input sanitization",
            "Enforce strong authentication controls",
            "Use stored procedures or ORM frameworks",
            "Deploy WAF filtering for logical SQLi payloads",
            "Perform regular vulnerability scanning of web inputs"
        ]
    },
    {
        "id": "mitigation_http_bruteforce",
        "attack": "HTTP Brute Force Login Attempt",
        "description": "Automated rapid login attempts against a web application's authentication endpoint.",
        "mitigation": [
            "Implement account lockout & throttling",
            "Use CAPTCHA on login pages",
            "Monitor for rapid repeated login failures",
            "Deploy WAF brute-force detection rules",
            "Enable MFA for all user accounts"
        ]
    },
    {
        "id": "mitigation_xss_script_tag",
        "attack": "Cross-Site Scripting (XSS) - Script Tag Injection",
        "description": "Attacker attempted to inject `<script>` tags into web inputs to execute malicious JavaScript.",
        "mitigation": [
            "Apply output encoding (HTML/JavaScript encoding)",
            "Filter script tags and dangerous characters server-side",
            "Deploy Content Security Policy (CSP)",
            "Use WAF rules for XSS payload detection",
            "Sanitize user-generated content before rendering"
        ]
    },
    {
        "id": "mitigation_xss_js_event",
        "attack": "Cross-Site Scripting (XSS) - JavaScript Event Injection",
        "description": "Attack attempt using JavaScript event handlers such as `onload`, `onclick`, etc.",
        "mitigation": [
            "Sanitize dangerous attributes (e.g., onload, onclick)",
            "Use whitelist-style input validation",
            "Enable CSP to restrict inline scripts",
            "Harden templates to prevent event handler injection",
            "Deploy WAF with XSS behavioral detection"
        ]
    },
    {
        "id": "mitigation_xss_img_tag",
        "attack": "Cross-Site Scripting (XSS) - IMG Tag Injection",
        "description": "Use of `<img>` tags with JavaScript attributes or malformed sources to trigger XSS.",
        "mitigation": [
            "Strip JavaScript URIs and harmful attributes from image tags",
            "Encode user-supplied HTML",
            "Implement CSP to disallow inline scripts",
            "Validate allowed HTML elements using a sanitizer library",
            "Monitor for anomalous client-side behavior"
        ]
    },
    {
        "id": "mitigation_command_injection",
        "attack": "Command Injection Attempt - System File Access",
        "description": "Attacker attempted to execute system-level commands or access OS-level files through input fields.",
        "mitigation": [
            "Do not pass user input into system calls directly",
            "Sanitize shell metacharacters (| ; & ` $ < >)",
            "Run web applications with minimal OS privileges",
            "Use allowlists for permitted commands or parameters",
            "Deploy runtime protection (e.g., mod_security, AppArmor)"
        ]
    },
    {
        "id": "mitigation_dir_traversal_passwd",
        "attack": "Directory Traversal - Sensitive File Access (e.g., /etc/passwd)",
        "description": "Attacker attempted directory traversal using ../ sequences to access system files such as /etc/passwd.",
        "mitigation": [
            "Normalize and validate file paths",
            "Block traversal sequences like ../ server-side",
            "Restrict file system permissions for the web service",
            "Use chroot or containerized environments",
            "Monitor logs for repeated traversal attempts"
        ]
    },
    {
        "id": "mitigation_dir_traversal_general",
        "attack": "Directory Traversal Attempt (General)",
        "description": "General attempt to escape the intended directory to access unauthorized files.",
        "mitigation": [
            "Validate and sanitize path inputs",
            "Enforce allowlists for file-access endpoints",
            "Disable direct filesystem access from user input",
            "Use WAF signatures for traversal payloads",
            "Implement OS-level hardening"
        ]
    },
    {
        "id": "mitigation_webshell_upload",
        "attack": "Web Shell Upload Attempt",
        "description": "Attacker attempted to upload a malicious script (web shell) to gain remote command execution.",
        "mitigation": [
            "Restrict uploaded file types using strict MIME and extension checks",
            "Store uploaded files outside the web root",
            "Scan uploaded files for malicious content",
            "Disable execution permissions on upload directories",
            "Monitor for suspicious file creation events"
        ]
    }
]

def flatten_metadata(doc):
    """Flatten metadata for ChromaDB storage"""
    meta = doc.copy()
    # Convert mitigation list to a string
    if isinstance(meta.get("mitigation"), list):
        meta["mitigation"] = "; ".join(meta["mitigation"])
    return meta

knowledge_col.add(
    ids=[doc["id"] for doc in attack_mitigation_docs],
    documents=[
        f"Attack: {doc['attack']}\nDescription: {doc['description']}\nMitigation: {', '.join(doc['mitigation'])}"
        for doc in attack_mitigation_docs
    ],
    metadatas=[flatten_metadata(doc) for doc in attack_mitigation_docs]
)

# ============================================================================
# LOAD DEMO THREATS - 20 Relevant Threats for Validation Layer
# ============================================================================
def load_demo_threats():
    """
    Create and load 20 demo threats into all_threats collection.
    These threats are formatted to match what the validation layer expects.
    """
    
    # Define 20 diverse demo threats covering different patterns
    demo_threats = [
        # ===== FALSE POSITIVE PATTERNS (8 threats) =====
        # Recurring FP IP - Port Scan
        {
            "ip": "192.168.1.100",
            "attack_type": "Port Scan",
            "severity": "LOW",
            "total_events": 15,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.85,
            "heuristic_flags": ["High volume", "Off-hours pattern"],
            "dest_ips": ["10.0.0.1", "10.0.0.2"],
            "ports": [22, 80, 443],
            "rules_violated": [{"rule_id": "SURICATA_PORT_SCAN"}],
            "description": "Recurring port scan from internal IP during off-hours",
            "timestamp": "2025-10-15T02:30:00Z"
        },
        {
            "ip": "192.168.1.100",
            "attack_type": "Port Scan",
            "severity": "LOW",
            "total_events": 12,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.88,
            "heuristic_flags": ["High volume", "Off-hours pattern"],
            "dest_ips": ["10.0.0.1"],
            "ports": [22, 80],
            "rules_violated": [{"rule_id": "SURICATA_PORT_SCAN"}],
            "description": "Recurring port scan from same internal IP",
            "timestamp": "2025-10-18T03:15:00Z"
        },
        {
            "ip": "192.168.1.100",
            "attack_type": "Port Scan",
            "severity": "LOW",
            "total_events": 18,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.90,
            "heuristic_flags": ["High volume", "Off-hours pattern"],
            "dest_ips": ["10.0.0.2"],
            "ports": [443, 8080],
            "rules_violated": [{"rule_id": "SURICATA_PORT_SCAN"}],
            "description": "Third occurrence of port scan from same IP",
            "timestamp": "2025-10-22T01:45:00Z"
        },
        # Recurring FP IP - Network Anomaly
        {
            "ip": "10.0.0.50",
            "attack_type": "Network Anomaly",
            "severity": "LOW",
            "total_events": 5,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.75,
            "heuristic_flags": ["Low volume", "Internal IP"],
            "dest_ips": ["10.0.0.1"],
            "ports": [443],
            "rules_violated": [{"rule_id": "SURICATA_ANOMALY"}],
            "description": "Internal network anomaly, likely benign",
            "timestamp": "2025-10-20T11:00:00Z"
        },
        {
            "ip": "10.0.0.50",
            "attack_type": "Network Anomaly",
            "severity": "LOW",
            "total_events": 3,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.78,
            "heuristic_flags": ["Low volume", "Internal IP"],
            "dest_ips": ["10.0.0.1"],
            "ports": [443],
            "rules_violated": [{"rule_id": "SURICATA_ANOMALY"}],
            "description": "Recurring network anomaly from internal IP",
            "timestamp": "2025-10-25T11:30:00Z"
        },
        # Recurring FP IP - Suspicious Activity (low severity)
        {
            "ip": "172.16.0.25",
            "attack_type": "Suspicious Activity",
            "severity": "LOW",
            "total_events": 8,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.70,
            "heuristic_flags": ["Low severity", "Internal network"],
            "dest_ips": ["172.16.0.1"],
            "ports": [80],
            "rules_violated": [{"rule_id": "SURICATA_SUSPICIOUS"}],
            "description": "Low-severity suspicious activity from internal network",
            "timestamp": "2025-10-16T14:20:00Z"
        },
        {
            "ip": "172.16.0.25",
            "attack_type": "Suspicious Activity",
            "severity": "LOW",
            "total_events": 6,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.72,
            "heuristic_flags": ["Low severity", "Internal network"],
            "dest_ips": ["172.16.0.1"],
            "ports": [80],
            "rules_violated": [{"rule_id": "SURICATA_SUSPICIOUS"}],
            "description": "Recurring low-severity suspicious activity",
            "timestamp": "2025-10-21T15:10:00Z"
        },
        {
            "ip": "172.16.0.25",
            "attack_type": "Suspicious Activity",
            "severity": "LOW",
            "total_events": 7,
            "classification": "false_positive",
            "llm_decision": "FALSE_POSITIVE",
            "confidence_score": 0.75,
            "heuristic_flags": ["Low severity", "Internal network"],
            "dest_ips": ["172.16.0.1"],
            "ports": [80],
            "rules_violated": [{"rule_id": "SURICATA_SUSPICIOUS"}],
            "description": "Third occurrence of low-severity suspicious activity",
            "timestamp": "2025-10-28T13:45:00Z"
        },
        
        # ===== REAL THREATS (6 threats) =====
        # SQL Injection - High Severity
        {
            "ip": "203.0.113.45",
            "attack_type": "SQL Injection",
            "severity": "HIGH",
            "total_events": 3,
            "classification": "REAL_THREAT",
            "llm_decision": "REAL_THREAT",
            "confidence_score": 0.92,
            "heuristic_flags": ["Suspicious payload", "High severity"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80, 443],
            "rules_violated": [{"rule_id": "1000010"}],
            "description": "SQL injection attempt with UNION operator targeting web application",
            "timestamp": "2025-10-20T09:15:00Z"
        },
        {
            "ip": "203.0.113.45",
            "attack_type": "SQL Injection",
            "severity": "CRITICAL",
            "total_events": 5,
            "classification": "REAL_THREAT",
            "llm_decision": "REAL_THREAT",
            "confidence_score": 0.95,
            "heuristic_flags": ["Suspicious payload", "High severity", "Escalation detected"],
            "dest_ips": ["10.77.0.20"],
            "ports": [443],
            "rules_violated": [{"rule_id": "1000011"}],
            "description": "Escalated SQL injection with OR 1=1 payload, critical severity",
            "timestamp": "2025-10-25T10:30:00Z"
        },
        # XSS Attack
        {
            "ip": "198.51.100.78",
            "attack_type": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "total_events": 2,
            "classification": "REAL_THREAT",
            "llm_decision": "REAL_THREAT",
            "confidence_score": 0.88,
            "heuristic_flags": ["Malicious script tag", "High severity"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80],
            "rules_violated": [{"rule_id": "1000020"}],
            "description": "XSS attack attempt with script tag injection",
            "timestamp": "2025-10-22T14:20:00Z"
        },
        # Command Injection
        {
            "ip": "203.0.113.67",
            "attack_type": "Command Injection",
            "severity": "HIGH",
            "total_events": 4,
            "classification": "REAL_THREAT",
            "llm_decision": "REAL_THREAT",
            "confidence_score": 0.90,
            "heuristic_flags": ["System command detected", "High severity"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80],
            "rules_violated": [{"rule_id": "1000030"}],
            "description": "Command injection attempt with Linux system commands",
            "timestamp": "2025-10-24T11:45:00Z"
        },
        # Directory Traversal
        {
            "ip": "198.51.100.89",
            "attack_type": "Directory Traversal",
            "severity": "MEDIUM",
            "total_events": 1,
            "classification": "REAL_THREAT",
            "llm_decision": "REAL_THREAT",
            "confidence_score": 0.82,
            "heuristic_flags": ["Path traversal detected"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80],
            "rules_violated": [{"rule_id": "1000041"}],
            "description": "Directory traversal attempt to access /etc/passwd",
            "timestamp": "2025-10-26T16:30:00Z"
        },
        # Brute Force Attack
        {
            "ip": "203.0.113.12",
            "attack_type": "Brute Force",
            "severity": "HIGH",
            "total_events": 150,
            "classification": "REAL_THREAT",
            "llm_decision": "REAL_THREAT",
            "confidence_score": 0.93,
            "heuristic_flags": ["High volume", "Rapid login attempts"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80, 443],
            "rules_violated": [{"rule_id": "1000060"}],
            "description": "HTTP brute force login attempt with 150 failed attempts",
            "timestamp": "2025-10-27T08:00:00Z"
        },
        
        # ===== SUSPICIOUS ACTIVITIES (4 threats) =====
        {
            "ip": "198.51.100.25",
            "attack_type": "Suspicious Activity",
            "severity": "MEDIUM",
            "total_events": 500,
            "classification": "SUSPICIOUS",
            "llm_decision": "SUSPICIOUS",
            "confidence_score": 0.65,
            "heuristic_flags": ["High volume", "Multiple ports"],
            "dest_ips": ["10.77.0.20"],
            "ports": [3389, 22, 80],
            "rules_violated": [{"rule_id": "suricata_alert_storm"}],
            "description": "High volume of Suricata alerts from single IP, multiple ports targeted",
            "timestamp": "2025-11-05T05:14:29Z"
        },
        {
            "ip": "203.0.113.99",
            "attack_type": "Port Scan",
            "severity": "MEDIUM",
            "total_events": 45,
            "classification": "SUSPICIOUS",
            "llm_decision": "SUSPICIOUS",
            "confidence_score": 0.60,
            "heuristic_flags": ["High volume", "External IP"],
            "dest_ips": ["10.77.0.20"],
            "ports": [22, 23, 25, 80, 443, 3389],
            "rules_violated": [{"rule_id": "1000001"}],
            "description": "Nmap scan detected from external IP, multiple ports scanned",
            "timestamp": "2025-10-23T19:30:00Z"
        },
        {
            "ip": "198.51.100.34",
            "attack_type": "Web Shell Upload",
            "severity": "MEDIUM",
            "total_events": 1,
            "classification": "SUSPICIOUS",
            "llm_decision": "SUSPICIOUS",
            "confidence_score": 0.70,
            "heuristic_flags": ["Malicious file upload"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80],
            "rules_violated": [{"rule_id": "1000051"}],
            "description": "Web shell upload attempt detected",
            "timestamp": "2025-10-28T12:15:00Z"
        },
        {
            "ip": "203.0.113.56",
            "attack_type": "Malicious File Upload",
            "severity": "MEDIUM",
            "total_events": 2,
            "classification": "SUSPICIOUS",
            "llm_decision": "SUSPICIOUS",
            "confidence_score": 0.68,
            "heuristic_flags": ["PHP file upload"],
            "dest_ips": ["10.77.0.20"],
            "ports": [80],
            "rules_violated": [{"rule_id": "1000050"}],
            "description": "Malicious PHP file upload attempt",
            "timestamp": "2025-10-29T15:20:00Z"
        },
        
        # ===== BENIGN ANOMALIES (2 threats) =====
        {
            "ip": "10.0.0.75",
            "attack_type": "Network Anomaly",
            "severity": "LOW",
            "total_events": 1,
            "classification": "BENIGN_ANOMALY",
            "llm_decision": "BENIGN_ANOMALY",
            "confidence_score": 0.75,
            "heuristic_flags": ["Low volume", "Internal IP"],
            "dest_ips": ["10.0.0.1"],
            "ports": [443],
            "rules_violated": [{"rule_id": "SURICATA_ANOMALY"}],
            "description": "Single network anomaly from internal IP, likely normal variation",
            "timestamp": "2025-10-19T10:00:00Z"
        },
        {
            "ip": "172.16.0.50",
            "attack_type": "Network Anomaly",
            "severity": "LOW",
            "total_events": 2,
            "classification": "BENIGN_ANOMALY",
            "llm_decision": "BENIGN_ANOMALY",
            "confidence_score": 0.72,
            "heuristic_flags": ["Low volume", "Internal IP", "Normal traffic pattern"],
            "dest_ips": ["172.16.0.1"],
            "ports": [80],
            "rules_violated": [{"rule_id": "SURICATA_ANOMALY"}],
            "description": "Minor network anomaly from internal network, benign",
            "timestamp": "2025-10-30T09:30:00Z"
        }
    ]
    
    print(f"\n{'='*80}")
    print(f"📥 Loading {len(demo_threats)} demo threats into ChromaDB...")
    print(f"{'='*80}\n")
    
    # Prepare documents for ChromaDB (matching validation_orchestrator format)
    documents = []
    metadatas = []
    ids = []
    
    for idx, threat in enumerate(demo_threats):
        ip = threat.get("ip", "unknown")
        attack_type = threat.get("attack_type", "unknown")
        severity = threat.get("severity", "LOW")
        total_events = threat.get("total_events", 0)
        classification = threat.get("classification", "UNKNOWN")
        llm_decision = threat.get("llm_decision", "UNKNOWN")
        heuristic_flags = threat.get("heuristic_flags", [])
        dest_ips = threat.get("dest_ips", [])
        ports = threat.get("ports", [])
        rules_violated = threat.get("rules_violated", [])
        
        # Create document text for embedding (matching validation_orchestrator format)
        doc_text = f"""
IP: {ip}
Attack Type: {attack_type}
Severity: {severity}
Total Events: {total_events}
Classification: {classification}
LLM Decision: {llm_decision}
Heuristic Flags: {', '.join(heuristic_flags)}
Destination IPs: {', '.join(map(str, dest_ips))}
Ports Targeted: {', '.join(map(str, ports))}
Rules Violated: {', '.join([r.get('rule_id', '') for r in rules_violated])}
""".strip()
        
        # Create metadata (matching validation_orchestrator format)
        metadata = {
            "ip": ip,
            "attack_type": attack_type,
            "severity": severity,
            "total_events": total_events,
            "classification": classification,
            "llm_decision": llm_decision,
            "confidence_score": float(threat.get("confidence_score", 0.5)),
            "timestamp": threat.get("timestamp", datetime.now().isoformat()),
            "source": "chroma_setup_demo"
        }
        
        # Create unique ID
        threat_id = f"demo_threat_{ip}_{datetime.now().strftime('%Y%m%d')}_{idx+1}"
        
        documents.append(doc_text)
        metadatas.append(metadata)
        ids.append(threat_id)
    
    # Add to ChromaDB
    try:
        all_threats_col.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )
        
        # Print summary
        classification_counts = {}
        for threat in demo_threats:
            cls = threat.get("classification", "UNKNOWN")
            classification_counts[cls] = classification_counts.get(cls, 0) + 1
        
        print("✅ Demo threats loaded successfully!")
        print(f"\n📊 Classification Breakdown:")
        for cls, count in classification_counts.items():
            print(f"   • {cls}: {count}")
        print(f"\n💾 Total threats stored: {len(demo_threats)}")
        return len(demo_threats)
    
    except Exception as e:
        print(f"❌ Error loading demo threats: {e}")
        import traceback
        traceback.print_exc()
        return 0

# ============================================================================
# LOAD TRAINING DATA FROM PDFs INTO CHROMA
# ============================================================================

def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """
    Split text into overlapping chunks for better context preservation.
    
    Args:
        text: Full text to chunk
        chunk_size: Characters per chunk
        overlap: Characters of overlap between chunks
    
    Returns:
        List of text chunks
    """
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start = end - overlap
    
    return chunks


def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Extract text from a PDF file.
    
    Args:
        pdf_path: Path to PDF file
    
    Returns:
        Extracted text
    """
    try:
        text = ""
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            num_pages = len(pdf_reader.pages)
            
            print(f"   📄 Reading {pdf_path} ({num_pages} pages)...")
            
            for page_num in range(num_pages):
                page = pdf_reader.pages[page_num]
                text += page.extract_text()
        
        return text
    
    except Exception as e:
        print(f"   ❌ Error reading {pdf_path}: {e}")
        return ""


def load_training_data_from_pdfs(collection_name: str = "training_data"):
    """Load and chunk PDF files from training_data directory."""
    print("\n" + "="*80)
    print("📚 Loading training data from PDFs into ChromaDB...")
    print("="*80 + "\n")
    
    # Fix: use /app/training_data (container path)
    training_dir = Path("/app/training_data")
    
    if not training_dir.exists():
        print(f"⚠️  Training directory not found: {training_dir}")
        return
    
    pdf_files = list(training_dir.glob("*.pdf"))
    
    if not pdf_files:
        print(f"⚠️  No PDF files found in {training_dir}")
        return
    
    print(f"✅ Found {len(pdf_files)} PDF files to process")
    print(f"   Files: {[f.name for f in pdf_files]}\n")
    
    # Extract text from all PDFs
    all_text = ""
    for pdf_file in pdf_files:
        text = extract_text_from_pdf(str(pdf_file))
        all_text += f"\n\n--- SOURCE: {pdf_file.name} ---\n\n" + text
    
    if not all_text.strip():
        print("❌ No text extracted from PDFs")
        return 0
    
    print(f"✅ Extracted {len(all_text)} characters from PDFs\n")
    
    # Chunk the text
    print(f"🔪 Chunking text (chunk_size=1000, overlap=200)...")
    chunks = chunk_text(all_text, chunk_size=1000, overlap=200)
    print(f"✅ Created {len(chunks)} chunks\n")
    
    # Prepare data for ChromaDB
    ids = []
    documents = []
    metadatas = []
    
    for idx, chunk in enumerate(chunks):
        chunk_id = f"training_chunk_{idx+1:06d}"
        
        # Create metadata
        metadata = {
            "source": "training_pdfs",
            "chunk_index": idx + 1,
            "total_chunks": len(chunks),
            "chunk_size": len(chunk),
            "timestamp": datetime.now().isoformat(),
            "type": "training_data"
        }
        
        ids.append(chunk_id)
        documents.append(chunk)
        metadatas.append(metadata)
    
    # Add to ChromaDB
    try:
        knowledge_col = client.get_or_create_collection("attack_mitigation_knowledge")
    
        # Add chunks to ChromaDB in batches (ChromaDB has batch size limits)
        batch_size = 100
        total_added = 0
    
        print(f"💾 Adding {len(chunks)} chunks to ChromaDB in batches...")
    
        for i in range(0, len(chunks), batch_size):
            batch_end = min(i + batch_size, len(chunks))
            batch_ids = ids[i:batch_end]
            batch_docs = documents[i:batch_end]
            batch_meta = metadatas[i:batch_end]
            
            try:
                knowledge_col.upsert(
                    ids=batch_ids,
                    documents=batch_docs,
                    metadatas=batch_meta
                )
                total_added += len(batch_ids)
                print(f"   ✅ Added batch {i//batch_size + 1}/{(len(chunks) + batch_size - 1)//batch_size} ({batch_end - i} chunks)")
            
            except Exception as e:
                print(f"   ❌ Error adding batch: {e}")
    
        print(f"\n{'='*80}")
        print(f"✅ Successfully loaded training data!")
        print(f"   • Total chunks: {total_added}")
        print(f"   • Collection: attack_mitigation_knowledge")
        print(f"   • Source: {len(pdf_files)} PDF files")
        print(f"{'='*80}\n")
    
        return total_added
    
    except Exception as e:
        print(f"❌ Error loading training data: {e}")
        return 0


def query_training_data(query: str, top_k: int = 5) -> List[dict]:
    """
    Query the training data collection.
    
    Args:
        query: Search query
        top_k: Number of results to return
    
    Returns:
        List of relevant chunks with metadata
    """
    
    knowledge_col = client.get_or_create_collection("attack_mitigation_knowledge")
    
    try:
        results = knowledge_col.query(
            query_texts=[query],
            n_results=top_k
        )
        
        formatted_results = []
        if results['documents'] and len(results['documents']) > 0:
            for doc, metadata, distance in zip(
                results['documents'][0],
                results['metadatas'][0],
                results['distances'][0]
            ):
                formatted_results.append({
                    "content": doc,
                    "metadata": metadata,
                    "relevance_score": 1 - (distance / 2)  # Convert distance to similarity
                })
        
        return formatted_results
    
    except Exception as e:
        print(f"❌ Error querying training data: {e}")
        return []


# ============================================================================
# INITIALIZE CHROMA COLLECTIONS - CALL FUNCTIONS ON MODULE LOAD
# ============================================================================

print(f"\n{'='*80}")
print(f"🔧 Initializing ChromaDB Collections...")
print(f"{'='*80}\n")

# ✅ LOAD DEMO THREATS
demo_count = load_demo_threats()

# ✅ LOAD TRAINING DATA FROM PDFs
training_count = load_training_data_from_pdfs("/training_data")

# ✅ FINAL STATUS
print(f"\n{'='*80}")
print(f"✅ ChromaDB Collections Ready!")
print(f"{'='*80}")
print(f"📊 Collections Status:")
print(f"   • suricata_rules: {suricata_col.count()} rules")
print(f"   • attack_mitigation_knowledge: {knowledge_col.count()} documents")
print(f"   • all_threats: {all_threats_col.count()} threats")
print(f"\n📥 Data Loaded:")
print(f"   • Demo threats: {demo_count}")
print(f"   • Training data chunks: {training_count}")
print(f"{'='*80}\n")
