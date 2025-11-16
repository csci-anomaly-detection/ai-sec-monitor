# This file sets up chromaDB along with suricata rule, mitre attack mappings
import chromadb
import os

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)

# Create collections
suricata_col = client.get_or_create_collection("suricata_rules")
mitre_col = client.get_or_create_collection("mitre_attack")

# Example: Add Suricata rules
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

# Create a collection for attack and mitigation knowledge
knowledge_col = client.get_or_create_collection("attack_mitigation_knowledge")

# Example: Add attack and mitigation entries
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
