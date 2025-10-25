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

# Example: Add MITRE ATT&CK techniques
mitre_techniques = [
    {
        "technique_id": "T1046",
        "name": "Network Service Scanning",
        "description": "Adversaries may scan for network services to identify available services, ports, and hosts for later exploitation."
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may exploit vulnerabilities in public-facing applications to gain access to internal systems."
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands or scripts on a system."
    },
    {
        "technique_id": "T1006",
        "name": "File and Directory Discovery",
        "description": "Adversaries may enumerate files and directories to discover information about the system and its contents."
    },
    {
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "description": "Adversaries may transfer tools or files into a compromised environment to facilitate further operations."
    },
    {
        "technique_id": "T1505",
        "name": "Web Shell",
        "description": "Adversaries may deploy web shells to compromised web servers for remote access and control."
    },
    {
        "technique_id": "T1110",
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to attempt to gain access to accounts by guessing passwords."
    }
]

mitre_col.add(
    ids=[t["technique_id"] for t in mitre_techniques],
    documents=[t["description"] for t in mitre_techniques],
    metadatas=mitre_techniques
)
