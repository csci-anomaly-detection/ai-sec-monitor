import json
from collections import defaultdict
from datetime import datetime
import os
import chromadb
import psycopg2

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)

suricata_col = client.get_or_create_collection("suricata_rules")

def get_mitre_id(signature_id):
    result = suricata_col.get(ids=[str(signature_id)])
    if result and result['metadatas']:
        return result['metadatas'][0].get('mitre_id', 'UNKNOWN')
    return 'UNKNOWN'


def process_and_store_batches(log_file_path='ai-agent/validation_results.json'):
    """
    Process validation results, batch threats, and store in both ChromaDB and Postgres.
    Uses the new preprocessor to handle validation_results.json.
    """
    import preprocessor
    from preprocessor import preprocess_logs
    # Process validation results
    threats = preprocess_logs(log_file_path)

    # Batch by IP (or other relevant field)
    batches = {}
    all_threats_col = client.get_or_create_collection("all_threats")

    for entry in threats:
        ip = entry.get("ip", "UNKNOWN")
        batch = batches.setdefault(ip, {
            "ip": ip,
            "severity": entry.get("severity"),
            "severity_level": entry.get("severity_level"),
            "attack_type": entry.get("attack_type"),
            "total_events": entry.get("total_events"),
            "rules_violated": entry.get("rules_violated", []),
            "ml_anomalies": entry.get("ml_anomalies", []),
            "timestamps": entry.get("timestamps", []),
            "src_ips": entry.get("src_ips", []),
            "dest_ips": entry.get("dest_ips", []),
            "ports": entry.get("ports", []),
            "classification": entry.get("classification"),
            "ml_confidence_score": entry.get("ml_confidence_score"),
            "feature_analyzer_confidence_score": entry.get("feature_analyzer_confidence_score"),
            "llm_decision": entry.get("llm_decision"),
            "llm_confidence": entry.get("llm_confidence"),
            "llm_reasoning": entry.get("llm_reasoning"),
            "proceed_to_analysis": entry.get("proceed_to_analysis"),
            "validator_used": entry.get("validator_used"),
            "llm_latency_ms": entry.get("llm_latency_ms"),
            "llm_errors": entry.get("llm_errors", []),
            "alerts": []
        })
        # Add alert info (if available)
        for rule in entry.get("rules_violated", []):
            for match in rule.get("matches", []):
                batch["alerts"].append({
                    "src_ip": match.get("src_ip"),
                    "dst_ip": match.get("dest_ip"),
                    "timestamp": match.get("suricata_timestamp", match.get("timestamp")),
                    "rule_id": rule.get("rule_id"),
                    "signature": match.get("message")
                })
        # Store every threat in all_threats collection
        threat_id = f"{ip}_{entry.get('severity','')}_{entry.get('attack_type','')}"
        all_threats_col.add(
            ids=[threat_id],
            documents=[json.dumps(entry, indent=2)],
            metadatas={
                "ip": ip,
                "severity": entry.get("severity"),
                "attack_type": entry.get("attack_type"),
                "classification": entry.get("classification"),
                "llm_decision": entry.get("llm_decision")
            }
        )

    batched_alerts = list(batches.values())
    

    # Connect to Postgres
    conn = psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "alertsdb"),
        user=os.getenv("POSTGRES_USER", "myuser"),
        password=os.getenv("POSTGRES_PASSWORD", "mypassword"),
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432")
    )
    cur = conn.cursor()

    # Store batched threats in ChromaDB and Postgres
    batch_col = client.get_or_create_collection("all_threats")

    for batch in batched_alerts:
        # Store in ChromaDB for temporary processing
        batch_col.add(
            ids=[str(batch["ip"])],
            documents=[json.dumps(batch, indent=2)],
            metadatas={
                "ip": batch["ip"],
                "severity": batch.get("severity"),
                "attack_type": batch.get("attack_type"),
                "classification": batch.get("classification"),
                "llm_decision": batch.get("llm_decision"),
                "alert_count": len(batch["alerts"])
            }
        )

        # Aggregate IP information
        src_ips = {}
        dst_ips = {}
        for alert in batch["alerts"]:
            if alert.get("src_ip"):
                src_ips[alert["src_ip"]] = src_ips.get(alert["src_ip"], 0) + 1
            if alert.get("dst_ip"):
                dst_ips[alert["dst_ip"]] = dst_ips.get(alert["dst_ip"], 0) + 1

        # Get timestamp range
        first_seen = min((a["timestamp"] for a in batch["alerts"] if a.get("timestamp")), default=None)
        last_seen = max((a["timestamp"] for a in batch["alerts"] if a.get("timestamp")), default=None)

        # Store in Postgres
        cur.execute("""
            INSERT INTO threat_batches
            (ip, severity, attack_type, classification, llm_decision, alert_count, src_ips, dst_ips, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            batch["ip"],
            batch.get("severity"),
            batch.get("attack_type"),
            batch.get("classification"),
            batch.get("llm_decision"),
            len(batch["alerts"]),
            json.dumps(src_ips),
            json.dumps(dst_ips),
            first_seen,
            last_seen
        ))

    conn.commit()
    cur.close()
    conn.close()

    return batched_alerts

