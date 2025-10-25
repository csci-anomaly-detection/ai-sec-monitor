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

def process_and_store_batches(log_file_path='/app/logs/eve.json'):
    """
    Process logs, batch alerts, and store in both ChromaDB and Postgres.
    Can work with either a log file or pre-batched JSON file.
    """
    # Determine if we're processing raw logs or pre-batched data
    if log_file_path.endswith('eve.json'):
        # Process raw logs
        import preprocessor
        from preprocessor import preprocess_logs
        logs = preprocess_logs(log_file_path)
        
        # Batch the logs
        batches = {}
        all_logs_col = client.get_or_create_collection("all_logs")
        
        for entry in logs:
            # Store every log in all_logs collection
            log_id = f"{entry.get('timestamp','')}_{entry.get('src_ip','')}_{entry.get('dest_ip','')}"
            all_logs_col.add(
                ids=[log_id],
                documents=[json.dumps(entry, indent=2)],
                metadatas=[{
                    "event_type": entry.get("event_type"),
                    "signature_id": entry.get("signature_id", ""),
                    "signature": entry.get("signature", ""),
                    "src_ip": entry.get("src_ip", ""),
                    "dst_ip": entry.get("dest_ip", ""),
                    "timestamp": entry.get("timestamp", "")
                }]
            )

            if entry.get("event_type") == "alert":
                sid = str(entry.get("rule_id") or entry.get("signature_id"))
                batch = batches.setdefault(sid, {
                    "signature_id": 0,
                    "signature": "UNKNOWN",
                    "mitre_id": "UNKNOWN",
                    "alerts": []
                })
                try:
                    batch["signature_id"] = int(sid)
                except (TypeError, ValueError):
                    batch["signature_id"] = 0
                batch["signature"] = entry.get("rule_name") or entry.get("signature")
                batch["mitre_id"] = get_mitre_id(sid)
                batch["alerts"].append({
                    "src_ip": entry.get("src_ip"),
                    "dst_ip": entry.get("dest_ip"),
                    "timestamp": entry.get("timestamp")
                })
        
        batched_alerts = list(batches.values())
    else:
        # Load pre-batched data from JSON file
        with open(log_file_path, 'r') as f:
            batched_alerts = json.load(f)
    
    # Connect to Postgres
    conn = psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "alertsdb"),
        user=os.getenv("POSTGRES_USER", "myuser"),
        password=os.getenv("POSTGRES_PASSWORD", "mypassword"),
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432")
    )
    cur = conn.cursor()
    
    # Store batched alerts in ChromaDB and Postgres
    batch_col = client.get_or_create_collection("batched_alerts")
    
    for batch in batched_alerts:
        # Store in ChromaDB for temporary processing
        batch_col.add(
            ids=[str(batch["signature_id"])],
            documents=[json.dumps(batch, indent=2)],
            metadatas=[{
                "signature_id": batch["signature_id"],
                "signature": batch["signature"],
                "mitre_id": batch["mitre_id"],
                "alert_count": len(batch["alerts"])
            }]
        )
        
        # Aggregate IP information
        src_ips = {}
        dst_ips = {}
        for alert in batch["alerts"]:
            src_ips[alert["src_ip"]] = src_ips.get(alert["src_ip"], 0) + 1
            dst_ips[alert["dst_ip"]] = dst_ips.get(alert["dst_ip"], 0) + 1
        
        # Get timestamp range
        first_seen = min(a["timestamp"] for a in batch["alerts"]) if batch["alerts"] else None
        last_seen = max(a["timestamp"] for a in batch["alerts"]) if batch["alerts"] else None

        # Store in Postgres
        cur.execute("""
            INSERT INTO alert_batches
            (signature_id, signature, mitre_id, alert_count, src_ips, dst_ips, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            batch["signature_id"],
            batch["signature"],
            batch["mitre_id"],
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

