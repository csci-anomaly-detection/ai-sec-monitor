import json
from datetime import datetime, timedelta

def load_logs(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

def parse_time(ts: str) -> datetime:
    """Handle Suricata ISO timestamps with +0000 suffix."""
    return datetime.fromisoformat(ts.replace("+0000", "+00:00"))

def preprocess_entry(entry: dict):
    etype = entry.get("event_type")

    if etype == "alert":
        return {
            "timestamp": entry["timestamp"],
            "event_type": "alert",
            "src_ip": entry.get("src_ip"),
            "src_port": entry.get("src_port"),
            "dest_ip": entry.get("dest_ip"),
            "dest_port": entry.get("dest_port"),
            "proto": entry.get("proto"),
            "rule_id": entry["alert"]["signature_id"],
            "rule_name": entry["alert"]["signature"],
            "category": entry["alert"]["category"],
            "severity": entry["alert"]["severity"]
        }

    elif etype == "flow":
        return {
            "timestamp": entry["timestamp"],
            "event_type": "flow",
            "src_ip": entry.get("src_ip"),
            "src_port": entry.get("src_port"),
            "dest_ip": entry.get("dest_ip"),
            "dest_port": entry.get("dest_port"),
            "proto": entry.get("proto"),
            "bytes_toserver": entry["flow"].get("bytes_toserver", 0),
            "bytes_toclient": entry["flow"].get("bytes_toclient", 0)
        }

    elif etype == "stats":
        return {
            "timestamp": entry["timestamp"],
            "event_type": "stats",
            "packets": entry["stats"]["decoder"].get("pkts", 0),
            "bytes": entry["stats"]["decoder"].get("bytes", 0),
            "flows_tcp": entry["stats"]["flow"].get("tcp", 0),
            "flows_udp": entry["stats"]["flow"].get("udp", 0),
            "flows_icmpv6": entry["stats"]["flow"].get("icmpv6", 0),
        }

    return None


def get_logs_in_window(all_logs: list, center_time: str, minutes: int = 15):
    ts_center = parse_time(center_time)
    window_start, window_end = ts_center - timedelta(minutes=minutes), ts_center + timedelta(minutes=minutes)

    return [
        entry for entry in all_logs
        if window_start <= parse_time(entry["timestamp"]) <= window_end
    ]


def preprocess_logs(filepath: str, alert_rule_id = None, minutes: int = 15):
    logs = load_logs(filepath)

    if alert_rule_id is not None:
        # find the first alert that matches
        target_alert = next(
            (l for l in logs if l.get("event_type") == "alert" and l["alert"]["signature_id"] == alert_rule_id),
            None
        )
        if not target_alert:
            return {"error": f"No alert found with rule_id {alert_rule_id}"}

        # time-window retrieval
        window_logs = get_logs_in_window(logs, target_alert["timestamp"], minutes=minutes)
    else:
        # if no alert_rule_id, process all logs
        window_logs = logs

    # preprocess entries
    processed = [preprocess_entry(l) for l in window_logs if preprocess_entry(l)]
    return processed
