from datetime import datetime, timedelta, UTC
from typing import List, Dict, Any, Optional
import os
import re
import json
import requests
from dotenv import load_dotenv

class LokiDataSource:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Use environment variables with fallbacks
        self.base_url = os.getenv("LOKI_URL", "http://localhost:3100")
        self.query_endpoint = f"{self.base_url}/loki/api/v1/query_range"
        self.labels_endpoint = f"{self.base_url}/loki/api/v1/labels"
        self.health_endpoint = f"{self.base_url}/ready"
        self.timeout = 30
        
        # Only log connection info once during initialization
        # print(f"Connecting to Loki at: {self.base_url}")
    
    def health_check(self) -> bool:
        """Check if Loki is available"""
        try:
            response = requests.get(self.health_endpoint, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def get_available_labels(self) -> List[str]:
        """Get all available labels from Loki"""
        try:
            response = requests.get(self.labels_endpoint, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                return []
        except Exception:
            return []
    
    def query_logs(self, 
                   query: str, 
                   start_time: datetime, 
                   end_time: datetime,
                   limit: int = 500) -> List[Dict[str, Any]]:
        """Query Loki for logs within a time range"""
        
        try:
            # Ensure UTC timestamps
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=UTC)
            if end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=UTC)
            
            start_utc = start_time.astimezone(UTC)
            end_utc = end_time.astimezone(UTC)
            
            # Convert to nanoseconds for Loki
            start_nano = int(start_utc.timestamp() * 1_000_000_000)
            end_nano = int(end_utc.timestamp() * 1_000_000_000)
            
            # Build query parameters
            params = {
                'query': query,
                'start': str(start_nano),
                'end': str(end_nano),
                'limit': str(limit),
                'direction': 'forward'
            }
            
            response = requests.get(self.query_endpoint, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                logs = self._parse_loki_response(data)
                return logs
            else:
                return []
                
        except Exception:
            return []

    def _parse_loki_response(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Loki API response into our log format"""
        logs = []
        
        if data.get("status") != "success":
            return []
        
        result = data.get("data", {}).get("result", [])
        
        for stream in result:
            stream_labels = stream.get("stream", {})
            values = stream.get("values", [])
            
            for entry in values:
                timestamp_ns, log_line = entry
                
                # Convert nanosecond timestamp to datetime
                timestamp_s = int(timestamp_ns) / 1_000_000_000
                log_timestamp = datetime.fromtimestamp(timestamp_s, tz=UTC)
                
                # Parse the log content
                parsed_log = self._parse_suricata_log(log_line, stream_labels)
                if parsed_log:
                    parsed_log['@timestamp'] = log_timestamp.isoformat()
                    logs.append(parsed_log)
        
        return logs

    def _parse_suricata_log(self, log_line: str, stream_labels: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse different types of Suricata logs"""
        
        # Handle JSON format
        if log_line.strip().startswith('{'):
            return self._parse_json_suricata(log_line, stream_labels)
        
        # Handle Suricata alert format
        suricata_pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+([0-9.]+):(\d+)\s+->\s+([0-9.]+):(\d+)'
        
        alert_match = re.match(suricata_pattern, log_line)
        if alert_match:
            return self._parse_alert_log(alert_match, stream_labels)
        
        # Create fallback for any unmatched logs
        return self._create_fallback_log(log_line, stream_labels)

    def _parse_json_suricata(self, log_line: str, stream_labels: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse JSON format Suricata logs"""
        try:
            log_data = json.loads(log_line)
            
            return {
                'message': log_line,
                'log_type': log_data.get('event_type', 'suricata'),
                'src_ip': log_data.get('src_ip', '0.0.0.0'),
                'dest_ip': log_data.get('dest_ip', '0.0.0.0'),
                'dest_port': log_data.get('dest_port', 0),
                'protocol': log_data.get('proto', 'unknown'),
                'priority': str(log_data.get('alert', {}).get('priority', 3)),
                'gid': str(log_data.get('alert', {}).get('gid', 0)),
                'sid': str(log_data.get('alert', {}).get('signature_id', 0)),
                'status': 'alert' if log_data.get('event_type') == 'alert' else 'info',
                'suricata_timestamp': log_data.get('timestamp', datetime.now(UTC).isoformat()),
                **stream_labels
            }
            
        except json.JSONDecodeError:
            return self._create_fallback_log(log_line, stream_labels)
    
    def _parse_alert_log(self, match, stream_labels: Dict[str, Any]) -> Dict[str, Any]:
        """Parse alert format logs"""
        try:
            return {
                'message': match.group(0),
                'log_type': 'alert',
                'suricata_timestamp': match.group(1),
                'gid': match.group(2),
                'sid': match.group(3),
                'rev': match.group(4),
                'alert_message': match.group(5),
                'classification': match.group(6),
                'priority': match.group(7),
                'protocol': match.group(8),
                'src_ip': match.group(9),
                'src_port': int(match.group(10)),
                'dest_ip': match.group(11),
                'dest_port': int(match.group(12)),
                'status': 'alert',
                **stream_labels
            }
        except (IndexError, ValueError):
            return self._create_fallback_log(match.group(0), stream_labels)

    def _create_fallback_log(self, log_line: str, stream_labels: Dict[str, Any]) -> Dict[str, Any]:
        """Create a basic log entry for unparsable logs"""
        return {
            'message': log_line,
            'log_type': 'unknown',
            'src_ip': '0.0.0.0',
            'dest_ip': '0.0.0.0',
            'priority': '3',
            'status': 'info',
            'suricata_timestamp': datetime.now(UTC).isoformat(),
            **stream_labels
        }
    
    def query_all_logs(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Query all Suricata logs without filtering"""
        return self.query_logs(
            query='{job="suricata"}',
            start_time=start_time,
            end_time=end_time,
            limit=500
        )