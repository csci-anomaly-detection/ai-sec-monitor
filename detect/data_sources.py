import requests
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode
from dotenv import load_dotenv  # Add this import
import re  # Missing import for re

class LokiDataSource:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Use environment variables with fallbacks
        self.base_url = os.getenv("LOKI_URL", "http://localhost:3100")
        self.query_endpoint = os.getenv("LOKI_QUERY_ENDPOINT", f"{self.base_url}/loki/api/v1/query_range")
        self.labels_endpoint = os.getenv("LOKI_LABELS_ENDPOINT", f"{self.base_url}/loki/api/v1/labels")
        self.health_endpoint = os.getenv("LOKI_HEALTH_ENDPOINT", f"{self.base_url}/ready")
        self.timeout = 30
        
        print(f"Connecting to Loki at: {self.base_url}")
    
    def health_check(self) -> bool:
        """Check if Loki is healthy and responding"""
        try:
            print(f"Health check: {self.health_endpoint}")
            response = requests.get(self.health_endpoint, timeout=self.timeout)
            print(f"Health response: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"Loki health check failed: {e}")
            return False
    
    def get_available_labels(self) -> List[str]:
        """Get all available labels from Loki"""
        try:
            print(f"Getting labels from: {self.labels_endpoint}")
            response = requests.get(self.labels_endpoint, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                labels = data.get("data", [])
                print(f"Found {len(labels)} labels")
                return labels
            else:
                print(f"Failed to get labels: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            print(f"Error fetching labels: {e}")
            return []
    
    def query_logs(self, 
                   query: str, 
                   start_time: datetime, 
                   end_time: datetime,
                   limit: int = 5000) -> List[Dict[str, Any]]:
        """Query Loki for logs within a time range"""
        
        # FIXED QUERY: Proper escaping for Loki
        if query == '{job="suricata"}':
            # Only get alert logs, exclude stats - FIXED ESCAPING
            query = '{job="suricata"} |~ "\\\\[\\\\*\\\\*\\\\]"'  # Double escape for Loki
    
        try:
            # Format times for Loki API (RFC3339 nano)
            start_nano = int(start_time.timestamp() * 1_000_000_000)
            end_nano = int(end_time.timestamp() * 1_000_000_000)
            
            params = {
                'query': query,
                'start': start_nano,
                'end': end_nano,
                'limit': limit,
                'direction': 'forward'
            }
            
            print(f"Querying Loki: {query}")
            print(f"Time range: {start_time} to {end_time}")
            
            response = requests.get(
                self.query_endpoint,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                print(f"Loki query failed: {response.status_code} - {response.text}")
                return []
            
            data = response.json()
            return self._parse_loki_response(data)
            
        except Exception as e:
            print(f"Error querying Loki: {e}")
            return []
    
    def _parse_loki_response(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Loki API response into our log format"""
        logs = []
        
        if data.get("status") != "success":
            return []
        
        result = data.get("data", {}).get("result", [])
        
        for stream in result:
            stream_labels = stream.get("stream", {})
            
            for entry in stream.get("values", []):
                timestamp_nano, log_line = entry
                
                # Convert timestamp
                timestamp_sec = int(timestamp_nano) / 1_000_000_000
                iso_timestamp = datetime.fromtimestamp(timestamp_sec).isoformat() + "+00:00"
                
                # Parse Suricata log format
                parsed_log = self._parse_suricata_log(log_line, stream_labels)
                parsed_log["@timestamp"] = iso_timestamp
                
                logs.append(parsed_log)
        
        return logs

    def _parse_suricata_log(self, log_line: str, stream_labels: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse different types of Suricata logs"""
        
        # Handle JSON format (historical logs)
        if log_line.strip().startswith('{'):
            return self._parse_json_suricata(log_line, stream_labels)
        
        # Handle text format (current logs) - YOUR EXISTING LOGIC
        suricata_pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]\s+\[Classification:\s*(.+?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+([0-9.]+):(\d+)\s+->\s+([0-9.]+):(\d+)'
    
        alert_match = re.match(suricata_pattern, log_line)
        if alert_match:
            return self._parse_alert_log(alert_match, stream_labels)
        
        # Skip unparseable logs
        return None

    def _parse_json_suricata(self, log_line: str, stream_labels: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse JSON format Suricata logs (historical data)"""
        try:
            json_log = json.loads(log_line)
            
            # ONLY process alert events - skip stats
            if json_log.get('event_type') != 'alert':
                return None
                
            # Extract alert data
            alert_data = json_log.get('alert', {})
            
            return {
                'message': log_line,
                'suricata_timestamp': json_log.get('timestamp', ''),
                'gid': str(alert_data.get('gid', 1)),
                'sid': str(alert_data.get('signature_id', 0)), 
                'rev': '1',
                'alert_message': alert_data.get('signature', 'JSON Alert'),
                'protocol': json_log.get('proto', 'TCP'),
                'src_ip': json_log.get('src_ip', '0.0.0.0'),
                'src_port': json_log.get('src_port', 0),
                'dest_ip': json_log.get('dest_ip', '0.0.0.0'),
                'dest_port': json_log.get('dest_port', 0),
                'classification': alert_data.get('category', 'Unknown'),
                'priority': str(alert_data.get('severity', 3)),
                'service_name': 'suricata',
                'client_ip': json_log.get('src_ip', '0.0.0.0'),
                'status': 'alert',
                'method': json_log.get('proto', 'TCP'),
                'log_type': 'json',
                **stream_labels
            }
            
        except Exception:
            # Silently skip malformed JSON
            return None
    
    def _parse_alert_log(self, match, stream_labels: Dict[str, Any]) -> Dict[str, Any]:
        """Parse alert format logs"""
        
        try:
            timestamp, gid, sid, rev, alert_message, classification, priority, protocol, src_ip, src_port, dest_ip, dest_port = match.groups()
            
            return {
                'message': match.group(0),  # Full matched string
                'suricata_timestamp': timestamp,
                'gid': gid,
                'sid': sid,
                'rev': rev,
                'alert_message': alert_message,
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': int(src_port),
                'dest_ip': dest_ip,
                'dest_port': int(dest_port),
                'classification': classification,
                'priority': priority,
                'service_name': 'suricata',
                'client_ip': src_ip,
                'status': 'alert',
                'method': protocol,
                'log_type': 'fast',
                **stream_labels  # Include Loki labels like environment, filename, etc.
            }
        except Exception as e:
            print(f"Error parsing alert log: {e}")
            return self._create_fallback_log(match.group(0), stream_labels)

    def _create_fallback_log(self, log_line: str, stream_labels: Dict[str, Any]) -> Dict[str, Any]:
        """Create a fallback log entry when parsing fails"""
        return {
            'message': log_line,
            'log_type': 'unparsed',
            'src_ip': '0.0.0.0',
            'dest_port': 0,
            'priority': '4',
            'gid': '0',
            'status': 'info',
            'suricata_timestamp': datetime.now().strftime('%m/%d/%Y-%H:%M:%S.000000'),
            **stream_labels
        }
    
    def query_all_logs(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Query all Suricata logs - use specific job matcher"""
        return self.query_logs(
            query='{job="suricata"}',  # Use specific job instead of {}
            start_time=start_time,
            end_time=end_time,
            limit=5000
        )
    
    def debug_query_logs(self, 
                    query: str, 
                    start_time: datetime, 
                    end_time: datetime,
                    limit: int = 5000) -> Dict[str, Any]:
        """Debug version that shows what Loki actually has"""
    
        try:
            # Test with NO filtering first - see all data
            debug_query = '{job="suricata"}'  # No filtering
        
            start_nano = int(start_time.timestamp() * 1_000_000_000)
            end_nano = int(end_time.timestamp() * 1_000_000_000)
        
            params = {
                'query': debug_query,
                'start': start_nano,
                'end': end_nano,
                'limit': limit,
                'direction': 'forward'
            }
        
            print(f"DEBUG: Querying all logs: {debug_query}")
        
            response = requests.get(self.query_endpoint, params=params, timeout=self.timeout)
        
            if response.status_code != 200:
                return {'error': f"Query failed: {response.status_code}", 'response': response.text}
        
            data = response.json()
            result = data.get("data", {}).get("result", [])
        
            # Count different log types
            log_types = {}
            sample_logs = []
        
            for stream in result:
                for entry in stream.get("values", []):
                    timestamp_nano, log_line = entry
                
                    # Categorize log types
                    if '[**]' in log_line:
                        log_types['alerts'] = log_types.get('alerts', 0) + 1
                    elif '|' in log_line and 'Total' in log_line:
                        log_types['stats'] = log_types.get('stats', 0) + 1
                    else:
                        log_types['other'] = log_types.get('other', 0) + 1
                
                    # Keep some samples
                    if len(sample_logs) < 5:
                        sample_logs.append(log_line[:100] + "...")
        
            return {
                'total_streams': len(result),
                'log_type_counts': log_types,
                'sample_logs': sample_logs,
                'time_range': f"{start_time} to {end_time}"
            }
        
        except Exception as e:
            return {'error': str(e)}