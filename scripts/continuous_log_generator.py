import time
import random
import json
import requests # type: ignore
import logging
import asyncio
import httpx
import os
from datetime import datetime, UTC, timezone
from typing import List, Dict, Any
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ContinuousLogGenerator:
    """
    Generates continuous attack simulation logs for testing real-time processor.
    """
    
    def __init__(self, 
                 interval_seconds: int = 30,
                 logs_per_burst: int = 50):
        """
        Initialize the continuous log generator.
        """
        self.interval_seconds = interval_seconds
        self.logs_per_burst = logs_per_burst  
        self.is_running = False
        
        # Attack patterns to simulate
        self.attack_patterns = [
            {
                'name': 'Port Scan',
                'source_ips': ['192.168.1.100', '10.0.0.50', '172.16.1.200'],
                'target_ports': [22, 80, 443, 3389, 1433, 3306],
            },
            {
                'name': 'Brute Force',
                'source_ips': ['203.0.113.10', '198.51.100.25'],
                'target_ports': [22, 3389, 21],
            },
            {
                'name': 'Web Attack',
                'source_ips': ['185.220.101.32', '45.32.105.15'],
                'target_ports': [80, 443, 8080],
            }
        ]
        
        logger.info(f"Initialized generator: {interval_seconds}s interval, {logs_per_burst} logs/burst")
    
    def generate_suricata_log(self, pattern: dict) -> dict:
        """Generate a realistic Suricata alert log that WILL trigger rules."""
        now = datetime.now(UTC)
        source_ip = random.choice(pattern['source_ips'])
        target_port = random.choice(pattern['target_ports'])
        
        alert_msg = f"Suspicious activity from {source_ip} to port {target_port}"
        signature_id = random.randint(2001, 2999)
        
        # CRITICAL FIX: Use integers for priority (not strings)
        priority_val = 1  # Always use priority 1 (highest) to trigger high_priority_alerts
        severity_val = random.randint(1, 3)
        
        timestamp_iso = now.isoformat()
        
        alert_log = {
            "timestamp": timestamp_iso,
            "@timestamp": timestamp_iso, 
            "event_type": "alert",
            "log_type": "alert",
            "src_ip": source_ip,
            "dest_ip": "10.77.0.20",  # Your honeypot IP
            "src_port": random.randint(1024, 65535),
            "dest_port": target_port,
            "proto": "TCP",
            "alert": {
                "signature_id": signature_id,
                "signature": alert_msg,
                "category": "Attempted Attack",
                "severity": severity_val,
                "priority": 1,
                "gid": 1,
                "rev": 1,
                "action": "allowed"
            },
            "status": "alert",
            "priority": "1",  # ← Add this at top level as STRING
            "gid": "1",       # ← Add this
            "sid": str(random.randint(2000, 3000)),  # ← Add this
            "severity": severity_val,   # INTEGER
            
            # Additional fields that rules might look for
            "flow": {
                "pkts_toserver": random.randint(5, 50),
                "pkts_toclient": random.randint(1, 20),
                "bytes_toserver": random.randint(500, 5000),
                "bytes_toclient": random.randint(100, 2000),
                "start": timestamp_iso
            },
            
            # App protocol detection
            "app_proto": "http" if target_port in [80, 443, 8080] else "ssh" if target_port == 22 else "tcp",
            
            # Network metadata
            "host": "suricata-honeypot",
            "in_iface": "eth0",
            
            # Classification info that rules might use
            "classification": "Attempted Attack",
            "reference": f"url,example.com/attack-{signature_id}"
        }
        
        return alert_log
    
    async def send_to_loki(self, logs: list[dict]) -> None:
        """Send generated logs to Loki"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Production server as fallback (server will use this)
                # Local dev overrides via .env (LOKI_URL=http://localhost:3100)
                base_url = os.getenv("LOKI_URL", "http://172.31.30.154:3101")
                loki_url = f"{base_url}/loki/api/v1/push"
                
                # Prepare logs in Loki format
                loki_payload = {
                    "streams": [
                        {
                            "stream": {
                                "job": "suricata",
                                "instance": "test-generator"
                            },
                            "values": []
                        }
                    ]
                }
                
                # Add each log as a timestamped entry
                for log in logs:
                    # Fix timestamp parsing - handle the timezone properly
                    timestamp_str = log['timestamp']
                    if timestamp_str.endswith('+00:00'):
                        timestamp_dt = datetime.fromisoformat(timestamp_str)
                    else:
                        timestamp_dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        
                    timestamp_ns = int(timestamp_dt.timestamp() * 1_000_000_000)
                    log_line = json.dumps(log)
                    loki_payload["streams"][0]["values"].append([str(timestamp_ns), log_line])
                
                # Send to Loki
                headers = {"Content-Type": "application/json"}
                
                response = await client.post(loki_url, json=loki_payload, headers=headers)
                
                if response.status_code == 204:
                    logger.info(f"Successfully sent {len(logs)} logs to Loki")
                else:
                    logger.error(f"Failed to send logs to Loki: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending logs to Loki: {e}")
    
    def send_logs_via_file(self, logs: List[Dict[str, Any]]):
        """
        Write logs to file for Promtail to pick up (more realistic simulation)
        """
        # Write to a file that Promtail monitors
        log_file = Path("/tmp/suricata-test/eve.json")
        log_file.parent.mkdir(exist_ok=True)
        
        with open(log_file, 'a') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
        
        logger.info(f"Wrote {len(logs)} logs to {log_file}")
    
    def generate_attack_burst(self) -> list:
        """Generate a burst of attack logs from a single source IP."""
        pattern = random.choice(self.attack_patterns)
        logs = []
        
        # Use SINGLE IP for entire attack burst (instead of random per log)
        attack_source_ip = random.choice(pattern['source_ips'])
        
        logger.info(f"Generating {self.logs_per_burst} logs for {pattern['name']} attack from {attack_source_ip}")
        
        for i in range(self.logs_per_burst):
            time.sleep(random.uniform(0.01, 0.05))  
            log = self.generate_suricata_log(pattern)
            
            # Override the source IP to be consistent for this attack
            log['src_ip'] = attack_source_ip
            
            logs.append(log)
        
        return logs
    
    def run_continuous_generation(self):
        """Main loop - generate logs continuously."""
        self.is_running = True
        attack_count = 0
        
        logger.info("Starting continuous log generation...")
        logger.info(f"Will generate attacks every {self.interval_seconds} seconds")
        
        try:
            while self.is_running:
                attack_count += 1
                
                logger.info(f"\n=== ATTACK #{attack_count} ===")
                
                # Generate attack logs
                logs = self.generate_attack_burst()
                
                # Send directly to Loki (works for real-time detection)
                asyncio.run(self.send_to_loki(logs))
                
                logger.info(f"Attack #{attack_count} completed - {len(logs)} logs generated")
                
                # Wait for next attack
                logger.info(f"Waiting {self.interval_seconds}s until next attack...")
                time.sleep(self.interval_seconds)
                
        except KeyboardInterrupt:
            logger.info("\nStopping log generation...")
        finally:
            self.is_running = False

    def generate_guaranteed_threat_attack(self, source_ip: str = "192.168.1.100") -> list:
        """Generate an attack that WILL trigger multiple rules."""
        logs = []
        pattern = self.attack_patterns[0]  # Port scan pattern
        
        logger.info(f"Generating GUARANTEED THREAT attack from {source_ip} (100 high-priority alerts)")
        
        # Generate 100 logs from same IP with priority 1 to guarantee triggers:
        # - suspicious_src_ip: 100 events >> 5 threshold ✅
        # - suricata_alert_storm: 100 alerts >> 10 threshold ✅  
        # - high_priority_alerts: 100 priority-1 alerts >> 1 threshold ✅
        
        for i in range(100):  # 100 logs = guaranteed rule triggers
            time.sleep(0.01)  # Small delay between logs
            
            log = self.generate_suricata_log(pattern)
            log['src_ip'] = source_ip        # Same IP for all logs
            log['priority'] = 1              # All highest priority
            log['alert']['priority'] = 1     # Consistent priority
            log['severity'] = 1              # Highest severity
            
            logs.append(log)
        
        return logs

    # Add this method to test guaranteed threats
    def test_guaranteed_threat(self):
        """Test method that generates one guaranteed threat."""
        logger.info("=== TESTING GUARANTEED THREAT GENERATION ===")
        
        logs = self.generate_guaranteed_threat_attack("192.168.1.100")
        success = self.send_logs_to_loki(logs)
        
        if success:
            logger.info(f"✅ Sent {len(logs)} guaranteed threat logs to Loki")
            logger.info("This SHOULD trigger multiple rules in your processor!")
        else:
            logger.error("❌ Failed to send guaranteed threat logs")


if __name__ == "__main__":
    # ENHANCED: More logs, faster attacks to guarantee rule triggers
    generator = ContinuousLogGenerator(
        interval_seconds=15,      # Faster attacks (every 15 seconds)
        logs_per_burst=60         # MORE logs per attack (was 30, now 60)
    )
    generator.run_continuous_generation()