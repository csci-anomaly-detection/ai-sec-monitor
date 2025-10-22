import asyncio
import logging
from datetime import datetime, timedelta, UTC
from collections import deque
from typing import List, Dict, Any, Optional
import json
import time
from pathlib import Path
import sys
import signal

# Ensure we can import our existing modules
sys.path.insert(0, str(Path(__file__).parents[1]))

from detect.data_sources import LokiDataSource
from detect.rule_runner import run_rules_on_live_data

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SlidingWindowProcessor:
    """
    Real-time log processor using sliding window technique.
    Continuously fetches logs and analyzes them in overlapping time windows.
    """
    
    def __init__(self, 
                 window_minutes: int = 5,
                 slide_minutes: int = 1,
                 max_logs_per_fetch: int = 5000,
                 max_buffer_minutes: int = 120):
        """
        Initialize the sliding window processor.
        
        Args:
            window_minutes: Size of analysis window in minutes
            slide_minutes: How often to slide the window (in minutes)
            max_logs_per_fetch: Maximum logs to fetch in one query
            max_buffer_minutes: Maximum time to keep logs in memory buffer
        """
        self.window_size = timedelta(minutes=window_minutes)
        self.slide_interval = timedelta(minutes=slide_minutes)
        self.max_logs_per_fetch = max_logs_per_fetch
        self.buffer_retention = timedelta(minutes=max_buffer_minutes)
        
        # Log buffer - stores logs with timestamps
        self.log_buffer = deque()
        
        # Tracking variables
        # CHANGED: Only look back 10 minutes instead of 2 hours
        self.last_fetch_time = datetime.now(UTC) - timedelta(minutes=max_buffer_minutes)
        self.is_running = False
        self.loki_source = None
        
        # Statistics
        self.stats = {
            'total_logs_processed': 0,
            'total_alerts_generated': 0,
            'windows_analyzed': 0,
            'last_window_size': 0,
            'processing_errors': 0,
            'start_time': None
        }
        
        logger.info(f"Initialized SlidingWindowProcessor: {window_minutes}min window, {slide_minutes}min slide")
    
    async def start_processing(self):
        """
        Main processing loop - runs continuously until stopped.
        """
        self.is_running = True
        self.stats['start_time'] = datetime.now(UTC)
        
        logger.info("Starting real-time sliding window processing...")
        
        # Initialize Loki connection
        self.loki_source = LokiDataSource()
        
        # Verify Loki is available
        if not self.loki_source.health_check():
            logger.error("Loki is not available - cannot start processing")
            return False
        
        try:
            while self.is_running:
                cycle_start = time.time()
                
                # Step 1: Fetch new logs since last fetch
                await self._fetch_incremental_logs()
                
                # Step 2: Clean old logs from buffer
                self._clean_buffer()
                
                # Step 3: Analyze current window
                alerts = await self._analyze_current_window()
                
                # Step 4: Handle generated alerts
                if alerts and alerts.get('correlated_threats'):
                    await self._handle_alerts(alerts)
                
                # Step 5: Update statistics
                self._update_stats()
                
                # Step 6: Sleep until next slide
                cycle_time = time.time() - cycle_start
                sleep_time = max(0, self.slide_interval.total_seconds() - cycle_time)
                
                logger.info(f"Cycle completed in {cycle_time:.2f}s, sleeping {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Processing loop error: {e}")
            self.stats['processing_errors'] += 1
        finally:
            self.is_running = False
            logger.info("Real-time processing stopped")
    
    async def _fetch_incremental_logs(self):
        """
        Fetch new logs since the last fetch time.
        """
        try:
            now = datetime.now(UTC)
            
            # DEBUG: Show what we're querying for
            time_span = (now - self.last_fetch_time).total_seconds() / 60
            logger.info(f"Fetching logs from {self.last_fetch_time.strftime('%H:%M:%S')} to {now.strftime('%H:%M:%S')} ({time_span:.1f} minutes)")
            
            # Fetch logs from last fetch time to now
            new_logs = self.loki_source.query_logs(
                query='{job="suricata"}',
                start_time=self.last_fetch_time,
                end_time=now,
                limit=self.max_logs_per_fetch
            )
            
            logger.info(f"Raw query returned {len(new_logs)} total logs")
            
            # CLEAN FILTER: Handle outbound honeypot traffic
            security_logs = [
                log for log in new_logs 
                if (log.get('log_type') in ['eve', 'fast', 'alert']  # Valid log types
                    and '10.77.0.20' in [log.get('src_ip'), log.get('dest_ip')]  # Honeypot involved
                    and log.get('dest_ip') not in ['0.0.0.0', None, '']  # Valid destination
                    and log.get('log_type') != 'stats')  # Exclude stats logs
            ]
            
            logger.info(f"After filtering: {len(security_logs)} security logs")
            
            # Add logs to buffer with metadata
            for log in security_logs:
                try:
                    timestamp_str = log.get('@timestamp', '')
                    if timestamp_str:
                        # Parse timestamp
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        self.log_buffer.append({
                            'timestamp': timestamp,
                            'data': log,
                            'processed': False
                        })
                except Exception as e:
                    logger.warning(f"Could not parse timestamp for log: {e}")
        
            # Update last fetch time
            self.last_fetch_time = now
            
            if security_logs:
                logger.info(f"Added {len(security_logs)} security logs to buffer")
            
            self.stats['total_logs_processed'] += len(security_logs)
            
        except Exception as e:
            logger.error(f"Error fetching logs: {e}")
            self.stats['processing_errors'] += 1
    
    def _clean_buffer(self):
        """
        Remove logs older than buffer retention time.
        """
        cutoff_time = datetime.now(UTC) - self.buffer_retention
        
        # Remove old logs from the left side of deque
        while (self.log_buffer and 
               self.log_buffer[0]['timestamp'] < cutoff_time):
            self.log_buffer.popleft()
    
    async def _analyze_current_window(self):
        """
        Analyze logs in the current sliding window.
        """
        try:
            now = datetime.now(UTC)
            window_start = now - self.window_size
            
            # Get logs within current window
            window_logs = [
                entry['data'] for entry in self.log_buffer
                if window_start <= entry['timestamp'] <= now
            ]
            
            self.stats['last_window_size'] = len(window_logs)
            
            # SPECIAL CASE: On first cycle with no logs in window, analyze entire buffer
            if self.stats['windows_analyzed'] == 0 and len(window_logs) == 0 and len(self.log_buffer) > 0:
                logger.info("First cycle: No logs in current window, analyzing entire buffer")
                window_logs = [entry['data'] for entry in self.log_buffer]
                
                # Show time range of buffer logs
                if self.log_buffer:
                    timestamps = [entry['timestamp'] for entry in self.log_buffer]
                    oldest = min(timestamps)
                    newest = max(timestamps)
                    logger.info(f"Buffer time range: {oldest.strftime('%H:%M:%S')} to {newest.strftime('%H:%M:%S')}")
                    logger.info(f"Analyzing {len(window_logs)} historical logs from buffer")
        
            if not window_logs:
                logger.debug("No logs in current window")
                return None
            
            logger.info(f"Analyzing window: {len(window_logs)} logs from {window_start.strftime('%H:%M:%S')} to {now.strftime('%H:%M:%S')}")
            
            # Run existing detection rules on window
            alerts = run_rules_on_live_data(window_logs, now)
            
            self.stats['windows_analyzed'] += 1
            
            # Log summary of alerts
            if alerts and alerts.get('correlated_threats'):
                threat_count = len(alerts['correlated_threats'])
                logger.info(f"Generated {threat_count} threats from window analysis")
                self.stats['total_alerts_generated'] += threat_count
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error analyzing window: {e}")
            self.stats['processing_errors'] += 1
            return None
    
    async def _handle_alerts(self, alerts):
        """
        Handle generated alerts - log them and prepare for storage.
        """
        try:
            for threat in alerts.get('correlated_threats', []):
                # Get IP (try multiple possible keys)
                ip = threat.get('ip', threat.get('source_ip', threat.get('src_ip', 'Unknown')))
                
                # Get attack details
                attack_type = threat.get('attack_type', 'Unknown')
                severity = threat.get('severity', 'UNKNOWN')
                
                # Get confidence score
                confidence = threat.get('confidence_score', 0.0)
                
                # Format confidence as percentage
                confidence_pct = confidence * 100 if confidence > 0 else 0
                
                # Log the threat detection
                logger.warning(
                    f"THREAT DETECTED: {ip} - {attack_type} "
                    f"(Severity: {severity}, Confidence: {confidence_pct:.0f}%)"
                )
        
            # TODO: In Phase 2, store alerts in database for LLM consumption
            
        except Exception as e:
            logger.error(f"Error handling alerts: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def _update_stats(self):
        """
        Update processing statistics.
        """
        uptime = datetime.now(UTC) - self.stats['start_time'] if self.stats['start_time'] else timedelta(0)
        
        # Warn if no new logs in last few cycles
        if self.stats['windows_analyzed'] > 5 and self.stats['last_window_size'] == 0:
            logger.warning(f"No security events in recent windows - honeypot may not be receiving attacks")
            logger.info(f"Tip: Run 'python scripts/continuous_log_generator.py' to generate test traffic")
        
        # Log stats every 10 windows or every cycle if no activity
        if self.stats['windows_analyzed'] % 10 == 0 or self.stats['last_window_size'] == 0:
            logger.info(f"STATS: {self.stats['windows_analyzed']} windows analyzed, "
                       f"{self.stats['total_logs_processed']} logs processed, "
                       f"{self.stats['total_alerts_generated']} alerts generated, "
                       f"uptime: {uptime}")
    
    def setup_signal_handlers(self):
        """Setup clean exit on Ctrl+C"""
        def signal_handler(signum, frame):
            if self.is_running:
                logger.info("Received interrupt signal - stopping processor...")
                self.stop_processing()
            # Don't call sys.exit() - let the main loop exit naturally
        
        signal.signal(signal.SIGINT, signal_handler)
    
    def stop_processing(self):
        """
        Stop the real-time processor.
        """
        if self.is_running:
            logger.info("Real-time processing stopped")
            self.is_running = False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current processing statistics.
        """
        stats = self.stats.copy()
        stats['buffer_size'] = len(self.log_buffer)
        stats['is_running'] = self.is_running
        stats['window_config'] = {
            'window_minutes': self.window_size.total_seconds() / 60,
            'slide_minutes': self.slide_interval.total_seconds() / 60,
            'buffer_retention_minutes': self.buffer_retention.total_seconds() / 60
        }
        return stats
    
    def get_buffer_info(self) -> Dict[str, Any]:
        """
        Get information about the current log buffer.
        """
        if not self.log_buffer:
            return {
                'buffer_size': 0,
                'time_span': None,
                'oldest_log': None,
                'newest_log': None
            }
        
        timestamps = [entry['timestamp'] for entry in self.log_buffer]
        oldest = min(timestamps)
        newest = max(timestamps)
        
        return {
            'buffer_size': len(self.log_buffer),
            'time_span_minutes': (newest - oldest).total_seconds() / 60,
            'oldest_log': oldest.isoformat(),
            'newest_log': newest.isoformat()
        }
    
    async def debug_log_fetching(self):
        """
        Debug method to test log fetching with different time ranges.
        """
        now = datetime.now(UTC)
        
        print(f"\n=== DEBUG LOG FETCHING ===")
        print(f"Current time: {now.isoformat()}")
        print(f"Last fetch time: {self.last_fetch_time.isoformat()}")
        
        # Test 1: Check if Loki has any logs at all in the last hour
        test_start = now - timedelta(hours=1)
        all_logs = self.loki_source.query_logs(
            query='{job="suricata"}',
            start_time=test_start,
            end_time=now,
            limit=500
        )
        print(f"Test 1 - Last hour logs: {len(all_logs)} total logs found")
        
        # Test 2: Check incremental fetch (what the processor is doing)
        incremental_logs = self.loki_source.query_logs(
            query='{job="suricata"}',
            start_time=self.last_fetch_time,
            end_time=now,
            limit=1000
        )
        print(f"Test 2 - Incremental logs: {len(incremental_logs)} logs since {self.last_fetch_time.strftime('%H:%M:%S')}")
        
        # Test 3: Check if we have any recent logs at all
        recent_start = now - timedelta(minutes=10)
        recent_logs = self.loki_source.query_logs(
            query='{job="suricata"}',
            start_time=recent_start,
            end_time=now,
            limit=100
        )
        print(f"Test 3 - Last 10 minutes: {len(recent_logs)} logs found")
        
        if all_logs:
            # Show timestamp range of available logs
            timestamps = [log.get('@timestamp', '') for log in all_logs if log.get('@timestamp')]
            if timestamps:
                timestamps.sort()
                print(f"Available log time range: {timestamps[0]} to {timestamps[-1]}")
                
                # Show sample IPs
                ips = list(set([log.get('src_ip', 'unknown') for log in all_logs[:10]]))
                print(f"Sample IPs in logs: {ips}")
        
        print("=== END DEBUG ===\n")
    
    def set_lookback_time(self, minutes_ago: int):
        """Set the last fetch time to look back further for testing"""
        self.last_fetch_time = datetime.now(UTC) - timedelta(minutes=minutes_ago)
        logger.info(f"Set lookback time to {minutes_ago} minutes ago: {self.last_fetch_time.isoformat()}")
    
    def test_log_availability(self):
        """
        Test if logs are available in different time ranges.
        """
        now = datetime.now(UTC)
        
        test_ranges = [
            ("last 10 minutes", now - timedelta(minutes=10)),
            ("last 30 minutes", now - timedelta(minutes=30)), 
            ("last 1 hour", now - timedelta(hours=1)),
            ("last 4 hours", now - timedelta(hours=4))
        ]
        
        print(f"\n=== LOG AVAILABILITY TEST ===")
        print(f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        for desc, start_time in test_ranges:
            try:
                logs = self.loki_source.query_logs(
                    query='{job="suricata"}',
                    start_time=start_time,
                    end_time=now,
                    limit=100
                )
                
                print(f"{desc}: {len(logs)} logs found")
                
                if logs:
                    # Show time range of actual logs
                    timestamps = [log.get('@timestamp', '') for log in logs if log.get('@timestamp')]
                    if timestamps:
                        timestamps.sort()
                        first = timestamps[0]
                        last = timestamps[-1]
                        print(f"  → Actual range: {first} to {last}")
                        
                        # Show sample IPs
                        ips = list(set([log.get('src_ip', 'none') for log in logs[:5]]))
                        print(f"  → Sample IPs: {ips}")
            
            except Exception as e:
                print(f"{desc}: ERROR - {e}")
        
        print("=== END TEST ===\n")
    
    def setup_signal_handlers(self):
        """Setup clean exit on Ctrl+C"""
        def signal_handler(signum, frame):
            if self.is_running:
                logger.info("Received interrupt signal - stopping processor...")
                self.stop_processing()
            # Don't call sys.exit() - let the main loop exit naturally
        
        signal.signal(signal.SIGINT, signal_handler)


# Main function for testing
async def main():
    """
    Test function to run the processor standalone.
    """
    processor = SlidingWindowProcessor(
        window_minutes=5,
        slide_minutes=1,
        max_logs_per_fetch=1000
    )
    
    # Setup clean exit handling
    processor.setup_signal_handlers()
    
    try:
        await processor.start_processing()
    except KeyboardInterrupt:
        logger.info("Processor stopped")
    except Exception as e:
        logger.error(f"Processor error: {e}")
    finally:
        processor.stop_processing()


if __name__ == "__main__":
    processor = SlidingWindowProcessor(
        window_minutes=5,
        slide_minutes=1,
        max_buffer_minutes=120  # Look back 2 hours on startup
    )
    
    try:
        asyncio.run(processor.start_processing())
    except KeyboardInterrupt:
        pass  # Signal handler already logged the message
    except Exception as e:
        logger.error(f"Processor crashed: {e}")
        import traceback
        logger.error(traceback.format_exc())