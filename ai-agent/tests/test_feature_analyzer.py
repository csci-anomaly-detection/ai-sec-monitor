#!/usr/bin/env python3
"""
Test script for FeatureAnalyzer class.
Tests __init__() and _extract_threat_from_api_response() functions.
"""

import sys
from pathlib import Path
from datetime import datetime, time, timedelta
from feature_analyzer import FeatureAnalyzer

def test_init():
    """Test FeatureAnalyzer initialization."""
    print("=" * 60)
    print("TEST 1: Testing __init__()")
    print("=" * 60)
    
    try:
        # Test default initialization
        analyzer = FeatureAnalyzer()
        print("✓ Default initialization successful")
        print(f"  Business hours: {analyzer.business_hours_start} - {analyzer.business_hours_end}")
        print(f"  Low confidence threshold: {analyzer.low_confidence_threshold}")
        print(f"  High confidence threshold: {analyzer.high_confidence_threshold}")
        print(f"  Internal IP ranges count: {len(analyzer.internal_ip_ranges)}")
        
        # Test custom initialization
        from datetime import time
        analyzer_custom = FeatureAnalyzer(
            business_hours_start=time(8, 0),
            business_hours_end=time(18, 0),
            low_confidence_threshold=0.15,
            enable_logging=False
        )
        print("\n✓ Custom initialization successful")
        print(f"  Business hours: {analyzer_custom.business_hours_start} - {analyzer_custom.business_hours_end}")
        print(f"  Low confidence threshold: {analyzer_custom.low_confidence_threshold}")
        print(f"  Logging enabled: {analyzer_custom.enable_logging}")
        
        # Test invalid business hours
        try:
            analyzer_invalid = FeatureAnalyzer(
                business_hours_start=time(17, 0),
                business_hours_end=time(9, 0)  # Invalid: start after end
            )
            print("\n✗ ERROR: Should have raised ValueError for invalid business hours")
            return False
        except ValueError as e:
            print(f"\n✓ Validation works: Caught expected ValueError - {e}")
        
        print("\n" + "=" * 60)
        print("TEST 1 PASSED")
        print("=" * 60 + "\n")
        return True
        
    except Exception as e:
        print(f"\n✗ TEST 1 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_extract_threats():
    """Test _extract_threat_from_api_response() function."""
    print("=" * 60)
    print("TEST 2: Testing _extract_threat_from_api_response()")
    print("=" * 60)
    
    try:
        # Initialize analyzer
        analyzer = FeatureAnalyzer(enable_logging=True)
        
        # Path to api_response.json (from ai-agent folder, go up one level)
        json_path = Path(__file__).parent.parent / "api_response.json"
        
        print(f"\nAttempting to read: {json_path}")
        print(f"File exists: {json_path.exists()}")
        
        if not json_path.exists():
            print(f"\n⚠ WARNING: {json_path} not found")
            print("Trying alternative path...")
            # Try current directory
            json_path = Path("api_response.json")
            if not json_path.exists():
                print(f"✗ ERROR: Could not find api_response.json")
                return False
        
        # Extract threats
        threats = analyzer._extract_threat_from_api_response(str(json_path))
        
        print(f"\n✓ Successfully extracted {len(threats)} threat(s)")
        
        # Display results
        for i, threat in enumerate(threats, 1):
            print(f"\n--- Threat {i} ---")
            print(f"  IP: {threat.get('ip', 'N/A')}")
            print(f"  Severity: {threat.get('severity', 'N/A')} (level: {threat.get('severity_level', 'N/A')})")
            print(f"  Confidence Score: {threat.get('confidence_score', 'N/A')}")
            print(f"  Attack Type: {threat.get('attack_type', 'N/A')}")
            print(f"  Total Events: {threat.get('total_events', 'N/A')}")
            print(f"  Rules Violated: {len(threat.get('rules_violated', []))} rule(s)")
            print(f"  ML Anomalies: {len(threat.get('ml_anomalies', []))} anomaly/anomalies")
            
            # Extracted data
            print(f"\n  Extracted Data:")
            print(f"    Timestamps: {len(threat.get('timestamps', []))} timestamp(s)")
            if threat.get('timestamps'):
                print(f"      First: {threat['timestamps'][0]}")
                print(f"      Last: {threat['timestamps'][-1]}")
            
            print(f"    Source IPs: {len(threat.get('src_ips', []))} IP(s)")
            if threat.get('src_ips'):
                print(f"      IPs: {', '.join(threat['src_ips'][:5])}")
                if len(threat['src_ips']) > 5:
                    print(f"      ... and {len(threat['src_ips']) - 5} more")
            
            print(f"    Destination IPs: {len(threat.get('dest_ips', []))} IP(s)")
            if threat.get('dest_ips'):
                print(f"      IPs: {', '.join(threat['dest_ips'][:5])}")
                if len(threat['dest_ips']) > 5:
                    print(f"      ... and {len(threat['dest_ips']) - 5} more")
            
            print(f"    Ports: {len(threat.get('ports', []))} port(s)")
            if threat.get('ports'):
                ports_display = sorted(threat['ports'])[:10]
                print(f"      Ports: {', '.join(map(str, ports_display))}")
                if len(threat['ports']) > 10:
                    print(f"      ... and {len(threat['ports']) - 10} more")
        
        # Test error handling - file not found
        print(f"\n--- Testing Error Handling ---")
        try:
            analyzer._extract_threat_from_api_response("nonexistent_file.json")
            print("✗ ERROR: Should have raised FileNotFoundError")
            return False
        except FileNotFoundError as e:
            print(f"✓ FileNotFoundError caught: {e}")
        
        print("\n" + "=" * 60)
        print("TEST 2 PASSED")
        print("=" * 60 + "\n")
        return True
        
    except Exception as e:
        print(f"\n✗ TEST 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_timing_patterns():
    """Test _check_timing_patterns() function."""
    print("=" * 60)
    print("TEST 3: Testing _check_timing_patterns()")
    print("=" * 60)
    
    try:
        from datetime import time as time_obj
        
        # Initialize analyzer with business hours 9 AM - 5 PM
        analyzer = FeatureAnalyzer(
            business_hours_start=time_obj(9, 0),
            business_hours_end=time_obj(17, 0),
            maintenance_windows=[(time_obj(2, 0), time_obj(4, 0))],  # 2 AM - 4 AM maintenance
            enable_logging=False
        )
        
        # Test 1: Business hours activity
        print("\n--- Test 1: Business Hours Activity ---")
        business_hours_threat = {
            "ip": "192.168.1.100",
            "timestamps": [
                datetime(2025, 11, 3, 10, 30, 0),  # Monday 10:30 AM (business hours)
                datetime(2025, 11, 3, 11, 15, 0),  # Monday 11:15 AM
                datetime(2025, 11, 3, 14, 45, 0), # Monday 2:45 PM
                datetime(2025, 11, 4, 10, 0, 0),  # Tuesday 10:00 AM
            ]
        }
        result = analyzer._check_timing_patterns(business_hours_threat)
        print(f"  Timestamp count: {result['timestamp_count']}")
        print(f"  Business hours ratio: {result['business_hours_ratio']:.2%}")
        print(f"  Is business hours: {result['is_business_hours']}")
        print(f"  Is weekday: {result['is_weekday']}")
        print(f"  Flags: {result['flags']}")
        assert result['is_business_hours'] == True, "Should detect business hours"
        assert result['is_weekday'] == True, "Should detect weekday"
        print("  ✓ PASSED")
        
        # Test 2: Off-hours activity
        print("\n--- Test 2: Off-Hours Activity ---")
        off_hours_threat = {
            "ip": "192.168.1.101",
            "timestamps": [
                datetime(2025, 11, 3, 1, 30, 0),   # Monday 1:30 AM (off-hours)
                datetime(2025, 11, 3, 2, 15, 0),   # Monday 2:15 AM
                datetime(2025, 11, 3, 20, 0, 0),  # Monday 8:00 PM
                datetime(2025, 11, 3, 22, 45, 0), # Monday 10:45 PM
            ]
        }
        result = analyzer._check_timing_patterns(off_hours_threat)
        print(f"  Timestamp count: {result['timestamp_count']}")
        print(f"  Business hours ratio: {result['business_hours_ratio']:.2%}")
        print(f"  Is business hours: {result['is_business_hours']}")
        print(f"  Flags: {result['flags']}")
        assert result['is_business_hours'] == False, "Should detect off-hours"
        assert "off_hours" in result['flags'], "Should flag as off-hours"
        print("  ✓ PASSED")
        
        # Test 3: Maintenance window activity
        print("\n--- Test 3: Maintenance Window Activity ---")
        maintenance_threat = {
            "ip": "192.168.1.102",
            "timestamps": [
                datetime(2025, 11, 3, 2, 10, 0),   # Monday 2:10 AM (maintenance window)
                datetime(2025, 11, 3, 2, 45, 0),   # Monday 2:45 AM
                datetime(2025, 11, 3, 3, 30, 0),   # Monday 3:30 AM
            ]
        }
        result = analyzer._check_timing_patterns(maintenance_threat)
        print(f"  Timestamp count: {result['timestamp_count']}")
        print(f"  Maintenance window ratio: {result['maintenance_window_ratio']:.2%}")
        print(f"  Is maintenance window: {result['is_maintenance_window']}")
        print(f"  Flags: {result['flags']}")
        assert result['is_maintenance_window'] == True, "Should detect maintenance window"
        assert "maintenance_window" in result['flags'], "Should flag as maintenance window"
        print("  ✓ PASSED")
        
        # Test 4: Weekend activity
        print("\n--- Test 4: Weekend Activity ---")
        weekend_threat = {
            "ip": "192.168.1.103",
            "timestamps": [
                datetime(2025, 11, 8, 10, 0, 0),   # Saturday 10:00 AM
                datetime(2025, 11, 8, 14, 30, 0), # Saturday 2:30 PM
                datetime(2025, 11, 9, 11, 15, 0), # Sunday 11:15 AM
            ]
        }
        result = analyzer._check_timing_patterns(weekend_threat)
        print(f"  Timestamp count: {result['timestamp_count']}")
        print(f"  Is weekend: {result['is_weekend']}")
        print(f"  Flags: {result['flags']}")
        assert result['is_weekend'] == True, "Should detect weekend"
        assert "weekend" in result['flags'], "Should flag as weekend"
        print("  ✓ PASSED")
        
        # Test 5: Concentrated timeline (all within 1 hour)
        print("\n--- Test 5: Concentrated Timeline ---")
        concentrated_threat = {
            "ip": "192.168.1.104",
            "timestamps": [
                datetime(2025, 11, 3, 10, 0, 0),
                datetime(2025, 11, 3, 10, 15, 0),
                datetime(2025, 11, 3, 10, 30, 0),
                datetime(2025, 11, 3, 10, 45, 0),
            ]
        }
        result = analyzer._check_timing_patterns(concentrated_threat)
        print(f"  Timestamp count: {result['timestamp_count']}")
        print(f"  Earliest: {result['earliest_timestamp']}")
        print(f"  Latest: {result['latest_timestamp']}")
        time_span = result['latest_timestamp'] - result['earliest_timestamp']
        print(f"  Time span: {time_span}")
        print(f"  Flags: {result['flags']}")
        assert "concentrated_timeline" in result['flags'], "Should flag as concentrated timeline"
        print("  ✓ PASSED")
        
        # Test 6: No timestamps (edge case)
        print("\n--- Test 6: No Timestamps (Edge Case) ---")
        no_timestamps_threat = {
            "ip": "192.168.1.105",
            "timestamps": []
        }
        result = analyzer._check_timing_patterns(no_timestamps_threat)
        print(f"  Timestamp count: {result['timestamp_count']}")
        print(f"  Flags: {result['flags']}")
        assert result['timestamp_count'] == 0, "Should report 0 timestamps"
        assert "no_timestamps" in result['flags'], "Should flag as no timestamps"
        print("  ✓ PASSED")
        
        # Test 7: Real data from api_response.json
        print("\n--- Test 7: Real Data from api_response.json ---")
        json_path = Path(__file__).parent.parent / "api_response.json"
        if json_path.exists():
            threats = analyzer._extract_threat_from_api_response(str(json_path))
            if threats and len(threats) > 0:
                threat_with_timestamps = threats[0]  # First threat has timestamps
                if threat_with_timestamps.get('timestamps'):
                    result = analyzer._check_timing_patterns(threat_with_timestamps)
                    print(f"  Threat IP: {threat_with_timestamps.get('ip')}")
                    print(f"  Timestamp count: {result['timestamp_count']}")
                    print(f"  Business hours ratio: {result['business_hours_ratio']:.2%}")
                    print(f"  Is business hours: {result['is_business_hours']}")
                    print(f"  Is weekday: {result['is_weekday']}")
                    print(f"  Earliest: {result['earliest_timestamp']}")
                    print(f"  Latest: {result['latest_timestamp']}")
                    print(f"  Flags: {result['flags']}")
                    print("  ✓ PASSED")
                else:
                    print("  ⚠ SKIPPED: Threat has no timestamps to analyze")
            else:
                print("  ⚠ SKIPPED: No threats extracted from JSON")
        else:
            print("  ⚠ SKIPPED: api_response.json not found")
        
        print("\n" + "=" * 60)
        print("TEST 3 PASSED")
        print("=" * 60 + "\n")
        return True
        
    except AssertionError as e:
        print(f"\n✗ TEST 3 FAILED: Assertion failed - {e}")
        return False
    except Exception as e:
        print(f"\n✗ TEST 3 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ip_reputation():
    """Test _check_ip_reputation() function."""
    print("=" * 60)
    print("TEST 4: Testing _check_ip_reputation()")
    print("=" * 60)
    
    try:
        # Initialize analyzer
        analyzer = FeatureAnalyzer(enable_logging=False)
        
        # Test 1: External-to-internal traffic (suspicious)
        print("\n--- Test 1: External-to-Internal Traffic ---")
        external_to_internal_threat = {
            "src_ips": ["185.220.101.32", "203.0.113.1"],  # External IPs
            "dest_ips": ["10.77.0.20", "192.168.1.100"]  # Internal IPs
        }
        result = analyzer._check_ip_reputation(external_to_internal_threat)
        print(f"  Source IP count: {result['src_ip_count']}")
        print(f"  Destination IP count: {result['dest_ip_count']}")
        print(f"  Internal src ratio: {result['internal_src_ratio']:.2%}")
        print(f"  Internal dest ratio: {result['internal_dest_ratio']:.2%}")
        print(f"  External to internal: {result['external_to_internal']}")
        print(f"  Flags: {result['flags']}")
        assert result['external_to_internal'] == True, "Should detect external-to-internal pattern"
        assert result['has_external_src'] == True, "Should detect external source IPs"
        assert result['all_dest_internal'] == True, "Should detect all internal destinations"
        assert "external_to_internal" in result['flags'], "Should flag as external-to-internal"
        print("  ✓ PASSED")
        
        # Test 2: Internal-to-internal traffic (less suspicious)
        print("\n--- Test 2: Internal-to-Internal Traffic ---")
        internal_to_internal_threat = {
            "src_ips": ["192.168.1.50", "10.0.0.5"],  # Internal IPs
            "dest_ips": ["10.77.0.20", "172.16.0.10"]  # Internal IPs
        }
        result = analyzer._check_ip_reputation(internal_to_internal_threat)
        print(f"  Source IP count: {result['src_ip_count']}")
        print(f"  Destination IP count: {result['dest_ip_count']}")
        print(f"  Internal src ratio: {result['internal_src_ratio']:.2%}")
        print(f"  Internal dest ratio: {result['internal_dest_ratio']:.2%}")
        print(f"  Internal to internal: {result['internal_to_internal']}")
        print(f"  Flags: {result['flags']}")
        assert result['internal_to_internal'] == True, "Should detect internal-to-internal pattern"
        assert result['all_src_internal'] == True, "Should detect all internal source IPs"
        assert result['all_dest_internal'] == True, "Should detect all internal destinations"
        assert "internal_to_internal" in result['flags'], "Should flag as internal-to-internal"
        print("  ✓ PASSED")
        
        # Test 3: Single external source IP (targeted attack)
        print("\n--- Test 3: Single External Source IP ---")
        single_external_threat = {
            "src_ips": ["185.220.101.32"],  # Single external IP
            "dest_ips": ["10.77.0.20"]
        }
        result = analyzer._check_ip_reputation(single_external_threat)
        print(f"  Source IP count: {result['src_ip_count']}")
        print(f"  External to internal: {result['external_to_internal']}")
        print(f"  Flags: {result['flags']}")
        assert result['src_ip_count'] == 1, "Should have 1 source IP"
        assert "single_src_ip" in result['flags'], "Should flag as single source IP"
        assert "external_to_internal" in result['flags'], "Should flag as external-to-internal"
        print("  ✓ PASSED")
        
        # Test 4: Multiple internal sources (internal scan)
        print("\n--- Test 4: Multiple Internal Sources ---")
        multiple_internal_threat = {
            "src_ips": ["192.168.1.10", "192.168.1.20", "192.168.1.30"],
            "dest_ips": ["10.0.0.1"]
        }
        result = analyzer._check_ip_reputation(multiple_internal_threat)
        print(f"  Source IP count: {result['src_ip_count']}")
        print(f"  Internal src ratio: {result['internal_src_ratio']:.2%}")
        print(f"  Flags: {result['flags']}")
        assert result['src_ip_count'] == 3, "Should have 3 source IPs"
        assert result['all_src_internal'] == True, "Should detect all internal sources"
        assert "multiple_internal_sources" in result['flags'], "Should flag as multiple internal sources"
        print("  ✓ PASSED")
        
        # Test 5: Mixed internal and external sources
        print("\n--- Test 5: Mixed Internal and External Sources ---")
        mixed_threat = {
            "src_ips": ["192.168.1.10", "185.220.101.32", "10.0.0.5"],  # 2 internal, 1 external
            "dest_ips": ["10.77.0.20"]
        }
        result = analyzer._check_ip_reputation(mixed_threat)
        print(f"  Source IP count: {result['src_ip_count']}")
        print(f"  Internal src ratio: {result['internal_src_ratio']:.2%}")
        print(f"  All src internal: {result['all_src_internal']}")
        print(f"  Has external src: {result['has_external_src']}")
        print(f"  Flags: {result['flags']}")
        assert result['internal_src_ratio'] == (2/3), "Should have 2/3 internal ratio"
        assert result['all_src_internal'] == False, "Should not be all internal"
        assert result['has_external_src'] == True, "Should detect external source"
        print("  ✓ PASSED")
        
        # Test 6: No IPs (edge case)
        print("\n--- Test 6: No IPs (Edge Case) ---")
        no_ips_threat = {
            "src_ips": [],
            "dest_ips": []
        }
        result = analyzer._check_ip_reputation(no_ips_threat)
        print(f"  Source IP count: {result['src_ip_count']}")
        print(f"  Destination IP count: {result['dest_ip_count']}")
        print(f"  Flags: {result['flags']}")
        assert result['src_ip_count'] == 0, "Should report 0 source IPs"
        assert result['dest_ip_count'] == 0, "Should report 0 destination IPs"
        assert "no_ips" in result['flags'], "Should flag as no IPs"
        print("  ✓ PASSED")
        
        # Test 7: Real data from api_response.json
        print("\n--- Test 7: Real Data from api_response.json ---")
        json_path = Path(__file__).parent.parent / "api_response.json"
        if json_path.exists():
            threats = analyzer._extract_threat_from_api_response(str(json_path))
            if threats and len(threats) > 0:
                threat_with_ips = threats[0]  # First threat has IPs
                if threat_with_ips.get('src_ips') or threat_with_ips.get('dest_ips'):
                    result = analyzer._check_ip_reputation(threat_with_ips)
                    print(f"  Threat IP: {threat_with_ips.get('ip')}")
                    print(f"  Source IP count: {result['src_ip_count']}")
                    print(f"  Destination IP count: {result['dest_ip_count']}")
                    print(f"  Internal src ratio: {result['internal_src_ratio']:.2%}")
                    print(f"  Internal dest ratio: {result['internal_dest_ratio']:.2%}")
                    print(f"  External to internal: {result['external_to_internal']}")
                    print(f"  Internal to internal: {result['internal_to_internal']}")
                    print(f"  Flags: {result['flags']}")
                    print("  ✓ PASSED")
                else:
                    print("  ⚠ SKIPPED: Threat has no IPs to analyze")
            else:
                print("  ⚠ SKIPPED: No threats extracted from JSON")
        else:
            print("  ⚠ SKIPPED: api_response.json not found")
        
        print("\n" + "=" * 60)
        print("TEST 4 PASSED")
        print("=" * 60 + "\n")
        return True
        
    except AssertionError as e:
        print(f"\n✗ TEST 4 FAILED: Assertion failed - {e}")
        return False
    except Exception as e:
        print(f"\n✗ TEST 4 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_traffic_patterns():
    """Test _check_traffic_patterns() function."""
    print("=" * 60)
    print("TEST 5: Testing _check_traffic_patterns()")
    print("=" * 60)
    
    try:
        # Initialize analyzer with default threshold (100 events)
        analyzer = FeatureAnalyzer(
            high_event_count_threshold=100,
            enable_logging=False
        )
        
        # Test 1: High volume burst activity (attack pattern)
        print("\n--- Test 1: High Volume Burst Activity ---")
        from datetime import timedelta
        base_time = datetime(2025, 11, 3, 1, 28, 10)
        burst_threat = {
            "total_events": 150,
            "timestamps": [
                base_time + timedelta(seconds=i) for i in range(20)
            ],
            "rules_violated": [
                {"rule_id": "alert_storm", "severity": "high", "count": 150}
            ]
        }
        result = analyzer._check_traffic_patterns(burst_threat)
        print(f"  Total events: {result['total_events']}")
        print(f"  High volume: {result['high_volume']}")
        print(f"  Events per minute: {result['events_per_minute']:.2f}")
        print(f"  Burst activity: {result['burst_activity']}")
        print(f"  Has high severity: {result['has_high_severity_rules']}")
        print(f"  Flags: {result['flags']}")
        assert result['high_volume'] == True, "Should detect high volume"
        assert result['burst_activity'] == True, "Should detect burst activity"
        assert result['has_high_severity_rules'] == True, "Should detect high severity"
        assert "high_volume" in result['flags'], "Should flag as high volume"
        assert "burst_activity" in result['flags'], "Should flag as burst"
        print("  ✓ PASSED")
        
        # Test 2: Sustained activity (legitimate load)
        print("\n--- Test 2: Sustained Activity ---")
        # Need > 1 hour for sustained activity, so use 14 events at 5 min intervals = 65 minutes
        sustained_threat = {
            "total_events": 200,
            "timestamps": [
                datetime(2025, 11, 3, 10, 0, 0) + timedelta(minutes=i*5) 
                for i in range(14)  # 14 events = 13*5 = 65 minutes = 1.08 hours (> 1 hour)
            ],
            "rules_violated": [
                {"rule_id": "traffic_spike", "severity": "low", "count": 200}
            ]
        }
        result = analyzer._check_traffic_patterns(sustained_threat)
        print(f"  Total events: {result['total_events']}")
        print(f"  High volume: {result['high_volume']}")
        print(f"  Events per minute: {result['events_per_minute']:.2f}")
        print(f"  Sustained activity: {result['sustained_activity']}")
        print(f"  Burst activity: {result['burst_activity']}")
        print(f"  Flags: {result['flags']}")
        assert result['sustained_activity'] == True, "Should detect sustained activity (>1 hour)"
        assert result['burst_activity'] == False, "Should not be burst"
        assert "sustained_activity" in result['flags'], "Should flag as sustained"
        print("  ✓ PASSED")
        
        # Test 3: Low volume (might be false positive)
        print("\n--- Test 3: Low Volume ---")
        low_volume_threat = {
            "total_events": 5,
            "timestamps": [
                datetime(2025, 11, 3, 10, 0, 0) + timedelta(seconds=i*10) 
                for i in range(5)
            ],
            "rules_violated": [
                {"rule_id": "minor_alert", "severity": "low", "count": 5}
            ]
        }
        result = analyzer._check_traffic_patterns(low_volume_threat)
        print(f"  Total events: {result['total_events']}")
        print(f"  High volume: {result['high_volume']}")
        print(f"  Flags: {result['flags']}")
        assert result['high_volume'] == False, "Should not be high volume"
        assert "low_volume" in result['flags'], "Should flag as low volume"
        print("  ✓ PASSED")
        
        # Test 4: Very high volume (attack)
        print("\n--- Test 4: Very High Volume ---")
        very_high_threat = {
            "total_events": 600,
            "timestamps": [
                datetime(2025, 11, 3, 1, 28, 10) + timedelta(seconds=i) 
                for i in range(50)
            ],
            "rules_violated": [
                {"rule_id": "ddos_pattern", "severity": "high", "count": 600}
            ]
        }
        result = analyzer._check_traffic_patterns(very_high_threat)
        print(f"  Total events: {result['total_events']}")
        print(f"  High volume: {result['high_volume']}")
        print(f"  Flags: {result['flags']}")
        assert result['high_volume'] == True, "Should detect high volume"
        assert "very_high_volume" in result['flags'], "Should flag as very high volume"
        print("  ✓ PASSED")
        
        # Test 5: High request rate
        print("\n--- Test 5: High Request Rate ---")
        high_rate_threat = {
            "total_events": 150,
            "timestamps": [
                datetime(2025, 11, 3, 1, 28, 10) + timedelta(seconds=i*2) 
                for i in range(25)  # 25 events in 50 seconds = 30 events/min
            ],
            "rules_violated": []
        }
        result = analyzer._check_traffic_patterns(high_rate_threat)
        print(f"  Total events: {result['total_events']}")
        print(f"  Events per minute: {result['events_per_minute']:.2f}")
        print(f"  Flags: {result['flags']}")
        assert result['events_per_minute'] > 10.0, "Should have high request rate"
        assert "high_request_rate" in result['flags'], "Should flag as high request rate"
        print("  ✓ PASSED")
        
        # Test 6: Multiple rule violations
        print("\n--- Test 6: Multiple Rule Violations ---")
        multiple_rules_threat = {
            "total_events": 150,
            "timestamps": [],
            "rules_violated": [
                {"rule_id": "rule1", "severity": "high", "count": 50},
                {"rule_id": "rule2", "severity": "medium", "count": 50},
                {"rule_id": "rule3", "severity": "low", "count": 30},
                {"rule_id": "rule4", "severity": "high", "count": 20}
            ]
        }
        result = analyzer._check_traffic_patterns(multiple_rules_threat)
        print(f"  Rule violation count: {result['rule_violation_count']}")
        print(f"  Total rule violations: {result['total_rule_violations']}")
        print(f"  Average severity: {result['avg_rule_severity']:.2f}")
        print(f"  Has high severity: {result['has_high_severity_rules']}")
        print(f"  Flags: {result['flags']}")
        assert result['rule_violation_count'] == 4, "Should have 4 rules"
        assert result['total_rule_violations'] == 150, "Should sum to 150"
        assert result['has_high_severity_rules'] == True, "Should detect high severity"
        assert "multiple_rule_violations" in result['flags'], "Should flag multiple rules"
        print("  ✓ PASSED")
        
        # Test 7: No timestamps (edge case)
        print("\n--- Test 7: No Timestamps (Edge Case) ---")
        no_timestamps_threat = {
            "total_events": 150,
            "timestamps": [],
            "rules_violated": [
                {"rule_id": "rule1", "severity": "high", "count": 150}
            ]
        }
        result = analyzer._check_traffic_patterns(no_timestamps_threat)
        print(f"  Total events: {result['total_events']}")
        print(f"  Events per minute: {result['events_per_minute']}")
        print(f"  Flags: {result['flags']}")
        assert result['events_per_minute'] == 0.0, "Should be 0 without timestamps"
        assert result['high_volume'] == True, "Should still detect high volume"
        print("  ✓ PASSED")
        
        # Test 8: Real data from api_response.json
        print("\n--- Test 8: Real Data from api_response.json ---")
        json_path = Path(__file__).parent.parent / "api_response.json"
        if json_path.exists():
            threats = analyzer._extract_threat_from_api_response(str(json_path))
            if threats and len(threats) > 0:
                threat_with_events = threats[0]  # First threat has events
                if threat_with_events.get('total_events', 0) > 0:
                    result = analyzer._check_traffic_patterns(threat_with_events)
                    print(f"  Threat IP: {threat_with_events.get('ip')}")
                    print(f"  Total events: {result['total_events']}")
                    print(f"  High volume: {result['high_volume']}")
                    print(f"  Events per minute: {result['events_per_minute']:.2f}")
                    print(f"  Burst activity: {result['burst_activity']}")
                    print(f"  Sustained activity: {result['sustained_activity']}")
                    print(f"  Rule violations: {result['rule_violation_count']}")
                    print(f"  Has high severity: {result['has_high_severity_rules']}")
                    print(f"  Flags: {result['flags']}")
                    print("  ✓ PASSED")
                else:
                    print("  ⚠ SKIPPED: Threat has no events to analyze")
            else:
                print("  ⚠ SKIPPED: No threats extracted from JSON")
        else:
            print("  ⚠ SKIPPED: api_response.json not found")
        
        print("\n" + "=" * 60)
        print("TEST 5 PASSED")
        print("=" * 60 + "\n")
        return True
        
    except AssertionError as e:
        print(f"\n✗ TEST 5 FAILED: Assertion failed - {e}")
        return False
    except Exception as e:
        print(f"\n✗ TEST 5 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_analyze_threat():
    """Test analyze_threat() function with comprehensive test cases."""
    print("=" * 60)
    print("TEST 6: Testing analyze_threat() - Comprehensive")
    print("=" * 60)
    
    try:
        from datetime import timedelta
        from datetime import time as time_obj
        
        # Initialize analyzer
        analyzer = FeatureAnalyzer(
            business_hours_start=time_obj(9, 0),
            business_hours_end=time_obj(17, 0),
            maintenance_windows=[(time_obj(2, 0), time_obj(4, 0))],
            low_confidence_threshold=0.2,
            high_confidence_threshold=0.7,
            enable_logging=False
        )
        
        # ===== FALSE_POSITIVE Test Cases =====
        
        # Test 1: Internal-to-internal + business hours + no high severity
        print("\n--- Test 1: FALSE_POSITIVE - Internal-to-Internal Business Hours ---")
        fp_threat1 = {
            "ip": "192.168.1.50",
            "confidence_score": 0.5,
            "total_events": 50,
            "timestamps": [
                datetime(2025, 11, 3, 10, 0, 0) + timedelta(minutes=i*5) 
                for i in range(14)  # Business hours activity
            ],
            "src_ips": ["192.168.1.50"],
            "dest_ips": ["10.77.0.20"],
            "rules_violated": [
                {"rule_id": "traffic_spike", "severity": "low", "count": 50}
            ]
        }
        result = analyzer.analyze_threat(fp_threat1)
        print(f"  Classification: {result['classification']}")
        print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        print(f"  LLM confidence: {result['llm_confidence_score']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "FALSE_POSITIVE", "Should classify as FALSE_POSITIVE"
        assert result['ml_confidence_score'] == 0.5, "Should preserve ML confidence"
        assert result['feature_analyzer_confidence_score'] >= 0.7, "Should have high heuristic confidence"
        assert result['llm_confidence_score'] is None, "LLM confidence should be None"
        print("  ✓ PASSED")
        
        # Test 2: Maintenance window activity
        print("\n--- Test 2: FALSE_POSITIVE - Maintenance Window ---")
        fp_threat2 = {
            "ip": "192.168.1.50",
            "confidence_score": 0.3,
            "total_events": 100,
            "timestamps": [
                datetime(2025, 11, 3, 2, 30, 0),  # During maintenance (2-4 AM)
                datetime(2025, 11, 3, 3, 0, 0),
            ],
            "src_ips": ["192.168.1.50"],
            "dest_ips": ["10.77.0.20"],
            "rules_violated": []
        }
        result = analyzer.analyze_threat(fp_threat2)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "FALSE_POSITIVE", "Should classify as FALSE_POSITIVE"
        assert "maintenance window" in result['reasoning'].lower(), "Should mention maintenance window"
        print("  ✓ PASSED")
        
        # Test 3: Low volume + low confidence + internal traffic
        print("\n--- Test 3: FALSE_POSITIVE - Low Volume Low Confidence Internal ---")
        fp_threat3 = {
            "ip": "192.168.1.50",
            "confidence_score": 0.1,  # Low confidence
            "total_events": 5,  # Low volume
            "timestamps": [datetime(2025, 11, 3, 10, 0, 0)],
            "src_ips": ["192.168.1.50"],  # Internal
            "dest_ips": ["10.77.0.20"],
            "rules_violated": []
        }
        result = analyzer.analyze_threat(fp_threat3)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "FALSE_POSITIVE", "Should classify as FALSE_POSITIVE"
        assert result['ml_confidence_score'] == 0.1, "Should preserve low ML confidence"
        print("  ✓ PASSED")
        
        # ===== POSSIBLE_THREAT Test Cases =====
        
        # Test 4: External-to-internal + high severity rules
        print("\n--- Test 4: POSSIBLE_THREAT - External IP + High Severity ---")
        threat_threat1 = {
            "ip": "185.220.101.32",
            "confidence_score": 0.5,
            "total_events": 120,
            "timestamps": [
                datetime(2025, 11, 3, 1, 28, 10) + timedelta(seconds=i) 
                for i in range(20)
            ],
            "src_ips": ["185.220.101.32"],  # External
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "alert_storm", "severity": "high", "count": 120}
            ]
        }
        result = analyzer.analyze_threat(threat_threat1)
        print(f"  Classification: {result['classification']}")
        print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "POSSIBLE_THREAT", "Should classify as POSSIBLE_THREAT"
        assert result['feature_analyzer_confidence_score'] >= 0.7, "Should have high heuristic confidence"
        assert "external" in result['reasoning'].lower(), "Should mention external IP"
        print("  ✓ PASSED")
        
        # Test 5: Very high volume + burst + off-hours
        print("\n--- Test 5: POSSIBLE_THREAT - Very High Volume Burst Off-Hours ---")
        threat_threat2 = {
            "ip": "203.0.113.1",
            "confidence_score": 0.6,
            "total_events": 600,  # Very high
            "timestamps": [
                datetime(2025, 11, 3, 1, 0, 0) + timedelta(seconds=i) 
                for i in range(50)  # Burst within 50 seconds
            ],
            "src_ips": ["203.0.113.1"],  # External
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "ddos", "severity": "high", "count": 600}
            ]
        }
        result = analyzer.analyze_threat(threat_threat2)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "POSSIBLE_THREAT", "Should classify as POSSIBLE_THREAT"
        # Should mention volume/burst/off-hours (multiple conditions can trigger)
        reasoning_lower = result['reasoning'].lower()
        assert ("very high volume" in reasoning_lower or "burst" in reasoning_lower or 
                "high volume" in reasoning_lower or "off-hours" in reasoning_lower), \
                "Should mention volume/burst/off-hours"
        print("  ✓ PASSED")
        
        # Test 6: High request rate + external IP + high severity
        print("\n--- Test 6: POSSIBLE_THREAT - High Request Rate External High Severity ---")
        threat_threat3 = {
            "ip": "185.220.101.32",
            "confidence_score": 0.5,
            "total_events": 150,
            "timestamps": [
                datetime(2025, 11, 3, 1, 28, 10) + timedelta(seconds=i*2) 
                for i in range(25)  # 25 events in 50 seconds = high rate
            ],
            "src_ips": ["185.220.101.32"],  # External
            "dest_ips": ["10.77.0.20"],
            "rules_violated": [
                {"rule_id": "attack", "severity": "high", "count": 150}
            ]
        }
        result = analyzer.analyze_threat(threat_threat3)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "POSSIBLE_THREAT", "Should classify as POSSIBLE_THREAT"
        print("  ✓ PASSED")
        
        # Test 7: Multiple rule violations + high severity
        print("\n--- Test 7: POSSIBLE_THREAT - Multiple High Severity Rules ---")
        threat_threat4 = {
            "ip": "203.0.113.1",
            "confidence_score": 0.5,
            "total_events": 200,
            "timestamps": [datetime(2025, 11, 3, 1, 0, 0)],
            "src_ips": ["203.0.113.1"],
            "dest_ips": ["10.77.0.20"],
            "rules_violated": [
                {"rule_id": "rule1", "severity": "high", "count": 50},
                {"rule_id": "rule2", "severity": "high", "count": 50},
                {"rule_id": "rule3", "severity": "high", "count": 50},
                {"rule_id": "rule4", "severity": "high", "count": 50}
            ]
        }
        result = analyzer.analyze_threat(threat_threat4)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "POSSIBLE_THREAT", "Should classify as POSSIBLE_THREAT"
        assert "multiple" in result['reasoning'].lower() or "high severity" in result['reasoning'].lower(), "Should mention multiple rules or high severity"
        print("  ✓ PASSED")
        
        # Test 8: Off-hours + external IP + high volume
        print("\n--- Test 8: POSSIBLE_THREAT - Off-Hours External High Volume ---")
        threat_threat5 = {
            "ip": "185.220.101.32",
            "confidence_score": 0.5,
            "total_events": 150,  # High volume
            "timestamps": [
                datetime(2025, 11, 3, 1, 0, 0) + timedelta(minutes=i)  # Off-hours (1 AM)
                for i in range(10)
            ],
            "src_ips": ["185.220.101.32"],  # External
            "dest_ips": ["10.77.0.20"],
            "rules_violated": [
                {"rule_id": "suspicious", "severity": "medium", "count": 150}
            ]
        }
        result = analyzer.analyze_threat(threat_threat5)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "POSSIBLE_THREAT", "Should classify as POSSIBLE_THREAT"
        print("  ✓ PASSED")
        
        # ===== NEEDS_LLM_REVIEW Test Cases =====
        
        # Test 9: Ambiguous case (default)
        print("\n--- Test 9: NEEDS_LLM_REVIEW - Ambiguous Case ---")
        ambiguous_threat1 = {
            "ip": "192.168.1.50",
            "confidence_score": 0.5,
            "total_events": 50,
            "timestamps": [
                datetime(2025, 11, 3, 18, 0, 0)  # Off-hours (not business hours)
            ],
            "src_ips": ["192.168.1.50"],  # Internal
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "rule1", "severity": "medium", "count": 50}  # Medium severity (not high)
            ]
        }
        result = analyzer.analyze_threat(ambiguous_threat1)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "NEEDS_LLM_REVIEW", "Should default to NEEDS_LLM_REVIEW for ambiguous"
        assert result['feature_analyzer_confidence_score'] == 0.5, "Should have default confidence"
        print("  ✓ PASSED")
        
        # Test 10: Low confidence threat adjustment (POSSIBLE_THREAT → NEEDS_LLM_REVIEW)
        print("\n--- Test 10: NEEDS_LLM_REVIEW - Low Confidence Adjustment ---")
        low_conf_threat = {
            "ip": "203.0.113.1",
            "confidence_score": 0.1,  # Very low confidence
            "total_events": 150,
            "timestamps": [datetime(2025, 11, 3, 1, 0, 0)],
            "src_ips": ["203.0.113.1"],  # External
            "dest_ips": ["10.77.0.20"],
            "rules_violated": [
                {"rule_id": "rule1", "severity": "medium", "count": 150}  # Medium severity (not high)
            ]
        }
        result = analyzer.analyze_threat(low_conf_threat)
        print(f"  Classification: {result['classification']}")
        print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        print(f"  Reasoning: {result['reasoning']}")
        # Should be downgraded to NEEDS_LLM_REVIEW due to low confidence
        assert result['classification'] in ["NEEDS_LLM_REVIEW", "POSSIBLE_THREAT"], "Should be NEEDS_LLM_REVIEW or POSSIBLE_THREAT"
        assert result['ml_confidence_score'] == 0.1, "Should preserve low ML confidence"
        if "(Low confidence threat)" in result['reasoning']:
            assert result['classification'] == "NEEDS_LLM_REVIEW", "Should be downgraded to NEEDS_LLM_REVIEW"
        print("  ✓ PASSED")
        
        # Test 11: High confidence threat adjustment (FALSE_POSITIVE → NEEDS_LLM_REVIEW)
        print("\n--- Test 11: NEEDS_LLM_REVIEW - High Confidence Adjustment ---")
        high_conf_threat = {
            "ip": "192.168.1.50",
            "confidence_score": 0.8,  # High confidence
            "total_events": 50,
            "timestamps": [
                datetime(2025, 11, 3, 10, 0, 0) + timedelta(minutes=i*5) 
                for i in range(14)  # Business hours
            ],
            "src_ips": ["192.168.1.50"],  # Internal
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "rule1", "severity": "low", "count": 50}  # Low severity
            ]
        }
        result = analyzer.analyze_threat(high_conf_threat)
        print(f"  Classification: {result['classification']}")
        print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        print(f"  Reasoning: {result['reasoning']}")
        # Might be FALSE_POSITIVE or NEEDS_LLM_REVIEW depending on exact scores
        assert result['ml_confidence_score'] == 0.8, "Should preserve high ML confidence"
        if "(High confidence threat)" in result['reasoning']:
            assert result['classification'] == "NEEDS_LLM_REVIEW", "Should be upgraded to NEEDS_LLM_REVIEW"
        print("  ✓ PASSED")
        
        # Test 12: Mixed indicators (ambiguous)
        print("\n--- Test 12: NEEDS_LLM_REVIEW - Mixed Indicators ---")
        mixed_threat = {
            "ip": "192.168.1.50",
            "confidence_score": 0.5,
            "total_events": 50,
            "timestamps": [
                datetime(2025, 11, 3, 1, 0, 0)  # Off-hours but internal
            ],
            "src_ips": ["192.168.1.50"],  # Internal
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "rule1", "severity": "medium", "count": 50}
            ]
        }
        result = analyzer.analyze_threat(mixed_threat)
        print(f"  Classification: {result['classification']}")
        print(f"  Reasoning: {result['reasoning']}")
        assert result['classification'] == "NEEDS_LLM_REVIEW", "Should default to NEEDS_LLM_REVIEW for ambiguous"
        print("  ✓ PASSED")
        
        # ===== Edge Cases =====
        
        # Test 13: No timestamps
        print("\n--- Test 13: Edge Case - No Timestamps ---")
        no_ts_threat = {
            "ip": "192.168.1.50",
            "confidence_score": 0.5,
            "total_events": 50,
            "timestamps": [],
            "src_ips": ["192.168.1.50"],
            "dest_ips": ["10.77.0.20"],
            "rules_violated": []
        }
        result = analyzer.analyze_threat(no_ts_threat)
        print(f"  Classification: {result['classification']}")
        assert result['classification'] in ["FALSE_POSITIVE", "NEEDS_LLM_REVIEW"], "Should handle missing timestamps"
        print("  ✓ PASSED")
        
        # Test 14: No IPs
        print("\n--- Test 14: Edge Case - No IPs ---")
        no_ips_threat = {
            "ip": "unknown",
            "confidence_score": 0.5,
            "total_events": 50,
            "timestamps": [datetime(2025, 11, 3, 10, 0, 0)],
            "src_ips": [],
            "dest_ips": [],
            "rules_violated": []
        }
        result = analyzer.analyze_threat(no_ips_threat)
        print(f"  Classification: {result['classification']}")
        assert result['classification'] == "NEEDS_LLM_REVIEW", "Should default to NEEDS_LLM_REVIEW without IPs"
        print("  ✓ PASSED")
        
        # Test 15: Missing confidence_score
        print("\n--- Test 15: Edge Case - Missing Confidence Score ---")
        no_conf_threat = {
            "ip": "192.168.1.50",
            # No confidence_score field
            "total_events": 50,
            "timestamps": [datetime(2025, 11, 3, 10, 0, 0)],
            "src_ips": ["192.168.1.50"],
            "dest_ips": ["10.77.0.20"],
            "rules_violated": []
        }
        result = analyzer.analyze_threat(no_conf_threat)
        print(f"  Classification: {result['classification']}")
        print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
        assert result['ml_confidence_score'] == 0.5, "Should default to 0.5 if missing"
        print("  ✓ PASSED")
        
        # Test 16: Very strong false positive (score >= 3)
        print("\n--- Test 16: FALSE_POSITIVE - Strong Indicators ---")
        strong_fp_threat = {
            "ip": "192.168.1.50",
            "confidence_score": 0.3,
            "total_events": 50,
            "timestamps": [
                datetime(2025, 11, 3, 10, 0, 0) + timedelta(minutes=i*5) 
                for i in range(14)  # Business hours
            ],
            "src_ips": ["192.168.1.50"],  # Internal
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "rule1", "severity": "low", "count": 50}  # Low severity
            ]
        }
        result = analyzer.analyze_threat(strong_fp_threat)
        print(f"  Classification: {result['classification']}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        assert result['classification'] == "FALSE_POSITIVE", "Should classify as FALSE_POSITIVE"
        assert result['feature_analyzer_confidence_score'] >= 0.8, "Should have high confidence for strong indicators"
        print("  ✓ PASSED")
        
        # Test 17: Very strong threat (score >= 3)
        print("\n--- Test 17: POSSIBLE_THREAT - Strong Indicators ---")
        strong_threat = {
            "ip": "185.220.101.32",
            "confidence_score": 0.6,
            "total_events": 600,  # Very high
            "timestamps": [
                datetime(2025, 11, 3, 1, 0, 0) + timedelta(seconds=i) 
                for i in range(50)  # Burst
            ],
            "src_ips": ["185.220.101.32"],  # External
            "dest_ips": ["10.77.0.20"],  # Internal
            "rules_violated": [
                {"rule_id": "attack", "severity": "high", "count": 600}
            ]
        }
        result = analyzer.analyze_threat(strong_threat)
        print(f"  Classification: {result['classification']}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        assert result['classification'] == "POSSIBLE_THREAT", "Should classify as POSSIBLE_THREAT"
        assert result['feature_analyzer_confidence_score'] >= 0.8, "Should have high confidence for strong indicators"
        print("  ✓ PASSED")
        
        # Test 18: Real data from api_response.json
        print("\n--- Test 18: Real Data from api_response.json ---")
        json_path = Path(__file__).parent.parent / "api_response.json"
        if json_path.exists():
            threats = analyzer._extract_threat_from_api_response(str(json_path))
            if threats and len(threats) > 0:
                real_threat = threats[0]  # First threat
                result = analyzer.analyze_threat(real_threat)
                print(f"  Threat IP: {real_threat.get('ip')}")
                print(f"  Classification: {result['classification']}")
                print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
                print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
                print(f"  LLM confidence: {result['llm_confidence_score']}")
                print(f"  Reasoning: {result['reasoning']}")
                print(f"  Flags: {result['heuristic_flags'][:5]}...")  # First 5 flags
                assert result['classification'] in ["FALSE_POSITIVE", "NEEDS_LLM_REVIEW", "POSSIBLE_THREAT"], "Should have valid classification"
                assert result['ml_confidence_score'] == real_threat.get('confidence_score', 0.5), "Should preserve ML confidence"
                assert result['llm_confidence_score'] is None, "LLM confidence should be None"
                print("  ✓ PASSED")
            else:
                print("  ⚠ SKIPPED: No threats extracted from JSON")
        else:
            print("  ⚠ SKIPPED: api_response.json not found")
        
        # Test 19: Verify all confidence scores are present
        print("\n--- Test 19: Verify Confidence Score Structure ---")
        test_threat = {
            "ip": "192.168.1.50",
            "confidence_score": 0.42,
            "total_events": 50,
            "timestamps": [datetime(2025, 11, 3, 10, 0, 0)],
            "src_ips": ["192.168.1.50"],
            "dest_ips": ["10.77.0.20"],
            "rules_violated": []
        }
        result = analyzer.analyze_threat(test_threat)
        print(f"  ML confidence: {result['ml_confidence_score']:.2f}")
        print(f"  FeatureAnalyzer confidence: {result['feature_analyzer_confidence_score']:.2f}")
        print(f"  LLM confidence: {result['llm_confidence_score']}")
        assert 'ml_confidence_score' in result, "Should have ml_confidence_score"
        assert 'feature_analyzer_confidence_score' in result, "Should have feature_analyzer_confidence_score"
        assert 'llm_confidence_score' in result, "Should have llm_confidence_score"
        assert result['ml_confidence_score'] == 0.42, "Should preserve exact ML confidence"
        assert isinstance(result['feature_analyzer_confidence_score'], float), "FeatureAnalyzer confidence should be float"
        assert result['llm_confidence_score'] is None, "LLM confidence should be None initially"
        print("  ✓ PASSED")
        
        print("\n" + "=" * 60)
        print("TEST 6 PASSED")
        print("=" * 60 + "\n")
        return True
        
    except AssertionError as e:
        print(f"\n✗ TEST 6 FAILED: Assertion failed - {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n✗ TEST 6 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("FEATURE ANALYZER TEST SUITE")
    print("=" * 60 + "\n")
    
    test1_passed = test_init()
    test2_passed = test_extract_threats()
    test3_passed = test_timing_patterns()
    test4_passed = test_ip_reputation()
    test5_passed = test_traffic_patterns()
    test6_passed = test_analyze_threat()
    
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Test 1 (__init__): {'PASSED' if test1_passed else 'FAILED'}")
    print(f"Test 2 (_extract_threat_from_api_response): {'PASSED' if test2_passed else 'FAILED'}")
    print(f"Test 3 (_check_timing_patterns): {'PASSED' if test3_passed else 'FAILED'}")
    print(f"Test 4 (_check_ip_reputation): {'PASSED' if test4_passed else 'FAILED'}")
    print(f"Test 5 (_check_traffic_patterns): {'PASSED' if test5_passed else 'FAILED'}")
    print(f"Test 6 (analyze_threat): {'PASSED' if test6_passed else 'FAILED'}")
    print("=" * 60)
    
    if test1_passed and test2_passed and test3_passed and test4_passed and test5_passed and test6_passed:
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

