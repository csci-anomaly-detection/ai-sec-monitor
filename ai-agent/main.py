#!/usr/bin/env python3
"""
AI Security Monitor - Main Pipeline
Reads threat data from JSON and analyzes it with LLM
"""

from file_reader import read_file
from agents import analyze_threat
from file_writer import write_analysis, write_analysis_json
import json


def main():
    """
    Main pipeline:
    1. Read the sample_response.json
    2. Extract threats
    3. Analyze each threat with LLM
    4. Display results
    """
    
    print("AI SECURITY MONITOR - THREAT ANALYSIS PIPELINE")
    print()
    
    # Step 1: Read the data
    data = read_file()
    
    if not data:
        print("ERROR: Failed to read data. Exiting.")
        return
    
    # Step 2: Extract threats
    response_summary = data.get('response_summary', {})
    threats = response_summary.get('threats_detected', [])
    stats = response_summary.get('summary_stats', {})
    
    print(f"Threats detected: {len(threats)}")
    print(f"Logs analyzed: {stats.get('logs_analyzed', 0)}")
    print(f"High severity threats: {stats.get('high_severity_threats', 0)}")
    print()
    
    if not threats:
        print("No threats detected. Nothing to analyze.")
        return
    
    # Step 3: Analyze each threat with LLM
    print()
    
    for idx, threat in enumerate(threats, 1):
        print(f"THREAT #{idx}")
        print(f"IP: {threat.get('ip')}")
        print(f"Type: {threat.get('attack_type')}")
        print(f"Severity: {threat.get('severity')}")
        print(f"Events: {threat.get('total_events')}")
        print()
        print("LLM Analysis:")
        
        # Call the LLM agent
        analysis = analyze_threat(threat)
        print()
        print(analysis)
        print()
        
        # Save analysis to files
        txt_path = write_analysis(threat, analysis)
        json_path = write_analysis_json(threat, analysis)
        print(f"Analysis saved to: {txt_path}")
        print(f"JSON saved to: {json_path}")
        print()

        print()
    
    # Step 4: Summary
    print("SUMMARY:")
    print(f"  Total threats analyzed: {len(threats)}")
    print(f"  High severity: {sum(1 for t in threats if t.get('severity') == 'HIGH')}")
    print(f"  Critical severity: {sum(1 for t in threats if t.get('severity') == 'CRITICAL')}")
    print()


if __name__ == "__main__":
    main()

