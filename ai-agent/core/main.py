#!/usr/bin/env python3
"""
AI Security Monitor - Main Pipeline
Reads threat data from JSON and analyzes it with LLM
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.file_reader import read_file
from core.agents import analyze_threat
from utils.file_writer import write_analysis, write_analysis_json
from agents.email_agent import send_critical_alert


def main():
    """
    Main pipeline:
    1. Read the sample_response.json
    2. Extract threats
    3. Analyze each threat with LLM
    4. Send email alerts for CRITICAL threats
    5. Save analysis results
    """
    
    # Read the data
    data = read_file()
    
    if not data:
        return
    
    # Extract threats
    response_summary = data.get('response_summary', {})
    threats = response_summary.get('threats_detected', [])
    
    if not threats:
        return
    
    # Analyze each threat with LLM
    for threat in threats:
        # Call the LLM agent
        analysis = analyze_threat(threat)
        
        # Save analysis to files
        write_analysis(threat, analysis)
        write_analysis_json(threat, analysis)
        
        # Check if this is a CRITICAL threat and send email alert
        if threat.get('severity') == 'CRITICAL':
            send_critical_alert(threat, analysis)


if __name__ == "__main__":
    main()

