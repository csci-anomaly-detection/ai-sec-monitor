import json
from pathlib import Path
from datetime import datetime


def write_analysis(threat_data, analysis_text, output_dir="analysis_output"):
    """
    Saves threat analysis to a file.
    
    Args:
        threat_data: Dictionary containing threat information
        analysis_text: The LLM analysis text
        output_dir: Directory to save analysis files (default: 'analysis_output')
    
    Returns:
        str: Path to the saved file
    """
    # Create output directory if it doesn't exist
    output_path = Path(__file__).parent / output_dir
    output_path.mkdir(exist_ok=True)
    
    # Generate filename with timestamp and IP
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ip = threat_data.get('ip', 'unknown').replace('.', '_')
    filename = f"threat_analysis_{ip}_{timestamp}.txt"
    
    file_path = output_path / filename
    
    # Prepare content
    content = f"""{'=' * 80}
THREAT ANALYSIS REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'=' * 80}

THREAT DETAILS:
{'─' * 80}
IP Address:      {threat_data.get('ip', 'N/A')}
Attack Type:     {threat_data.get('attack_type', 'N/A')}
Severity:        {threat_data.get('severity', 'N/A')}
Total Events:    {threat_data.get('total_events', 'N/A')}
Recommendation:  {threat_data.get('recommendation', 'N/A')}

LLM ANALYSIS:
{'─' * 80}
{analysis_text}

{'=' * 80}
"""
    
    # Write to file
    with open(file_path, 'w') as f:
        f.write(content)
    
    return str(file_path)


def write_analysis_json(threat_data, analysis_text, output_dir="analysis_output"):
    """
    Saves threat analysis to a JSON file.
    
    Args:
        threat_data: Dictionary containing threat information
        analysis_text: The LLM analysis text
        output_dir: Directory to save analysis files (default: 'analysis_output')
    
    Returns:
        str: Path to the saved file
    """
    # Create output directory if it doesn't exist
    output_path = Path(__file__).parent / output_dir
    output_path.mkdir(exist_ok=True)
    
    # Generate filename with timestamp and IP
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ip = threat_data.get('ip', 'unknown').replace('.', '_')
    filename = f"threat_analysis_{ip}_{timestamp}.json"
    
    file_path = output_path / filename
    
    # Prepare JSON structure
    analysis_record = {
        "timestamp": datetime.now().isoformat(),
        "threat_data": {
            "ip": threat_data.get('ip'),
            "attack_type": threat_data.get('attack_type'),
            "severity": threat_data.get('severity'),
            "total_events": threat_data.get('total_events'),
            "recommendation": threat_data.get('recommendation')
        },
        "analysis": analysis_text
    }
    
    # Write to file
    with open(file_path, 'w') as f:
        json.dump(analysis_record, f, indent=2)
    
    return str(file_path)


if __name__ == "__main__":
    # Test the function
    test_threat = {
        'ip': '172.31.30.154',
        'attack_type': 'Reconnaissance / Scanning',
        'severity': 'HIGH',
        'total_events': 27,
        'recommendation': 'Block IP, monitor for lateral movement'
    }
    
    test_analysis = """This is a test analysis.
The threat appears to be a reconnaissance scan.
Immediate action required."""
    
    # Save as text
    txt_path = write_analysis(test_threat, test_analysis)
    print(f"Text file saved: {txt_path}")
    
    # Save as JSON
    json_path = write_analysis_json(test_threat, test_analysis)
    print(f"JSON file saved: {json_path}")

