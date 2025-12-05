import json
from pathlib import Path

def read_file():
    """
    Reads the sample_response.json file.
    """
    # Look for sample_response.json in ai-agent root directory
    json_path = Path(__file__).parent.parent / "sample_response.json"
    
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        return data
    except (FileNotFoundError, json.JSONDecodeError, Exception):
        return None