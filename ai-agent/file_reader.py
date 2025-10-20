import json
from pathlib import Path

def read_file():
    """
    Reads and displays the sample_response.json file in the terminal.
    """
    # Get the path to the JSON file (relative to this script)
    json_path = Path(__file__).parent / "sample_response.json"
    
    try:
        # Read and parse the JSON file
        with open(json_path, 'r') as f:
            data = json.load(f)
        

        return data
    except FileNotFoundError:
        print(f"Error: Could not find {json_path}")
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format - {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    display_sample_response()