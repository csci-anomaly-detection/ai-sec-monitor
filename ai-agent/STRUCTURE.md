# AI Agent Folder Structure

## Overview
The `ai-agent` folder has been organized into logical subdirectories for better maintainability.

## Directory Structure

```
ai-agent/
├── core/                    # Core modules
│   ├── __init__.py
│   ├── feature_analyzer.py  # FeatureAnalyzer class for heuristic analysis
│   ├── agents.py            # LLM agent functions
│   └── main.py              # Main pipeline entry point
│
├── scripts/                 # Standalone scripts
│   ├── __init__.py
│   └── run_api_response.py  # Script to process api_response.json
│
├── utils/                   # Utility modules
│   ├── __init__.py
│   ├── file_reader.py       # File reading utilities
│   └── file_writer.py       # File writing utilities
│
├── agents/                  # Agent implementations
│   ├── __init__.py
│   └── email_agent.py      # Email notification agent
│
├── tests/                   # Test files
│   ├── __init__.py
│   ├── test_email.py
│   └── test_feature_analyzer.py
│
├── batching-agent/          # Batching agent (unchanged)
│   └── ...
│
├── analysis_output/         # Output directory for analysis results
│   └── ...
│
├── venv/                   # Virtual environment (if exists)
│   └── ...
│
└── README.md               # Documentation
```

## Usage

### Running the main pipeline:
```bash
cd ai-agent
python3 -m core.main
```

### Running the FeatureAnalyzer script:
```bash
cd ai-agent
python3 scripts/run_api_response.py
```

### Running tests:
```bash
cd ai-agent
python3 -m pytest tests/
# or
python3 tests/test_feature_analyzer.py
```

## Import Examples

### From other modules:
```python
from core.feature_analyzer import FeatureAnalyzer
from core.agents import analyze_threat
from utils.file_reader import read_file
from utils.file_writer import write_analysis
from agents.email_agent import send_critical_alert
```

### From scripts:
```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.feature_analyzer import FeatureAnalyzer
```

## Notes

- All `__init__.py` files have been created to make folders proper Python packages
- Import paths have been updated to reflect the new structure
- Path references in utility functions have been adjusted to work from subdirectories
- The `batching-agent/` folder remains unchanged as it's a separate component
