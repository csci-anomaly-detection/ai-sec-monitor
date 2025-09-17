import sys
from pathlib import Path

# Add project root to Python path for test imports
project_root = Path(__file__).parents[2]  # go up from tests/ to project root
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))