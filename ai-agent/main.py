import datetime
from ai.preprocess import preprocess_logs
from ai.ai_agent import run_ai_triage
from ai.postprocess import validate_and_enrich

# --- 1. Load logs ---
all_logs = preprocess_logs("./audit.json")

# --- 2. Generate AI summary ---
try:
    llm_output = run_ai_triage(
        all_logs
    )
except Exception as e:
    llm_output = {"error": str(e), "raw_output": None}

print(llm_output)
# --- 4. Post-process AI output ---
final_output = validate_and_enrich(llm_output)

# --- 5. Print structured JSON ---
import json
print(json.dumps(final_output, indent=2))
