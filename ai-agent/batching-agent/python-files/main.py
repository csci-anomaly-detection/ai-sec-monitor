import sys
import os
import json
import subprocess

# Add paths for imports
sys.path.insert(0, '/app')

# Import the functions
from pre_batch import process_and_store_batches
from batching_agent import react_agent
log_location = "/app/logs/eve.json"
if __name__ == "__main__":
    # Step 1: Run pre_batch to process logs
    print("Running prebatching and preprocessing for log batching and storage...")
    try:
        batched_data = process_and_store_batches(log_location)
        print(f"✅ Batched {len(batched_data)} alert groups")
    except Exception as e:
        print(f"Error in pre_batch.py: {e}")
        exit(1)
    
    # Step 2: Pass batched_data to the agent
    print("\nRunning batching_agent.py for LLM-driven analysis...")
    try:
        if batched_data:
            analysis_result = react_agent(batched_data=batched_data)
            print("\n" + "="*60)
            print("FINAL ANALYSIS RESULT")
            print("="*60)
            print(analysis_result)
        else:
            print("Batched data not found.")
    except Exception as e:
            print(f"Error in batching_agent.py: {e}")
            exit(1)