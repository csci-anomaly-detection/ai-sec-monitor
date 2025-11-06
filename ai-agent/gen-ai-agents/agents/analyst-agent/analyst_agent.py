import logging
import os
import re
import ast
import json
from langchain_ollama import ChatOllama
from chroma import query_chroma
from websearch import websearch

# ============================================================================
# SETUP LOGGING TO FILE
# ============================================================================
log_file = os.path.expanduser('~/pipeline_user.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - ANALYST_AGENT - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Create a logger for this module
logger = logging.getLogger(__name__)

# Redirect print to logger
class PrintToLogger:
    def __init__(self, log_func):
        self.log_func = log_func
    
    def write(self, message):
        if message.strip():
            self.log_func(message.strip())
    
    def flush(self):
        pass

import sys
sys.stdout = PrintToLogger(logger.info)
sys.stderr = PrintToLogger(logger.error)

# ============================================================================

port = os.getenv("OLLAMA_PORT", "11434")
llm = ChatOllama(
    model="qwen2.5:7b",
    base_url=f"http://ollama:{port}",
    temperature=0,
    num_ctx=8192,
    stop=[
        "Observation:", 
        "\nObservation",
        "Final Assessment:",
        "\n\n"  # Stop at double newlines
    ]
)    
def trim_messages(messages, max_messages=10):
    """Keep system prompt + last N user/assistant pairs"""
    if len(messages) <= max_messages + 2: 
        return messages
    
    # Always keep system prompt (first message)
    system_msg = messages[0]
    
    # Keep only last N messages
    recent_messages = messages[-(max_messages):]
    
    return [system_msg] + recent_messages

def filter_final_report(report_json_str):
    """
    Parse and filter the final report JSON string.
    Returns a dict with only the required fields.
    """
    try:
        report = json.loads(report_json_str)
    except json.JSONDecodeError as e:
        print(f"⚠️ Error parsing JSON in filter_final_report: {e}")
        return report_json_str
    
    filtered = {
        "threat_sources": report.get("threat_sources", []),
        "attack_types": report.get("attack_types", []),
        "severity": report.get("severity", ""),
        "confidence": report.get("confidence", ""),
        "what_is_happening": report.get("what_is_happening", ""),
        "immediate_actions": report.get("immediate_actions", []),
        "recommendations": report.get("recommendations", ""),
        "signature_ids_analyzed": report.get("signature_ids_analyzed", [])
    }
    return filtered

def analyze_threat(threat_data, max_retries=10):
    """
    LLM agent with clear step-by-step instructions and available tools
    """
    
    system_prompt = """You are an expert cybersecurity threat analyst with access to two tools.

================================================================================
MANDATORY TOOL USAGE REQUIREMENT
================================================================================
YOU MUST CALL AT LEAST ONE TOOL BEFORE PROVIDING YOUR FINAL ANSWER.
IF YOU PROVIDE A FINAL ANSWER WITHOUT CALLING ANY TOOLS, YOUR RESPONSE WILL BE REJECTED.

================================================================================
AVAILABLE TOOLS
================================================================================

Tool 1: ChromaQuery
Purpose: Retrieve detailed logs from the database
Format: 
Action: ChromaQuery
Action Input: "query string"

Tool 2: WebSearch
Purpose: Research threat intelligence and mitigation strategies
Format:
Action: WebSearch
Action Input: "search query"

================================================================================
WORKFLOW (STRICT ORDER)
================================================================================

1. FIRST ACTION: Call ChromaQuery to get detailed logs
2. SECOND ACTION: Call WebSearch to research mitigation strategies
3. OPTIONAL: Call ChromaQuery or WebSearch again if needed
4. FINAL STEP: Provide structured JSON analysis

YOU CANNOT SKIP TO STEP 4 WITHOUT COMPLETING STEPS 1-2.

================================================================================
ACTION FORMAT (USE THIS EXACTLY)
================================================================================

Thought: I need to gather log data for the signatures
Action: ChromaQuery
Action Input: "all_logs signature_id"

DO NOT ADD ANYTHING AFTER "Action Input:" - STOP IMMEDIATELY.

================================================================================
FINAL ANSWER FORMAT
================================================================================

Only after using tools, provide:

Final Answer:
{
  "threat_sources": ["IPs from data"],
  "attack_types": ["attack types"],
  "severity": "HIGH/MEDIUM/LOW",
  "confidence": 0.85,
  "what_is_happening": "attack description",
  "immediate_actions": ["action1", "action2", "action3"],
  "recommendations": "mitigation steps",
  "signature_ids_analyzed": ["ids"]
}

================================================================================
CRITICAL RULES
================================================================================
1. YOU MUST USE AT LEAST ONE TOOL BEFORE FINAL ANSWER
2. DO NOT PROVIDE FINAL ANSWER WITHOUT TOOL USAGE
3. ANALYZE REAL DATA FROM TOOLS, NOT FROM YOUR TRAINING
================================================================================
"""

    prompt = f"""ANALYZE THIS THREAT DATA. YOU MUST USE THE TOOLS BEFORE ANSWERING.

<threat_data>
{threat_data}
</threat_data>

STEP 1: Call ChromaQuery to get logs for these signatures
STEP 2: Call WebSearch to research mitigation strategies
STEP 3: Provide your Final Answer based on tool results

START WITH YOUR FIRST ACTION NOW. DO NOT SKIP TO FINAL ANSWER."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt}
    ]

    chroma_calls = 0
    websearch_calls = 0
    max_chroma_calls = 2
    max_websearch_calls = 2
    
    for i in range(max_retries):
        messages_trimmed = trim_messages(messages, max_messages=7)

        try:
            response = llm.invoke(messages_trimmed)
            content = response.content
        except Exception as e:
            print(f"❌ LLM Error: {e}")
            error_report = {
                "threat_sources": ["unknown"],
                "attack_types": ["unknown"],
                "severity": "UNKNOWN",
                "confidence": 0.0,
                "what_is_happening": "Analysis failed due to LLM error",
                "immediate_actions": ["Escalate to security team"],
                "recommendations": "Manual review required",
                "signature_ids_analyzed": []
            }
            return filter_final_report(json.dumps(error_report))

        # Clean up response
        if "Observation:" in content:
            content = content.split("Observation:")[0].strip()

        print(f"\n{'='*60}")
        print(f"ITERATION {i+1} [ChromaQuery: {chroma_calls}/{max_chroma_calls} | WebSearch: {websearch_calls}/{max_websearch_calls}]")
        print(f"{'='*60}")
        print(f"🔍 RAW LLM RESPONSE:\n{content}\n")

        # Check for premature Final Answer (without tool usage)
        if "Final Answer:" in content and chroma_calls == 0 and websearch_calls == 0:
            print(f"⚠️ REJECTED: Final Answer provided without using any tools!")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": "ERROR: You provided a Final Answer without using any tools. You MUST call ChromaQuery or WebSearch before providing your final answer. Start with: Action: ChromaQuery"})
            continue

        # Check for Final Answer (after tool usage)
        if "Final Answer:" in content and (chroma_calls > 0 or websearch_calls > 0):
            final = content.split("Final Answer:")[-1].strip()
            final = final.strip('`').strip()
            if final.startswith('json'):
                final = final[4:].strip()
        
            try:
                final_json = json.loads(final)
                
                required_fields = [
                    'threat_sources', 'attack_types', 'severity', 'confidence',
                    'what_is_happening', 'immediate_actions',
                    'recommendations', 'signature_ids_analyzed'
                ]
                
                missing_fields = [field for field in required_fields if field not in final_json]
                
                if missing_fields:
                    print(f"⚠️ Missing required fields: {missing_fields}")
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": f"ERROR: Missing fields: {', '.join(missing_fields)}. Provide complete JSON."})
                    continue
                
                print(f"\n✅ Analysis complete with all required fields after {chroma_calls} ChromaQuery + {websearch_calls} WebSearch calls!")
                return filter_final_report(final)
                
            except json.JSONDecodeError as e:
                print(f"⚠️ Invalid JSON: {e}")
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "ERROR: Invalid JSON. Provide valid JSON with all 8 fields."})
                continue

        # Parse Actions
        action_match = re.search(r'Action:\s*(\w+)', content)
        input_match = re.search(r'Action Input:\s*["\']?(.+?)["\']?(?:\n|$)', content, re.DOTALL)

        if action_match and input_match:
            action = action_match.group(1).strip()
            action_input = input_match.group(1).strip().strip('"').strip("'")
            
            print(f"🔧 Action: {action}")
            print(f"📝 Input: {action_input}")
            
            messages.append({"role": "assistant", "content": content})
            
            if action == "ChromaQuery":
                if chroma_calls >= max_chroma_calls:
                    print(f"⚠️ ChromaQuery limit reached")
                    messages.append({"role": "user", "content": f"ChromaQuery limit reached. Use WebSearch or provide Final Answer."})
                    continue
                
                chroma_calls += 1
                result = query_chroma(action_input)
                if result:
                    print(f"📊 Observation: {result[:200]}...")
                    messages.append({"role": "user", "content": f"Observation:\n{result}"})
                else:
                    messages.append({"role": "user", "content": "Observation: No data found."})
                    
            elif action == "WebSearch":
                if websearch_calls >= max_websearch_calls:
                    print(f"⚠️ WebSearch limit reached")
                    messages.append({"role": "user", "content": f"WebSearch limit reached. Use ChromaQuery or provide Final Answer."})
                    continue
                
                websearch_calls += 1
                result = websearch(action_input)
                if result:
                    print(f"🔍 Observation: {result[:200]}...")
                    messages.append({"role": "user", "content": f"Observation:\n{result}"})
                else:
                    messages.append({"role": "user", "content": "Observation: No results found."})
                    
            else:
                print(f"⚠️ Unknown action: {action}")
                messages.append({"role": "user", "content": f"Unknown action. Use ChromaQuery or WebSearch."})
                continue
            
            # After 2+ tool calls, prompt for final answer
            if chroma_calls + websearch_calls >= 2:
                print(f"\n✅ Tool calls completed. Requesting final answer...")
                force_final_prompt = f"""You have used {chroma_calls} ChromaQuery and {websearch_calls} WebSearch calls.

NOW PROVIDE YOUR FINAL ANSWER using data from the tools.

Final Answer:
{{
  "threat_sources": [...],
  "attack_types": [...],
  "severity": "...",
  "confidence": 0.85,
  "what_is_happening": "...",
  "immediate_actions": [...],
  "recommendations": "...",
  "signature_ids_analyzed": [...]
}}
"""
                messages.append({"role": "user", "content": force_final_prompt})
        else:
            print(f"⚠️ Could not parse Action/Action Input")
            print(f"RESPONSE DUMP:\n{repr(content)}\n")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": "ERROR: Provide 'Action:' and 'Action Input:'. Example:\nAction: ChromaQuery\nAction Input: \"all_logs 1000010\""})
            continue
        
    # Fallback
    print(f"\n⚠️ Max retries reached without valid analysis")
    fallback_report = {
        "threat_sources": ["unknown"],
        "attack_types": ["unknown"],
        "severity": "UNKNOWN",
        "confidence": 0.0,
        "what_is_happening": "Analysis failed - max retries",
        "immediate_actions": ["Escalate"],
        "recommendations": "Manual review",
        "signature_ids_analyzed": []
    }
    return filter_final_report(json.dumps(fallback_report))