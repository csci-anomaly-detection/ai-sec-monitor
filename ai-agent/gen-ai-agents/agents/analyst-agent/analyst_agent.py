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
        "Decision:",
        "Next Step:",
        "Recommendations:",
        "Final Assessment:",
        "Based on",
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
    
    system_prompt = """You are an expert cybersecurity threat analyst. Your job is to analyze threat signatures and provide a final structured assessment based on REAL DATA PROVIDED TO YOU.

================================================================================
AVAILABLE TOOLS (USE THESE TO GATHER DATA)
================================================================================

Tool 1: ChromaQuery
Purpose: Retrieve detailed logs, rules, and threat intelligence from the database
Format: Action: ChromaQuery
        Action Input: "query string"
Use when: You need specific logs, signature details, or threat context
LIMIT: You can call this tool UP TO 2 TIMES

Tool 2: WebSearch
Purpose: Research current threat intelligence, best practices, and mitigation strategies
Format: Action: WebSearch
        Action Input: "search query"
Use when: You need research, mitigation recommendations, or current best practices
LIMIT: You can call this tool UP TO 2 TIMES

================================================================================
YOUR ANALYSIS WORKFLOW (FOLLOW THESE STEPS)
================================================================================

STEP 1: UNDERSTAND THE THREAT DATA
  - You will receive threat signatures with IDs and severity levels
  - Read the initial threat data provided and ANALYZE IT SPECIFICALLY
  - DO NOT use generic examples - use the ACTUAL data you receive

STEP 2: GATHER INTELLIGENCE (Call tools strategically)
  - Call ChromaQuery (up to 2 times) to get logs and details for EACH signature
  - Call WebSearch (up to 2 times) to find mitigation strategies
  - Mix your tool calls: ChromaQuery, then WebSearch, then ChromaQuery, then WebSearch

STEP 3: SYNTHESIZE THE ANALYSIS
  - Combine all gathered data
  - Identify the attack pattern and timeline from REAL DATA
  - Map to MITRE ATT&CK if possible
  - Assess severity based on PROVIDED data only (no guessing)

STEP 4: RETURN FINAL ANSWER
  - Provide complete JSON with all 8 required fields
  - NO markdown, NO extra text, just the JSON
  - BASE YOUR ANSWER ON THE THREAT DATA YOU RECEIVED, NOT EXAMPLES

================================================================================
FINAL ANSWER FORMAT (REQUIRED - ALL 8 FIELDS MANDATORY)
================================================================================

After gathering data, return EXACTLY:

Final Answer:
{
  "threat_sources": ["IP addresses from the actual data"],
  "attack_types": ["attack types from the actual signatures"],
  "severity": "HIGH/MEDIUM/LOW based on actual data",
  "confidence": 0.75,
  "what_is_happening": "Describe THE ACTUAL attack chain from the data provided",
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "recommendations": "mitigation steps based on actual signatures",
  "signature_ids_analyzed": ["actual signature IDs from the threat data"]
}

CRITICAL REQUIREMENTS FOR FINAL ANSWER:
- "threat_sources": Array of IPs from YOUR DATA
- "attack_types": Array of attack techniques from YOUR DATA
- "severity": HIGH/MEDIUM/LOW (based on YOUR provided data)
- "confidence": Number between 0.0 and 1.0
- "what_is_happening": Describe THE ACTUAL attack chain YOU RECEIVED
- "immediate_actions": Array of exactly 3 actions specific to YOUR threat data
- "recommendations": Mitigation steps for YOUR specific signatures
- "signature_ids_analyzed": All signature IDs from YOUR input data

================================================================================
CRITICAL RULES (FOLLOW THESE OR ANALYSIS FAILS)
================================================================================

1. ✅ ANALYZE REAL DATA: Only analyze the threat data you receive - DO NOT return examples
2. ✅ NO FABRICATION: Only use data explicitly provided or from tool results
3. ✅ NO REPETITION: Do NOT call the same tool twice with same query
4. ✅ CHROMA LIMIT: Call ChromaQuery maximum 2 times and minimum 1 times
5. ✅ WEBSEARCH LIMIT: Call WebSearch maximum 2 times and minimum 1 times
6. ✅ MIX YOUR CALLS: Alternate between ChromaQuery and WebSearch
7. ✅ VALID JSON ONLY: Final Answer MUST be parseable JSON
8. ✅ ALL SIGNATURES: Include ALL signature IDs from input
9. ✅ NO MARKDOWN: NO backticks (```), NO "```json", just raw JSON
10. ✅ 8 FIELDS REQUIRED: Do not omit any field
11. ✅ USE ACTUAL DATA: Your final answer MUST be specific to the threat_data provided

================================================================================
IMPORTANT: YOU MUST ANALYZE THE THREAT DATA PROVIDED TO YOU AND MUST USE THE TOOLS GIVEN TO YOU ATLEAST 1 TIME.
DO NOT RETURN GENERIC OR EXAMPLE ANSWERS.
DO NOT RETURN 203.0.113.5 IF IT'S NOT IN YOUR DATA.
ANALYZE THE SPECIFIC SIGNATURES AND IPs IN THE THREAT_DATA SECTION.
================================================================================
"""

    # Extract actual threat data info
    threat_summary = threat_data
    if isinstance(threat_data, dict):
        threat_summary = f"Threat signatures: {threat_data.get('signature_ids_analyzed', [])} from IPs: {threat_data.get('threat_sources', [])}"
    elif isinstance(threat_data, list):
        threat_summary = f"Total threats: {len(threat_data)}"
    
    prompt = f"""ANALYZE THE FOLLOWING THREAT DATA AND PROVIDE A STRUCTURED ASSESSMENT.

<threat_data>
{threat_data}
</threat_data>

IMPORTANT INSTRUCTIONS:
- Analyze THIS specific threat data, not examples
- Use the tools to gather information about THESE specific signatures
- Return analysis SPECIFIC to the threat_data above
- Do NOT return generic or example answers
- Do NOT return the same answer for every input
- Do NOT return without using any tools.

Use ChromaQuery and WebSearch to gather information:
1. Call ChromaQuery to get logs and details for each signature
2. Call WebSearch to find mitigation strategies
3. Call ChromaQuery again for more context
4. Call WebSearch again for best practices
5. After all 4 tool calls, provide your final structured analysis SPECIFIC TO THIS DATA

PROVIDE YOUR FINAL STRUCTURED ANALYSIS."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt}
    ]

    # Track tool calls separately
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
        if "\n\n" in content:
            content = content.split("\n\n")[0].strip()

        print(f"\n{'='*60}")
        print(f"ITERATION {i+1} [ChromaQuery: {chroma_calls}/{max_chroma_calls} | WebSearch: {websearch_calls}/{max_websearch_calls}]")
        print(f"{'='*60}")
        print(f"🔍 RAW LLM RESPONSE:\n{content}\n")  # <-- ADD THIS DEBUG LINE
        print(content)

        # Check for Final Answer
        if "Final Answer:" in content:
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
                    messages.append({"role": "user", "content": f"ERROR: Your Final Answer is missing these fields: {', '.join(missing_fields)}. Provide complete JSON with all 8 fields."})
                    continue
                
                print(f"\n✅ Analysis complete with all required fields!")
                return filter_final_report(final)
                
            except json.JSONDecodeError as e:
                print(f"⚠️ Invalid JSON in final answer: {e}")
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "ERROR: Final Answer must be valid JSON. Check for syntax errors and provide complete JSON with all 8 required fields."})
                continue

        # Parse Actions
        action_match = re.search(r'Action:\s*(\w+)', content)
        input_match = re.search(r'Action Input:\s*(.+?)(?:\n|$)', content, re.DOTALL)

        print(f"🔧 Action Match: {action_match}")  # <-- ADD THIS DEBUG LINE
        print(f"📝 Input Match: {input_match}")    # <-- ADD THIS DEBUG LINE

        if action_match and input_match:
            action = action_match.group(1).strip()
            action_input = input_match.group(1).strip().strip('"').strip("'")
            
            print(f"🔧 Action: {action}")
            print(f"📝 Input: {action_input}")
            
            messages.append({"role": "assistant", "content": content})
            
            if action == "ChromaQuery":
                if chroma_calls >= max_chroma_calls:
                    print(f"⚠️ ChromaQuery limit reached ({max_chroma_calls}/{max_chroma_calls}). Use WebSearch instead.")
                    messages.append({"role": "user", "content": f"ERROR: You have reached the ChromaQuery limit ({max_chroma_calls} calls). Use WebSearch tool instead to gather more information."})
                    continue
                
                chroma_calls += 1
                result = query_chroma(action_input)
                if result:
                    print(f"📊 Observation: {result[:200]}...")
                    messages.append({"role": "user", "content": f"Observation:\n{result}"})
                else:
                    messages.append({"role": "user", "content": "Observation: No data found for this query."})
                    
            elif action == "WebSearch":
                if websearch_calls >= max_websearch_calls:
                    print(f"⚠️ WebSearch limit reached ({max_websearch_calls}/{max_websearch_calls}). Use ChromaQuery instead or provide Final Answer.")
                    messages.append({"role": "user", "content": f"ERROR: You have reached the WebSearch limit ({max_websearch_calls} calls). Use ChromaQuery tool instead or provide your Final Answer now."})
                    continue
                
                websearch_calls += 1
                result = websearch(action_input)
                if result:
                    print(f"🔍 Observation: {result[:200]}...")
                    messages.append({"role": "user", "content": f"Observation:\n{result}"})
                else:
                    messages.append({"role": "user", "content": "Observation: No results found for this search."})
                    
            else:
                print(f"⚠️ Unknown action: {action}")
                messages.append({"role": "user", "content": f"ERROR: Unknown action '{action}'. Available tools are: ChromaQuery (max {max_chroma_calls}), WebSearch (max {max_websearch_calls})"})
                continue
            
            # FORCE SYNTHESIS AFTER ALL 4 TOOL CALLS
            if chroma_calls >= max_chroma_calls and websearch_calls >= max_websearch_calls:
                print(f"\n✅ All tool calls completed. Forcing final synthesis...")
                force_final_prompt = f"""
You have completed all 4 tool calls. NOW PROVIDE YOUR FINAL ANSWER IMMEDIATELY.

REMEMBER: You are analyzing THIS specific threat data:
{threat_data}

Return ONLY the JSON (no markdown, no extra text):

Final Answer:
{{
  "threat_sources": ["IPs from THIS threat data"],
  "attack_types": ["types from THIS data"],
  "severity": "HIGH/MEDIUM/LOW",
  "confidence": 0.85,
  "what_is_happening": "describe THE ACTUAL attack in THIS data",
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "recommendations": "mitigation for THIS specific threat",
  "signature_ids_analyzed": ["signature IDs from THIS data"]
}}

CRITICAL: Use REAL data from the threat_data provided, not examples.
"""
                messages.append({"role": "user", "content": force_final_prompt})
                response = llm.invoke(messages[-2:])
                
                if "Final Answer:" in response.content:
                    final = response.content.split("Final Answer:")[-1].strip()
                    final = final.strip('`').strip()
                    if final.startswith('json'):
                        final = final[4:].strip()
                    try:
                        final_json = json.loads(final)
                        if len(final_json) >= 8:
                            print(f"\n✅ Forced synthesis succeeded!")
                            return filter_final_report(final)
                    except json.JSONDecodeError:
                        pass
        else:
            print(f"🔧 Action: {action_match}")
            print(f"📝 Input: {input_match}")
            print(f"⚠️ Could not parse Action/Action Input - DUMPING FULL RESPONSE:")
            print(f"RESPONSE DUMP:\n{repr(content)}\n")  # <-- ADD THIS TO SEE EXACT CONTENT
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": f"ERROR: You must provide 'Action:' and 'Action Input:' lines."})
            continue
        
    # Fallback
    print(f"\n⚠️ Max retries reached.")
    fallback_report = {
        "threat_sources": ["unknown"],
        "attack_types": ["unknown"],
        "severity": "UNKNOWN",
        "confidence": 0.0,
        "what_is_happening": "Analysis failed",
        "immediate_actions": ["Escalate"],
        "recommendations": "Manual review",
        "signature_ids_analyzed": []
    }
    return filter_final_report(json.dumps(fallback_report))