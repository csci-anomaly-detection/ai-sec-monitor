from langchain_ollama import ChatOllama
import os
import re
import ast
import json
from pgres import run_query
from chroma import query_chroma
from check_relevance import check_vulnerability_relevance
port = os.getenv("OLLAMA_PORT", "11434")
llm = ChatOllama(
    model="llama3.1:8b",
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

def execute_tool(tool_name, tool_input):
    """Execute tools based on parsed actions"""
    print(f"\n🔧 Executing {tool_name} with input: {tool_input}")
    
    if tool_name == "ChromaQuery":
        result = query_chroma(tool_input)
    elif tool_name == "PostgresQuery":
        result = run_query(tool_input)
    elif tool_name == "RelevanceScore":
        result = check_vulnerability_relevance(tool_input)
    else:
        result = f"Unknown tool: {tool_name}"
    
    print(f"✅ Tool result: {str(result)[:200]}...")
    return result


def react_agent(batched_data, max_iterations=6):
    """Manual ReAct loop with strict observation control"""
    if not batched_data: return "No data provided"
    print(f"📊 Batched Data: {batched_data}")
    executed_queries = set()
    data_collected = {'postgres': "", 'chroma': "", 'relevance': ""}
    
    # ============================================================
    # FIX 1: Extract REAL signature descriptions from batched_data
    # ============================================================
    signature_mapping = {}  # signature_id -> description
    signature_ids = []
    batch_summary = []
    
    for batch in batched_data:
        sig_id = batch.get('signature_id')
        signature = batch.get('signature', 'Unknown')  # Get actual description
        count = batch.get('count', len(batch.get('alert_ids', [])))
        
        signature_ids.append(sig_id)
        signature_mapping[str(sig_id)] = signature  # Store real description
        batch_summary.append(f"  - Signature ID {sig_id} ({signature}): {count} alerts")
    
    signature_ids_str = ", ".join(map(str, set(signature_ids)))
    batch_summary_str = "\n".join(batch_summary)
    signature_mapping_str = json.dumps(signature_mapping, indent=2)

    system_prompt = """You are an expert security analyst agent.

═══════════════════════════════════════════════════════════════
CRITICAL RULES
═══════════════════════════════════════════════════════════════

1. NEVER fabricate or modify signature descriptions
2. Use EXACT descriptions provided in <signature_mapping>
3. ONE action per response - NO multiple Action Input lines
4. STOP immediately after Action Input line
5. Final Answer MUST include ALL signature_ids from the batch

═══════════════════════════════════════════════════════════════
AVAILABLE TOOLS
═══════════════════════════════════════════════════════════════

1. RelevanceScore
   PURPOSE: Determines if alerts are real threats based on server technology stack
   INPUT: Python dictionary with EXACT signature descriptions from <signature_mapping>
   EXAMPLE: {"1000010": "SQL Injection Attempt - UNION", "1000020": "MongoDB NoSQL Injection"}
   OUTPUT: JSON mapping signature_id to severity: false_positive|low|medium|high|critical
   
   ⚠️  CRITICAL: You can only call RelevanceScore ONCE per unique set of signature_ids.
   Do NOT call it multiple times with the same signatures - the descriptions never change.

2. PostgresQuery
   PURPOSE: Retrieve historical alert patterns
   INPUT: Valid SQL SELECT query as single-line string
   
   TABLE SCHEMA:
   - signature_id (int)
   - alert_count (int)
   - src_ips (jsonb)
   - created_at (timestamp)
   
   EXAMPLE: SELECT signature_id, alert_count, created_at FROM alert_batches WHERE signature_id IN (1000010, 1000020) ORDER BY created_at DESC LIMIT 50

3. ChromaQuery
   PURPOSE: Fetch detailed logs/rules
   INPUT: Collection name + signature_id
   EXAMPLES:
   - "all_logs 1000010"
   - "suricata_rules 1000010"

═══════════════════════════════════════════════════════════════
RESPONSE FORMAT - MANDATORY
═══════════════════════════════════════════════════════════════

EVERY response MUST be EXACTLY 3 lines:

Thought: [one sentence about what you need]
Action: [ChromaQuery OR PostgresQuery OR RelevanceScore]
Action Input: [the exact input]

STOP IMMEDIATELY after Action Input. NO additional text.

FINAL ANSWER FORMAT:
When analysis complete, return JSON array with ALL signatures:

[
  {
    "signature_id": 1000010,
    "severity": "CRITICAL",
    "reasoning": ["reason1", "reason2", "reason3"]
  },
  {
    "signature_id": 1000020,
    "severity": "LOW",
    "reasoning": ["reason1", "reason2"]
  }
]

═══════════════════════════════════════════════════════════════
ANALYSIS WORKFLOW
═══════════════════════════════════════════════════════════════

STEP 1: Call RelevanceScore ONCE with ALL signatures from <signature_mapping>
STEP 2: For non-false-positives, query PostgreSQL for historical patterns
STEP 3: If still unclear, use ChromaQuery for payload analysis
STEP 4: Provide Final Answer with ALL signatures assessed

═══════════════════════════════════════════════════════════════
EXAMPLE
═══════════════════════════════════════════════════════════════

USER: Analyze batch with signatures 1000010, 1000020

ASSISTANT:
Thought: I need to check tech-stack relevance for all signatures
Action: RelevanceScore
Action Input: {"1000010": "SQL Injection - UNION", "1000020": "Port Scan"}

[STOP - wait for observation]

USER: Observation: {"1000010": "critical", "1000020": "low"}

ASSISTANT:
Thought: I need historical data for the critical signature
Action: PostgresQuery
Action Input: SELECT * FROM alert_batches WHERE signature_id = 1000010 LIMIT 50

[STOP - wait for observation]

USER: Observation: [...]

ASSISTANT:
Final Answer: [
  {"signature_id": 1000010, "severity": "CRITICAL", "reasoning": ["Tech match", "Persistent IP", "300% increase"]},
  {"signature_id": 1000020, "severity": "LOW", "reasoning": ["Generic scan", "No persistence"]}
]
"""

    prompt_template = f"""Analyze this security alert batch:

═══════════════════════════════════════════════════════════════
BATCH DETAILS
═══════════════════════════════════════════════════════════════

{batch_summary_str}

═══════════════════════════════════════════════════════════════
SIGNATURE MAPPING (USE THESE EXACT DESCRIPTIONS)
═══════════════════════════════════════════════════════════════

<signature_mapping>
{signature_mapping_str}
</signature_mapping>

Signature IDs to analyze: {signature_ids_str}

Begin analysis. Remember:
1. Use RelevanceScore FIRST with exact descriptions from <signature_mapping>
2. ONE action per response
3. STOP after Action Input
4. Final Answer must cover ALL {len(set(signature_ids))} signatures

Start now:"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt_template}
    ]

    # ============================================================
    # FIX 2: Track which signatures have been assessed
    # ============================================================
    relevance_checked = False
    assessed_signatures = set()

    for i in range(max_iterations):
        if i > 0 and i % 3 == 0:
            summary = create_summary(messages)
            messages = messages[:-6] + [{"role": "user", "content": summary}]

        messages = trim_messages(messages, max_messages=8)
        
        response = llm.invoke(messages)
        content = response.content

        # ============================================================
        # FIX 3: Aggressive content cleaning
        # ============================================================
        if "Observation:" in content:
            content = content.split("Observation:")[0].strip()
        if "\n\n" in content:
            content = content.split("\n\n")[0].strip()
        
        print(f"\n{'='*60}")
        print(f"ITERATION {i+1}")
        print(f"{'='*60}")
        print(content)

        # Check for final answer
        if "Final Answer:" in content:
            final = content.split("Final Answer:")[-1].strip()
            final = final.strip('`').strip()
            if final.startswith('json'):
                final = final[4:].strip()
            
            # ============================================================
            # FIX 4: Validate final answer covers all signatures
            # ============================================================
            try:
                final_json = json.loads(final)
                if isinstance(final_json, dict):
                    final_json = [final_json]
                
                covered_sigs = {item['signature_id'] for item in final_json}
                missing_sigs = set(signature_ids) - covered_sigs
                
                if missing_sigs:
                    print(f"⚠️ Missing signatures in final answer: {missing_sigs}")
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": f"ERROR: You must provide assessments for ALL signatures: {missing_sigs}"})
                    continue
                
                return final
            except json.JSONDecodeError:
                print(f"⚠️ Invalid JSON in final answer")
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "ERROR: Final Answer must be valid JSON"})
                continue
        
        # Parse action
        action_match = re.search(r'Action:\s*(ChromaQuery|PostgresQuery|RelevanceScore)', content, re.IGNORECASE)
        input_match = re.search(r'Action Input:\s*(.+?)(?=\n|$)', content, re.DOTALL | re.IGNORECASE)

        if action_match and input_match:
            tool_name = action_match.group(1)
            raw_input = input_match.group(1).strip()
            
            # Remove quotes
            if (raw_input.startswith('"') and raw_input.endswith('"')) or \
               (raw_input.startswith("'") and raw_input.endswith("'")):
                tool_input = raw_input[1:-1]
            else:
                tool_input = raw_input
            
            # ============================================================
            # FIX 5: Strict RelevanceScore validation
            # ============================================================
            if tool_name == "RelevanceScore":
                if relevance_checked:
                    print(f"\n⚠️ RelevanceScore already called! Skipping...")
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": "ERROR: You already called RelevanceScore. Use the previous results."})
                    continue
                
                try:
                    parsed = json.loads(tool_input) if '"' in tool_input else ast.literal_eval(tool_input)
                    
                    if not isinstance(parsed, dict):
                        raise TypeError(f"Expected dict, got {type(parsed).__name__}")
                    
                    # Validate signatures match the mapping
                    for sig_id, description in parsed.items():
                        if str(sig_id) not in signature_mapping:
                            raise ValueError(f"Unknown signature_id: {sig_id}")
                        if description != signature_mapping[str(sig_id)]:
                            raise ValueError(f"Description mismatch for {sig_id}: got '{description}', expected '{signature_mapping[str(sig_id)]}'")
                    
                    normalized_dict = {str(k): str(v) for k, v in parsed.items()}
                    tool_input = normalized_dict
                    tool_input_for_hash = json.dumps(normalized_dict, sort_keys=True)
                    relevance_checked = True
                    
                except (json.JSONDecodeError, ValueError, SyntaxError, TypeError) as e:
                    print(f"\n❌ RelevanceScore validation error: {e}")
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": f"ERROR: {e}\nUse exact descriptions from <signature_mapping>"})
                    continue
            else:
                tool_input_for_hash = tool_input
            
            # Check duplicates
            query_hash = f"{tool_name}:{tool_input_for_hash if isinstance(tool_input, dict) else tool_input}"
            if query_hash in executed_queries:
                print(f"\n⚠️ Duplicate query detected!")
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "ERROR: You already ran that query. Analyze existing data or try different query."})
                continue

            executed_queries.add(query_hash)

            # Execute tool
            try:
                observation = execute_tool(tool_name, tool_input)
                if 'Postgres' in tool_name:
                    data_collected['postgres'] = observation
                elif 'Chroma' in tool_name:
                    data_collected['chroma'] = observation
                elif 'RelevanceScore' in tool_name:
                    data_collected["relevance"] = observation
                
                obs_text = f"Observation: {json.dumps(observation, indent=2) if isinstance(observation, (dict, list)) else str(observation)}"
                
                # Force conclusion if approaching limit
                if i >= (max_iterations - 3):
                    obs_text += f"\n\n⚠️ CRITICAL: Only {max_iterations - i} actions remaining. You MUST provide Final Answer covering ALL {len(set(signature_ids))} signatures NOW."
                    
            except Exception as e:
                obs_text = f"Observation: ERROR - {str(e)}"
                print(f"❌ Tool execution failed: {e}")
            
            print(f"\n{obs_text[:500]}...")
            
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": obs_text})
        else:
            print("\n⚠️ Invalid format detected")
            messages.append({"role": "assistant", "content": content})
            messages.append({
                "role": "user",
                "content": "ERROR: Invalid format. Use:\nThought: [reasoning]\nAction: [tool]\nAction Input: [input]\n\nSTOP after Action Input."
            })
    
    # Force final answer
    print("\n⚠️ Max iterations reached")
    force_final = f"""CRITICAL: Max iterations reached.

You MUST provide Final Answer NOW covering ALL {len(set(signature_ids))} signatures: {signature_ids_str}

Format:
[
  {{"signature_id": X, "severity": "...", "reasoning": ["...", "...", "..."]}},
  ...
]
"""
    messages.append({"role": "user", "content": force_final})
    response = llm.invoke(messages)

    if "Final Answer:" in response.content:
        final = response.content.split("Final Answer:")[-1].strip()
        final = final.strip('`').strip()
        if final.startswith('json'):
            final = final[4:].strip()
        return final
    
    # Fallback: construct answer from collected data
    return json.dumps([{
        "signature_id": sig_id,
        "severity": "UNKNOWN",
        "reasoning": ["Analysis incomplete - max iterations reached"]
    } for sig_id in set(signature_ids)])

def trim_messages(messages, max_messages=10):
    """Keep system prompt + last N user/assistant pairs"""
    if len(messages) <= max_messages + 1:  # +1 for system prompt
        return messages
    
    # Always keep system prompt (first message)
    system_msg = messages[0]
    
    # Keep only last N messages
    recent_messages = messages[-(max_messages):]
    
    return [system_msg] + recent_messages

def create_summary(messages):
    """Summarize last 3 tool executions"""
    recent = messages[-6:]  # Last 3 action/observation pairs
    
    summary = "Summary of recent actions:\n"
    for msg in recent:
        if "Action:" in msg.get("content", ""):
            action = msg["content"].split("Action:")[1].split("\n")[0].strip()
            summary += f"- Executed {action}\n"
    
    return summary

