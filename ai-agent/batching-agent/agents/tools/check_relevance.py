import os
from langchain_ollama import ChatOllama
import json

port = os.getenv("OLLAMA_PORT", "11434")
llm = ChatOllama(
    model="deepseek-r1:7b",
    base_url=f"http://ollama:{port}",
    temperature=0,
)


def check_vulnerability_relevance(signature_map: dict) -> dict:
    """
    Accepts a dict of signature_id: signature_string.
    Returns a dict of signature_id: score.
    """
    if not isinstance(signature_map, dict):
        print(f"❌ ERROR: Expected dict, got {type(signature_map)}")
        print(f"Received: {signature_map}")
        return {"error": f"Expected dict, got {type(signature_map).__name__}"}
    
    filepath = "/app/logs/server_profile.json"
    with open(filepath, "r") as f:
        server_details = json.load(f)
    
    results = {}
    for signature_id, signature in signature_map.items():
        if isinstance(signature_id, str):
            signature_id = int(signature_id)
        
        # Build prompt using string concatenation to avoid f-string issues
        prompt = (
            "YOU ARE A RATIONAL VULNERABILITY RELEVANCE DETECTOR AGENT.\n\n"
            "INPUTS:\n"
            f"- signature_id: {signature_id}\n"
            f"- signature: {signature}\n"
            "- server_profile: " + json.dumps(server_details) + "\n\n"
            "YOUR JOB IS TO COMPARE THE ALERT WITH SERVER PROFILE AND ASSIGN A RELEVANCE SCORE FROM BELOW CHOICES:\n\n"
            "- false_positive: The alert does not affect our server at all. Common reasons include:\n"
            "  * Server does not use the vulnerable technology (e.g., MongoDB injection alert but server uses MySQL)\n"
            "  * Attack targets wrong platform (e.g., Windows-specific exploit against Linux server)\n"
            "  * Attack targets non-existent service (e.g., SSH brute force but SSH is not running)\n"
            "  * Protocol mismatch (e.g., SMTP attack but no mail server present)\n"
            "  * Known legitimate traffic misidentified as attack (e.g., security scanner, monitoring tools)\n\n"
            "- low: Alert is technically relevant but poses minimal actual risk because:\n"
            "  * Vulnerability exists but is not exploitable due to other security controls (e.g., WAF, input validation)\n"
            "  * Attack signature matches but payload is malformed/incomplete\n"
            "  * Targeted component exists but is not exposed or accessible\n"
            "  * Attack requires preconditions that are not met (e.g., needs authentication but has no credentials)\n"
            "  * Version-specific exploit against patched/different version\n\n"
            "- medium: Alert represents a genuine threat that requires investigation because:\n"
            "  * Vulnerability exists and is theoretically exploitable\n"
            "  * Attack payload is well-formed and targets correct technology stack\n"
            "  * No confirmed protective controls in place\n"
            "  * Single attack attempt that may be reconnaissance or testing\n"
            "  * Attack could succeed with additional attempts or refinement\n\n"
            "- high: Alert indicates serious attack activity that demands immediate attention because:\n"
            "  * Multiple coordinated attempts detected (indicates determined attacker)\n"
            "  * Attack targets known critical vulnerability in the stack\n"
            "  * Payload sophistication suggests skilled attacker or automated tool\n"
            "  * Part of observable multi-stage attack pattern\n"
            "  * Attack vector has direct path to sensitive data or system compromise\n\n"
            "- critical: Alert represents active exploitation or imminent breach requiring emergency response because:\n"
            "  * Attack successfully exploited vulnerability (evidence of success in response data)\n"
            "  * Multiple attack vectors being used simultaneously\n"
            "  * Attack is part of confirmed kill chain (reconnaissance → exploitation → post-exploitation)\n"
            "  * Automated tool actively probing all endpoints\n"
            "  * Attack targets internet-facing production system with sensitive data\n"
            "  * Indicators match known APT/threat actor TTPs\n\n"
            "DECISION PROCESS:\n"
            "1. Technology Stack Match: Does the attack target technology actually present in server_profile?\n"
            "2. Version Compatibility: Is the server running a vulnerable version?\n"
            "3. Service Availability: Is the targeted service/port actually exposed?\n"
            "4. Exploitability: Could this attack realistically succeed given current configuration?\n"
            "5. Impact Assessment: What would happen if the attack succeeds?\n\n"
            "CRITICAL RULES:\n"
            "- ONLY TYPE OF RESPONSE EXPECTED FROM YOU IS A JSON WITH THE FIELD score\n"
            "- PLEASE ADHERE TO THE EXPECTED RESPONSE FORMAT, OTHER TYPE OF RESPONSES WILL NOT BE TOLERATED.\n"
            "- ALWAYS check technology stack compatibility first.\n"
            "- Be conservative: if unsure, choose higher severity (better false alarm than missed attack).\n\n"
            "OUTPUT FORMAT (JSON only):\n"
            '{"score": "false_positive|low|medium|high|critical"}'
        )
        
        response = llm.invoke(prompt)
        try:
            # Extract JSON from response
            content = response.content.strip()
            # Remove markdown code blocks if present
            if content.startswith('```'):
                content = content.split('```')[1]
                if content.startswith('json'):
                    content = content[4:]
            
            score_json = json.loads(content.strip())
            results[signature_id] = score_json.get("score", "unknown")
        except Exception as e:
            print(f"❌ Failed to parse response for {signature_id}: {e}")
            print(f"Response was: {response.content[:200]}")
            results[signature_id] = "error"
    
    return results

# Example usage:
# sig_map = {1000010: "SQL Injection Attempt - UNION", 1000020: "MongoDB NoSQL Injection Attempt"}
# print(check_vulnerability_relevance(sig_map))