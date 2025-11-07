import ollama
import time

def analyze_threat(threat_data, max_retries=2):
    """
    LLM agent - version 3
    With basic error handling
    """
    
    prompt = f"""You are a cybersecurity threat analyst. Analyze this threat and provide a structured assessment.

THREAT DATA:
- IP Address: {threat_data['ip']}
- Attack Type: {threat_data['attack_type']}
- Severity: {threat_data['severity']}
- Total Events: {threat_data['total_events']}
- Initial Recommendation: {threat_data.get('recommendation', 'Not provided')}

Please provide:

1. WHAT IS HAPPENING:
   Explain what the attacker is doing in 2-3 sentences.

2. WHY IT MATTERS:
   What's the actual risk? What could happen if not addressed?

3. IMMEDIATE ACTIONS:
   List 3 specific things to do right now.

4. CONFIDENCE LEVEL:
   Rate your confidence from 0 to 1 and briefly explain why.

Be specific and actionable."""
    
    # Try calling Ollama with retries
    for attempt in range(max_retries):
        try:
            response = ollama.chat(
                model='llama3.1:latest',
                messages=[
                    {'role': 'user', 'content': prompt}
                ]
            )
            
            return response['message']['content']
            
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2)
            else:
                # Return a basic fallback
                return f"""LLM Analysis Unavailable

Basic Assessment:
- Threat from IP: {threat_data['ip']}
- Type: {threat_data['attack_type']}
- Severity: {threat_data['severity']}
- Recommendation: {threat_data.get('recommendation', 'Manual review required')}

Note: Automated analysis failed. Please review manually."""

