import json

# Required fields in LLM output
REQUIRED_FIELDS = ["summary", "severity", "confidence", "attack_technique", "rationale", "next_steps"]

# Severity mapping (optional: could be dynamic)
SEVERITY_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

def validate_and_enrich(output):
    if not output or "error" in output:
        raise ValueError(f"Invalid LLM output: {output}")
    severity = output.get("severity", "").lower()
    if severity not in SEVERITY_SCORE:
        severity = "medium"  # Default if unknown
    output["severity"] = severity
    output["severity_score"] = SEVERITY_SCORE[severity]

    # 3. Normalize confidence
    confidence = output.get("confidence")
    try:
        if confidence is not None:
            confidence = float(confidence)
        else:
            raise TypeError("Confidence is None")
        if confidence > 1:
            confidence = 1.0
        elif confidence < 0:
            confidence = 0.0
    except (TypeError, ValueError):
        confidence = 0.5  # Default if missing or invalid
    output["confidence"] = confidence

    # 5. Ensure next_steps is a list
    if not isinstance(output.get("next_steps"), list):
        output["next_steps"] = [str(output.get("next_steps"))] if output.get("next_steps") else []

    return output