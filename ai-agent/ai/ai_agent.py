import json
import jinja2
from langchain_ollama import OllamaLLM
from langchain_core.output_parsers import JsonOutputParser
from pathlib import Path

# Initialize DeepSeek via Ollama
llm = OllamaLLM(model="gemma3:4b")

# Load Jinja2 template
def load_template():
    template_path = Path(__file__).parent.parent / "prompts" / "prompt.j2"
    with open(template_path, "r") as f:
        return f.read()

# Generate prompt using your Jinja2 template
def build_prompt(logs, rule_name=None, rule_id=None, technique=None):
    template_str = load_template()
    template = jinja2.Template(template_str)
    return template.render(
        rule_name=rule_name or "N/A",
        rule_id=rule_id or "N/A",
        technique=technique or "N/A",
        logs=logs
    )

# Run DeepSeek inference
def run_ai_triage(logs, rule_name=None, rule_id=None, technique=None):
    prompt_str = build_prompt(logs, rule_name, rule_id, technique)

    parser = JsonOutputParser()

    try:
        raw_output = llm.invoke(prompt_str)
        if raw_output.startswith("<think>"):
            raw_output = raw_output.split("</think>")[-1].strip()

        json_output = parser.parse(raw_output)
        return json_output
    except Exception as e:
        return {
            "error": str(e),
            "raw_output": raw_output if "raw_output" in locals() else None
        }
