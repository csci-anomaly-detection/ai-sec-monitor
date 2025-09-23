# AI Agent Documentation

## Overview
The AI Agent is a modular system designed to preprocess, process, and postprocess data using AI models. It is structured to allow flexibility and customization for various use cases.

---

## Folder Structure

### Root Directory
- **`audit.json`**: Logs and tracks the audit trail of the AI agent's operations.
- **`main.py`**: The entry point for running the AI agent.
- **`test_runs.txt`**: Contains logs or notes from test runs of the AI agent.

### `ai/` Directory
- **`ai_agent.py`**: Core logic for the AI agent, including model inference and decision-making.
- **`preprocess.py`**: Handles data preprocessing tasks such as cleaning, normalization, and feature extraction.
- **`postprocess.py`**: Handles data postprocessing tasks such as formatting results and generating outputs.
- **`__pycache__/`**: Stores compiled Python files for faster execution.

### `prompts/` Directory
- **`prompt.j2`**: A Jinja2 template file for dynamically generating prompts for the AI model.

---

## How to Use

### Running the AI Agent
1. Ensure ollama and all dependencies are installed.
2. Run the `main.py` file to execute the AI agent:
   ```bash
   python main.py
   ```

### Configuration
- Modify the fake logs in `audit.json` to customize logging behavior.
- Update `prompt.j2` to change the AI model's prompt structure.

### Testing
- Use `test_runs.txt` to document test cases and results.

---

## Key Components

### Preprocessing
- **File**: `preprocess.py`
- **Purpose**: Prepares raw data for AI model consumption.
- **Example Tasks**:
  - Data cleaning
  - Feature extraction

### Core AI Logic
- **File**: `ai_agent.py`
- **Purpose**: Implements the main AI model logic.
- **Example Tasks**:
  - Model inference
  - Decision-making

### Postprocessing
- **File**: `postprocess.py`
- **Purpose**: Processes the AI model's output for end-user consumption.
- **Example Tasks**:
  - Formatting results
  - Generating reports

## Future Improvements
 - Add more robust error handling.
 - Trigger ai-generated alerts when detection systems picks up alerts.
 - Introduce rate-limits/time-window to avoid overwhelming the model and hardware.
 - Integrate and Fine Tune additional AI models for broader use cases.
 - Connect email/slack api to send llm responses.


