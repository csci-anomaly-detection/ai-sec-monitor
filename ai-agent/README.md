# AI Security Monitor - Email Notification System

## Overview

This AI-powered security monitoring system analyzes threats from security logs and automatically sends email alerts for CRITICAL severity threats.

## Features

- **Threat Analysis**: Uses LLM (Ollama) to provide detailed analysis of security threats
- **File I/O**: Reads JSON threat data and saves analysis reports (TXT and JSON formats)
- **Email Notifications**: Automatically sends professional HTML email alerts for CRITICAL threats
- **Comprehensive Logging**: Tracks all analysis and email notification attempts

## Components

### 1. `file_reader.py`
Reads threat data from `sample_response.json`

### 2. `agents.py`
LLM-powered threat analysis with error handling and retries

### 3. `file_writer.py`
Saves analysis results to:
- Text files (`analysis_output/*.txt`)
- JSON files (`analysis_output/*.json`)

### 4. `email_agent.py`
Professional email notification system with:
- HTML formatted emails with color-coded severity levels
- Plain text fallback for older email clients
- Comprehensive error handling
- Configuration via `.env` file

### 5. `main.py`
Main pipeline that orchestrates:
- Reading threat data
- LLM analysis
- File storage
- Email notifications for CRITICAL threats
- Summary reporting

## Setup

### 1. Install Dependencies

```bash
cd ai-agent
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install python-dotenv ollama
```

### 2. Configure Email Settings

Copy the example environment file and configure it:

```bash
cp .env.example .env
```

Then edit `.env` with your actual values:

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your-email@gmail.com
SENDER_PASSWORD=your-app-password
RECIPIENT_EMAIL=it-staff@company.com
```

**Note**: For Gmail, you need to:
1. Enable 2-Factor Authentication
2. Generate an App Password at https://myaccount.google.com/apppasswords
3. Use the App Password (not your regular password) in the `.env` file

### 3. Run Ollama

Make sure Ollama is running with the `llama3.1:latest` model:

```bash
ollama pull llama3.1:latest
ollama serve
```

## Usage

Run the main pipeline:

```bash
cd ai-agent
source venv/bin/activate
python main.py
```

The system will:
1. Read threats from `sample_response.json`
2. Analyze each threat with AI
3. Save analysis reports to `analysis_output/`
4. Send email alerts for any CRITICAL severity threats
5. Display a summary of all actions taken

## Email Alert Behavior

- **CRITICAL severity**: Email alert sent immediately
- **HIGH, MEDIUM, LOW severity**: No email sent (logged only)
- **Email failures**: Pipeline continues, failure logged in summary

## Testing

### Test Individual Components

```bash
# Test email configuration
python email_agent.py

# Test file reading
python file_reader.py

# Test LLM analysis
python agents.py
```

### Test Full Pipeline

The `sample_response.json` includes test threats at different severity levels to verify the system works correctly.

## Output

### Analysis Files
Saved in `analysis_output/`:
- `threat_analysis_{ip}_{timestamp}.txt` - Human-readable report
- `threat_analysis_{ip}_{timestamp}.json` - Machine-readable data

### Email Alerts
Sent to configured recipient with:
- Color-coded severity badge
- Threat details table
- AI analysis
- Recommended actions
- Professional formatting

## Security

- Email credentials stored in `.env` (gitignored)
- No sensitive data in code repository
- App passwords used instead of account passwords
- TLS encryption for email transmission

## Future Enhancements

- Rate limiting for email notifications
- Multiple recipient support
- Email templates for different threat types
- Notification history database
- Webhook integrations
- Dashboard UI

## Troubleshooting

### Email Not Sending

1. Check `.env` file exists and has correct values
2. Verify SMTP credentials (use App Password for Gmail)
3. Test with `python email_agent.py`
4. Check firewall/network allows SMTP on port 587

### LLM Analysis Fails

1. Ensure Ollama is running: `ollama serve`
2. Check model is installed: `ollama list`
3. Pull model if needed: `ollama pull llama3.1:latest`

### No Threats Detected

1. Check `sample_response.json` format
2. Verify `threats_detected` array has items
3. Ensure severity field is set correctly

