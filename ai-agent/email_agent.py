import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from datetime import datetime
import markdown


def load_email_config():
    """
    Load email configuration from .env file.
    
    Returns:
        dict: Configuration dictionary with email settings
        
    Raises:
        ValueError: If any required setting is missing
    """
    load_dotenv()
    
    # Required environment variables
    required_vars = {
        'SMTP_SERVER': 'server',
        'SMTP_PORT': 'port',
        'SENDER_EMAIL': 'sender',
        'SENDER_PASSWORD': 'password',
        'RECIPIENT_EMAIL': 'recipient'
    }
    
    config = {}
    
    # Load and validate each setting
    for env_var, config_key in required_vars.items():
        value = os.getenv(env_var)
        
        if not value:
            raise ValueError(f"Missing required environment variable: {env_var}")
        
        # Convert port to integer
        if env_var == 'SMTP_PORT':
            try:
                value = int(value)
            except ValueError:
                raise ValueError(f"SMTP_PORT must be a number, got: {value}")
        
        config[config_key] = value
    
    return config


def format_alert_email(threat_data, analysis_text):
    """
    Format a professional security alert email with HTML.
    
    Args:
        threat_data: Dictionary with threat information
        analysis_text: String containing LLM analysis
        
    Returns:
        tuple: (subject, html_body, plain_body) for the email
    """
    # Get current timestamp in readable format
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    
    # Extract threat data with defaults
    ip = threat_data.get('ip', 'Unknown')
    attack_type = threat_data.get('attack_type', 'Unknown Attack')
    severity = threat_data.get('severity', 'UNKNOWN')
    total_events = threat_data.get('total_events', 0)
    recommendation = threat_data.get('recommendation', 'Review and assess')
    
    # Create subject line
    subject = f"CRITICAL SECURITY ALERT: {attack_type} from {ip}"
    
    # Severity color mapping
    severity_colors = {
        'CRITICAL': '#DC2626',
        'HIGH': '#EA580C',
        'MEDIUM': '#F59E0B',
        'LOW': '#84CC16'
    }
    severity_color = severity_colors.get(severity, '#6B7280')
    
    # Convert markdown analysis to HTML
    analysis_html = markdown.markdown(
        analysis_text,
        extensions=['nl2br', 'fenced_code', 'tables']
    )
    
    # HTML email body
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* Markdown content styling */
        .analysis-content h1, .analysis-content h2, .analysis-content h3 {{
            color: #1F2937;
            margin: 15px 0 10px 0;
            font-weight: 600;
        }}
        .analysis-content h1 {{ font-size: 18px; }}
        .analysis-content h2 {{ font-size: 16px; }}
        .analysis-content h3 {{ font-size: 14px; }}
        .analysis-content p {{
            margin: 8px 0;
            color: #374151;
        }}
        .analysis-content strong {{
            color: #1F2937;
            font-weight: 700;
        }}
        .analysis-content ul, .analysis-content ol {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .analysis-content li {{
            margin: 5px 0;
            color: #374151;
        }}
        .analysis-content code {{
            background-color: #F3F4F6;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #F3F4F6;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #F3F4F6; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, {severity_color} 0%, #1F2937 100%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #FFFFFF; font-size: 24px; font-weight: 700;">SECURITY ALERT</h1>
                            <p style="margin: 10px 0 0 0; color: #F3F4F6; font-size: 14px;">{timestamp}</p>
                        </td>
                    </tr>
                    
                    <!-- Severity Badge -->
                    <tr>
                        <td style="padding: 20px; text-align: center; background-color: #FEF2F2;">
                            <span style="display: inline-block; background-color: {severity_color}; color: #FFFFFF; padding: 8px 20px; border-radius: 20px; font-weight: 700; font-size: 16px;">
                                {severity} SEVERITY
                            </span>
                        </td>
                    </tr>
                    
                    <!-- Threat Summary -->
                    <tr>
                        <td style="padding: 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1F2937; font-size: 20px; border-bottom: 2px solid #E5E7EB; padding-bottom: 10px;">
                                Threat Details
                            </h2>
                            
                            <table width="100%" cellpadding="8" cellspacing="0" style="border-collapse: collapse;">
                                <tr style="background-color: #F9FAFB;">
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; font-weight: 600; color: #374151; width: 35%;">
                                        IP Address
                                    </td>
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; color: #1F2937; font-family: 'Courier New', monospace;">
                                        {ip}
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; font-weight: 600; color: #374151;">
                                        Attack Type
                                    </td>
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; color: #1F2937;">
                                        {attack_type}
                                    </td>
                                </tr>
                                <tr style="background-color: #F9FAFB;">
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; font-weight: 600; color: #374151;">
                                        Total Events
                                    </td>
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; color: #1F2937; font-weight: 700;">
                                        {total_events}
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; font-weight: 600; color: #374151;">
                                        Recommended Action
                                    </td>
                                    <td style="padding: 12px; border: 1px solid #E5E7EB; color: #DC2626; font-weight: 600;">
                                        {recommendation}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- AI Analysis -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="margin: 0 0 15px 0; color: #1F2937; font-size: 20px; border-bottom: 2px solid #E5E7EB; padding-bottom: 10px;">
                                AI Analysis
                            </h2>
                            <div class="analysis-content" style="background-color: #F9FAFB; padding: 20px; border-left: 4px solid #3B82F6; border-radius: 4px; color: #1F2937; line-height: 1.6;">
                                {analysis_html}
                            </div>
                        </td>
                    </tr>
                    
                    <!-- Action Required -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <div style="background-color: #FEF2F2; border: 2px solid {severity_color}; border-radius: 8px; padding: 20px;">
                                <h3 style="margin: 0 0 10px 0; color: {severity_color}; font-size: 18px;">
                                    Immediate Action Required
                                </h3>
                                <p style="margin: 0; color: #1F2937; line-height: 1.6;">
                                    This is a <strong>{severity}</strong> severity threat that requires immediate attention. 
                                    Please review the AI analysis above and take the recommended actions without delay.
                                </p>
                            </div>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #F9FAFB; padding: 20px; text-align: center; border-top: 1px solid #E5E7EB;">
                            <p style="margin: 0; color: #6B7280; font-size: 12px;">
                                AI Security Monitor System - Automated Alert<br>
                                Generated: {timestamp}
                            </p>
                        </td>
                    </tr>
                    
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    
    # Plain text fallback
    plain_body = f"""
CRITICAL SECURITY ALERT
{timestamp}

SEVERITY: {severity}

THREAT DETAILS:
IP Address: {ip}
Attack Type: {attack_type}
Total Events: {total_events}
Recommended Action: {recommendation}

AI ANALYSIS:
{analysis_text}

IMMEDIATE ACTION REQUIRED:
This is a {severity} severity threat that requires immediate attention.
Please review the AI analysis above and take the recommended actions.

---
AI Security Monitor System - Automated Alert
Generated: {timestamp}
"""
    
    return subject, html_body, plain_body


def send_critical_alert(threat_data, analysis_text):
    """
    Send a critical security alert email with HTML formatting.
    
    Args:
        threat_data: Dictionary with threat information
        analysis_text: String containing LLM analysis
        
    Returns:
        dict: Result with 'success', 'message', and 'timestamp'
    """
    timestamp = datetime.now().isoformat()
    
    try:
        # Load configuration
        config = load_email_config()
        
        # Format the email
        subject, html_body, plain_body = format_alert_email(threat_data, analysis_text)
        
        # Create multipart message (HTML + plain text fallback)
        msg = MIMEMultipart('alternative')
        msg['From'] = config['sender']
        msg['To'] = config['recipient']
        msg['Subject'] = subject
        
        # Attach both plain and HTML versions
        # Email clients will prefer HTML if they support it
        part1 = MIMEText(plain_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        
        msg.attach(part1)
        msg.attach(part2)
        
        # Connect and send
        server = smtplib.SMTP(config['server'], config['port'])
        server.starttls()
        server.login(config['sender'], config['password'])
        
        text = msg.as_string()
        server.sendmail(config['sender'], config['recipient'], text)
        server.quit()
        
        return {
            'success': True,
            'message': f"Alert email sent successfully to {config['recipient']}",
            'timestamp': timestamp
        }
        
    except ValueError as e:
        return {
            'success': False,
            'message': f"Configuration error: {e}",
            'timestamp': timestamp
        }
    
    except smtplib.SMTPAuthenticationError as e:
        return {
            'success': False,
            'message': f"Email authentication failed: {e}",
            'timestamp': timestamp
        }
    
    except smtplib.SMTPException as e:
        return {
            'success': False,
            'message': f"SMTP error: {e}",
            'timestamp': timestamp
        }
    
    except Exception as e:
        return {
            'success': False,
            'message': f"Unexpected error: {e}",
            'timestamp': timestamp
        }


if __name__ == "__main__":
    # Test 1: Configuration loading
    print("=" * 80)
    print("TEST 1: Email Configuration Loading")
    print("=" * 80)
    try:
        config = load_email_config()
        print("Configuration loaded successfully!")
        print(f"Server: {config['server']}:{config['port']}")
        print(f"Sender: {config['sender']}")
        print(f"Recipient: {config['recipient']}")
        print("Password: [HIDDEN]")
    except ValueError as e:
        print(f"Configuration error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    print()
    
    # Test 2: Email formatting
    print("=" * 80)
    print("TEST 2: Email Formatting")
    print("=" * 80)
    
    test_threat = {
        'ip': '192.168.1.100',
        'attack_type': 'SQL Injection Attack',
        'severity': 'CRITICAL',
        'total_events': 50,
        'recommendation': 'Block IP immediately and investigate database logs'
    }
    
    test_analysis = """This is a serious SQL injection attack attempt.

The attacker is probing for vulnerabilities in your database layer.
Immediate action is required to prevent data breach."""
    
    subject, html_body, plain_body = format_alert_email(test_threat, test_analysis)
    
    print("\nSUBJECT:")
    print(subject)
    print("\nPLAIN TEXT VERSION:")
    print(plain_body)
    print("\nHTML VERSION:")
    print("[HTML email generated - view in email client for full formatting]")
    
    print()
    
    # Test 3: Send actual email
    print("=" * 80)
    print("TEST 3: Send Critical Alert Email")
    print("=" * 80)
    
    response = input("\nDo you want to send a test email? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        print("\nSending test email...")
        result = send_critical_alert(test_threat, test_analysis)
        
        if result['success']:
            print(f"SUCCESS: {result['message']}")
            print(f"Sent at: {result['timestamp']}")
        else:
            print(f"FAILED: {result['message']}")
            print(f"Failed at: {result['timestamp']}")
    else:
        print("\nTest email skipped.")
