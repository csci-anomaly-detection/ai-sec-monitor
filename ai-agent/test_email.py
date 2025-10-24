# test_email.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_email_connection():
    # Get credentials from .env
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')
    recipient_email = os.getenv('RECIPIENT_EMAIL')
    
    print(f"Testing email connection...")
    print(f"Server: {smtp_server}:{smtp_port}")
    print(f"From: {sender_email}")
    print(f"To: {recipient_email}")
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = "Test Email - AI Security Monitor"
        
        body = "This is a test email from your AI Security Monitor system. If you received this, your email configuration is working!"
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect and send
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        
        print("Success! Email sent successfully.")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_email_connection()