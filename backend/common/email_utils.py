import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from common import logger
from config import settings


async def send_pdf_email(to_email: str, pdf_path: str, scan_id: str):
    """
    Send the generated PDF as an email attachment.
    """
    # Email configuration
    smtp_server = settings.SMTP_SERVER
    smtp_port = settings.SMTP_PORT  # or the appropriate port for your SMTP server
    smtp_username = settings.SMTP_USERNAME
    smtp_password = settings.SMTP_PASSWORD

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = smtp_username
    msg["To"] = to_email
    msg["Subject"] = f"Scan Results - Scan ID: {scan_id}"

    # Email body
    body = f"Please find attached the scan results for Scan ID: {scan_id}"
    msg.attach(MIMEText(body, "plain"))

    # Check if the file exists
    if not os.path.exists(pdf_path):
        logger.error(f"Error: PDF file not found at {pdf_path}")
        return

    # Attach the PDF
    with open(pdf_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())

    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f"attachment; filename= {os.path.basename(pdf_path)}",
    )
    msg.attach(part)

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Error sending email: {str(e)}")
