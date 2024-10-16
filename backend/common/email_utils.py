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
    smtp_port = settings.SMTP_PORT
    smtp_username = settings.SMTP_USERNAME
    smtp_password = settings.SMTP_PASSWORD
    cc_email = settings.CC_EMAIL if settings.CC_EMAIL else None

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = smtp_username
    if cc_email is not None:
        msg["Cc"] = cc_email
    msg["To"] = to_email
    msg["Subject"] = f"Scan Results - Scan ID: {scan_id}"

    # Email body
    body = f"""
Thank you for using Audit Agent. We are pleased to provide you with the results of your recent scan.

Scan ID: {scan_id}

The detailed scan results are attached to this email as a PDF file. Please review the document carefully for a comprehensive analysis of the scan.

If you have any questions about the results or need further clarification, please don't hesitate to contact us at {cc_email}

We appreciate your trust in our services and look forward to assisting you with any future scanning needs.

Best regards,
Audit Agent Team"""
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
        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
