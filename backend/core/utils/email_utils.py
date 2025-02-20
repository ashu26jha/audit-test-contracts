import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import settings
from core.utils.errors import ConfigurationError, EnvironmentError
from core.utils.logger import logger

# Email configuration
smtp_server = settings.SMTP_SERVER
smtp_port = settings.SMTP_PORT
smtp_username = settings.SMTP_USERNAME
smtp_password = settings.SMTP_PASSWORD

if not all([smtp_server, smtp_port, smtp_username, smtp_password]):
    raise ConfigurationError(
        "Missing SMTP configuration",
        details={
            "missing_fields": [
                field
                for field, value in {
                    "SMTP_SERVER": smtp_server,
                    "SMTP_PORT": smtp_port,
                    "SMTP_USERNAME": smtp_username,
                    "SMTP_PASSWORD": smtp_password,
                }.items()
                if not value
            ]
        },
    )


async def send_pdf_email(to_email: str, pdf_path: str, scan_id: str):
    """
    Send the generated PDF as an email attachment.

    Args:
        to_email: The recipient's email address
        pdf_path: Path to the PDF file to attach
        scan_id: The ID of the scan

    Raises:
        EnvironmentError: If the PDF file is not found or if there are SMTP connection issues
    """
    # Skip sending emails when running the benchmark
    if to_email == "audit-agent-benchmark@example.com":
        return

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = smtp_username
    msg["To"] = to_email
    msg["Subject"] = f"Scan Results - Scan ID: {scan_id}"

    # Email body
    body = f"""
Thank you for using AuditAgent. We are pleased to provide you with the results of your recent scan.

Scan ID: {scan_id}

The detailed scan results are attached to this email as a PDF file. Please review the document carefully for a comprehensive analysis of the scan.

If you have any questions about the results or need further clarification, don't hesitate to reply to this email.

We appreciate your trust in our services and look forward to assisting you with any future scanning needs.

Best regards,
AuditAgent Team"""
    msg.attach(MIMEText(body, "plain"))

    # Check if the file exists
    if not os.path.exists(pdf_path):
        raise EnvironmentError(
            f"PDF file not found at {pdf_path}", details={"pdf_path": pdf_path, "scan_id": scan_id}
        )

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
    except smtplib.SMTPException as e:
        raise EnvironmentError(
            "Failed to send email",
            details={"error": str(e), "to_email": to_email, "scan_id": scan_id},
        ) from e


async def send_error_email(to_email: str, scan_number: int):
    """
    Send an email with the error message.

    Args:
        to_email: The recipient's email address
        scan_number: The scan number that failed

    Raises:
        EnvironmentError: If there are SMTP connection issues
    """
    # Skip sending emails when running the benchmark
    if to_email == "audit-agent-benchmark@example.com":
        return

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = smtp_username
    msg["To"] = to_email
    msg["Subject"] = f"Scan ID {scan_number} Failed!"

    # Email body
    body = f"""
Hello,

We regret to inform you that your scan (ID: {scan_number}) has encountered an error and could not be completed successfully.

You can try scanning one more time from your AuditAgent dashboard.

If the issue persists after retrying, please contact our support team for assistance.

We apologize for any inconvenience caused.

Best regards,
AuditAgent Team"""

    msg.attach(MIMEText(body, "plain"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Error email sent successfully to {to_email}")
    except smtplib.SMTPException as e:
        raise EnvironmentError(
            "Failed to send error notification email",
            details={"error": str(e), "to_email": to_email, "scan_number": scan_number},
        ) from e


async def send_failed_refund_email(user_id: str, scan_id: str):
    """
    Send a monitoring email to the team when a credit refund failed.

    Args:
        user_id: The ID of the user whose refund failed
        scan_id: The ID of the scan that failed to refund

    Raises:
        EnvironmentError: If there are SMTP connection issues
    """
    team_email = settings.SMTP_USERNAME

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = smtp_username
    msg["To"] = team_email
    msg["Subject"] = f"Refund failed for Scan ID {scan_id}!"

    # Email body
    body = f"""
Hello AuditAgent Team,

A credit refund failed for the following Scan ID:

Scan ID: {scan_id}
User ID: {user_id}

Please investigate and manually refund the credit if needed.

Best regards,
AuditAgent Team"""

    msg.attach(MIMEText(body, "plain"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        logger.info(f"Monitoring email sent successfully to {team_email}")
    except smtplib.SMTPException as e:
        raise EnvironmentError(
            "Failed to send refund failure notification email",
            details={"error": str(e), "user_id": user_id, "scan_id": scan_id},
        )
