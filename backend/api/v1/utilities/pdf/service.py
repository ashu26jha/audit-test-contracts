import asyncio
import html
import os
from pathlib import Path
from typing import Optional

import markdown
from fastapi import HTTPException
from markdown.extensions.attr_list import AttrListExtension
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.nl2br import Nl2BrExtension
from markdown.extensions.sane_lists import SaneListExtension
from pypdf import PdfReader, PdfWriter

from api.v1.utilities.pdf.helpers.pdf_generation import (
    create_finding_section,
    extract_organization_name,
    html_to_pdf,
    read_html,
)
from core.db.repositories.scan import ScanRepository
from core.models.user import User
from core.utils.email_utils import send_pdf_email
from core.utils.logger import logger
from core.utils.process_pool import get_process_pool
from core.utils.validate import validate_user_scan_access

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
TEMPLATE_DIR = BASE_DIR / "config" / "template"


async def generate_pdf_from_scan(user: Optional[User], scan_id: str, email: Optional[str] = None):
    """
    Generate a PDF report from the scan data and send it via email.
    Either user or email must be provided.

    Args:
        user: Optional user object. If provided, will validate scan ownership.
        scan_id: The ID of the scan to generate PDF for.
        email: Optional email address. Used when user object is not available.

    Raises:
        HTTPException: If validation fails or PDF generation fails.
    """
    try:
        if not user and not email:
            raise HTTPException(status_code=400, detail="User or email is required")

        # Only validate user access if a user is provided
        if user:
            await validate_user_scan_access(scan_id, user)
            recipient_email = user.email
        else:
            recipient_email = email

        if not recipient_email:
            raise HTTPException(
                status_code=400, detail="No email address available for PDF delivery"
            )

        scan = await ScanRepository.get_scan(scan_id)
        full_result = await ScanRepository.get_scan_result(scan_id)

        # Run PDF generation and email sending in a separate process with timeout
        async with get_process_pool() as pool:
            try:
                task = pool.run_in_process(
                    _generate_and_send_pdf,
                    full_result,
                    scan.repositoryName,
                    scan.branchName,
                    scan.commitHash,
                    scan.repositoryURL,
                    scan.contractFiles,
                    scan.linesOfCode.total_lines,
                    scan.scan_number,
                    scan_id,
                    recipient_email,
                )
                success = await asyncio.wait_for(task, timeout=300)  # 5 minutes timeout

                if not success:
                    raise HTTPException(
                        status_code=500, detail="Failed to generate and send PDF report"
                    )

            except asyncio.TimeoutError as e:
                logger.error(f"PDF generation and email sending timed out for scan ID: {scan_id}")
                raise HTTPException(status_code=500, detail="Operation timed out") from e

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during PDF generation and email sending: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to generate and send Audit Agent report"
        ) from e


async def generate_pdf_report(
    scan_result,
    repository_name: str,
    branch_name: str,
    commit_hash: str,
    repository_url: str,
    contract_files: list,
    lines_of_code: int,
    scan_number: int,
    scan_id: str,
) -> Path:
    """
    Generate a PDF report from scan data without any DB or email interactions.
    Returns the path to the generated PDF file.
    """
    try:
        report_data = {
            "summary": scan_result.summary,
            "repository_name": repository_name,
            "branch_name": branch_name,
            "commit_hash": commit_hash,
            "total_vulnerabilities": scan_result.total_findings,
            "total_lines_of_code": lines_of_code,
            "organization": extract_organization_name(repository_url),
            "contract_files": contract_files,
            "findings": _prepare_findings_data(scan_result.findings),
            "scan_id": scan_id,
            "scan_number": scan_number,
        }

        html_content = await _create_report_html(report_data)
        pdf_filename = f"audit_agent_report_{scan_number}.pdf"
        report_pdf_path = await _generate_pdf(html_content, pdf_filename)
        final_pdf_path = _combine_pdfs(report_pdf_path)

        # Cleanup the intermediate PDF
        os.remove(report_pdf_path)

        return final_pdf_path
    except Exception as e:
        logger.exception(f"Error during PDF report generation: {str(e)}")
        raise


async def _generate_and_send_pdf(
    scan_result,
    repository_name: str,
    branch_name: str,
    commit_hash: str,
    repository_url: str,
    contract_files: list,
    lines_of_code: int,
    scan_number: int,
    scan_id: str,
    user_email: str,
) -> bool:
    """
    Generate PDF and send email in one worker process.
    Returns True if successful, False otherwise.
    """
    try:
        # Generate the PDF
        final_pdf_path = await generate_pdf_report(
            scan_result,
            repository_name,
            branch_name,
            commit_hash,
            repository_url,
            contract_files,
            lines_of_code,
            scan_number,
            scan_id,
        )

        # Send the email
        await send_pdf_email(user_email, str(final_pdf_path), scan_id)

        # Cleanup
        os.remove(final_pdf_path)
        return True
    except Exception as e:
        logger.exception(f"Error during PDF generation and email sending: {str(e)}")
        return False


async def _generate_pdf(html_content: str, pdf_filename: str) -> Path:
    """
    Convert HTML content to PDF and handle temporary file cleanup.
    All files are created in and read from TEMPLATE_DIR for process safety.
    """
    # Ensure all paths are explicitly within TEMPLATE_DIR
    pdf_path = TEMPLATE_DIR / pdf_filename
    temp_html_path = TEMPLATE_DIR / f"temp_{pdf_filename}.html"

    try:
        # Write HTML to temporary file
        with open(temp_html_path, "w", encoding="utf-8") as file:
            file.write(html_content)

        # Convert to PDF
        await html_to_pdf(temp_html_path, pdf_path)
        return pdf_path
    finally:
        # Always cleanup temporary HTML file
        if temp_html_path.exists():
            os.remove(temp_html_path)


def _prepare_findings_data(findings):
    severity_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Info": 5,
        "Best Practices": 6,
    }

    severity_map = {
        "Critical": "chip1",
        "High": "chip2",
        "Medium": "chip3",
        "Low": "chip4",
        "Info": "chip5",
        "Best Practices": "chip6",
    }

    # Sort findings by severity using the defined severity order
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.Severity, 6))

    return [
        {
            "issue": finding.Issue,
            "severity": severity_map.get(finding.Severity, "chip6"),
            "contracts": finding.Contracts,
            "description": finding.Description,
        }
        for finding in sorted_findings
    ]


async def _create_report_html(report_data):
    template_path = TEMPLATE_DIR / "report_template.html"
    html_content = read_html(template_path)

    # Convert markdown summary to HTML with code highlighting and better list handling
    summary_html = markdown.markdown(
        report_data["summary"],
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, css_class="codehilite", pygments_style="default"),
            SaneListExtension(),
            Nl2BrExtension(),
            AttrListExtension(),
        ],
    )

    # Use a single placeholder replacement
    html_content = html_content.replace("<!--organization-->", str(report_data["organization"]))
    html_content = html_content.replace("<!--scanId-->", str(report_data["scan_number"]))
    html_content = html_content.replace("<!--repository-->", str(report_data["repository_name"]))
    html_content = html_content.replace("<!--branch-->", str(report_data["branch_name"]))
    html_content = html_content.replace("<!--commit_hash-->", str(report_data["commit_hash"]))
    html_content = html_content.replace(
        "<!--vulnerabilties_found-->", str(report_data["total_vulnerabilities"])
    )
    html_content = html_content.replace(
        "<!--Contracts_Scanned-->", str(len(report_data["contract_files"]))
    )
    html_content = html_content.replace("<!--LoC-->", str(report_data["total_lines_of_code"]))

    # Replace the summary placeholder with just the content, not wrapped in another div
    html_content = html_content.replace("<!--summary-->", summary_html)

    contract_files_html = _create_contract_files_html(report_data["contract_files"])
    html_content = html_content.replace("<!--contracts_files-->", contract_files_html)

    findings_html = _create_findings_html(report_data["findings"])
    html_content = html_content.replace("<!--findings-->", findings_html)

    return html_content


def _create_contract_files_html(contract_files):
    return "".join(
        f"""<span class="file-name">{html.escape(contract)}</span>""" for contract in contract_files
    )


def _create_findings_html(findings):
    # Initialize without any manual page breaks
    html = ""

    for index, finding in enumerate(findings):
        html += create_finding_section(
            index + 1,
            len(findings),
            finding["severity"],
            finding["issue"],
            finding["contracts"],
            finding["description"],
        )

    return html


def _combine_pdfs(report_pdf_path):
    cover_page_path = TEMPLATE_DIR / "cover_page.pdf"
    disclaimer_page_path = TEMPLATE_DIR / "disclaimer_page.pdf"
    final_pdf_path = report_pdf_path.with_name(f"final_{report_pdf_path.name}")

    pdf_writer = PdfWriter()

    # Add cover page
    cover_reader = PdfReader(str(cover_page_path))
    for page in cover_reader.pages:
        pdf_writer.add_page(page)

    # Add report pages
    report_reader = PdfReader(str(report_pdf_path))
    for page in report_reader.pages:
        pdf_writer.add_page(page)

    # Add disclaimer page at the end
    disclaimer_reader = PdfReader(str(disclaimer_page_path))
    for page in disclaimer_reader.pages:
        pdf_writer.add_page(page)

    # Write the combined PDF
    with open(str(final_pdf_path), "wb") as out_file:
        pdf_writer.write(out_file)

    return final_pdf_path
