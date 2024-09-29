import os
from pathlib import Path

from api.v1.models.scan import Scan
from api.v1.models.user import User
from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import get_full_scan_result
from common import logger
from common.email_utils import send_pdf_email
from common.pdf_generation import (
    create_finding_section,
    extract_organization_name,
    html_to_pdf,
    read_html,
)
from config import settings
from fastapi import HTTPException
from PyPDF2 import PdfReader, PdfWriter

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
TEMPLATE_DIR = BASE_DIR / "config" / "template"


async def generate_pdf_from_scan(user: User, scan_id: str):
    """
    Generate a PDF report from the scan data and send it via email.
    """
    try:
        scan = await get_scan(scan_id)
        full_result = await get_full_scan_result(scan_id)

        report_data = {
            "summary": full_result.summary,
            "repository_name": scan.repositoryName,
            "branch_name": scan.branchName,
            "commit_hash": scan.commitHash,
            "total_vulnerabilities": full_result.total_findings,
            "total_lines_of_code": scan.linesOfCode["total_lines"],
            "organization": extract_organization_name(scan.repositoryURL),
            "contract_files": scan.contractFiles,
            "findings": prepare_findings_data(full_result.findings),
            "scan_id": scan_id,
            "scan_number": scan.scan_number,
        }

        html_content = await create_report_html(report_data)

        pdf_filename = f"audit_agent_report_{scan.scan_number}.pdf"
        report_pdf_path = await generate_pdf(html_content, pdf_filename)

        final_pdf_path = combine_pdfs(report_pdf_path)

        # Check if scan has been paid for
        scan = await Scan.find_one(Scan.scan_id == scan_id)
        if not scan.paid_status and not settings.ENVIRONMENT == "development":
            raise ValueError("You have not paid for this scan")

        # Send the PDF via email to the user and the address in settings.py
        await send_pdf_email(user.email, str(final_pdf_path), scan_id)
        await send_pdf_email(settings.EMAIL_ADDRESS, str(final_pdf_path), scan_id)

        cleanup_temporary_files(report_pdf_path, final_pdf_path)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during Audit Agent report generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate Audit Agent report")


def prepare_findings_data(findings):
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


async def create_report_html(report_data):
    template_path = TEMPLATE_DIR / "report_template.html"
    html_content = read_html(template_path)

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
    html_content = html_content.replace("<!--summary-->", str(report_data["summary"]))

    contract_files_html = create_contract_files_html(report_data["contract_files"])
    html_content = html_content.replace("<!--contracts_files-->", contract_files_html)

    findings_html = create_findings_html(report_data["findings"])
    html_content = html_content.replace("<!--findings-->", findings_html)

    return html_content


def create_contract_files_html(contract_files):
    return "".join(f"""<span class="file-name">{contract}</span>""" for contract in contract_files)


def create_findings_html(findings):
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


async def generate_pdf(html_content, pdf_filename):

    pdf_path = TEMPLATE_DIR / pdf_filename

    html_file_path = TEMPLATE_DIR / f"{pdf_filename}.html"
    with open(html_file_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    await html_to_pdf(html_file_path, pdf_path)
    os.remove(html_file_path)

    return pdf_path


def combine_pdfs(report_pdf_path):
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


def cleanup_temporary_files(report_pdf_path, final_pdf_path):
    os.remove(report_pdf_path)
    # Uncomment the following line if you want to remove the final PDF after sending
    # os.remove(final_pdf_path)
