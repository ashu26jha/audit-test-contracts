import os
from pathlib import Path

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

BASE_DIR = Path(__file__).resolve().parent.parent.parent


async def generate_pdf_from_scan(scan_id: str):
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
            "total_vulnerabilities": full_result.total_findings,
            "total_lines_of_code": scan.linesOfCode["total_lines"],
            "organization": extract_organization_name(scan.repositoryURL),
            "contract_files": scan.contractFiles,
            "findings": prepare_findings_data(full_result.findings),
            "scan_id": scan_id,
        }

        html_content = await create_report_html(report_data)

        pdf_filename = f"audit_agent_report_{scan.scan_number}.pdf"
        report_pdf_path = await generate_pdf(html_content, pdf_filename)

        final_pdf_path = combine_pdfs(report_pdf_path)

        await send_pdf_email(settings.EMAIL_ADDRESS, str(final_pdf_path), scan_id)

        cleanup_temporary_files(report_pdf_path, final_pdf_path)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during Audit Agent report generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate Audit Agent report")


def prepare_findings_data(findings):
    severity_map = {
        "Critical": "chip1",
        "High": "chip2",
        "Medium": "chip3",
        "Low": "chip4",
        "Info": "chip5",
        "Best Practices": "chip6",
    }

    return [
        {
            "issue": finding.Issue,
            "severity": severity_map.get(finding.Severity, "chip6"),
            "contracts": finding.Contracts,
            "description": finding.Description,
        }
        for finding in findings
    ]


async def create_report_html(report_data):
    template_path = BASE_DIR / "v1" / "services" / "template" / "report_template.html"
    html_content = read_html(template_path).splitlines()

    placeholders = {
        "<!--vulnerabilties_found-->": str(report_data["total_vulnerabilities"]),
        "<!--Contracts_Scanned-->": str(len(report_data["contract_files"])),
        "<!--LoC-->": str(report_data["total_lines_of_code"]),
        "<!--scanId-->": str(report_data["scan_id"]),
        "<!--summary-->": str(report_data["summary"]),
        "<!--organization-->": str(report_data["organization"]),
        "<!--repository-->": str(report_data["repository_name"]),
        "<!--branch-->": str(report_data["branch_name"]),
    }

    for i, line in enumerate(html_content):
        for placeholder, value in placeholders.items():
            if placeholder in line:
                html_content[i] = line.replace(placeholder, value)

        if "<!--contracts_files-->" in line:
            contract_files_html = create_contract_files_html(report_data["contract_files"])
            html_content[i] = line.replace("<!--contracts_files-->", contract_files_html)

        elif "<!--findings-->" in line:
            findings_html = create_findings_html(report_data["findings"])
            html_content[i] = line.replace("<!--findings-->", findings_html)

    return "\n".join(html_content)


def create_contract_files_html(contract_files):
    return "".join(
        f"""<span class="file-name textSmall">{contract}</span>""" for contract in contract_files
    )


def create_findings_html(findings):
    # Start with a page break to ensure the first finding starts on a new page
    html = '<div style="page-break-before: always; margin-top: 20mm;"></div>'

    for index, finding in enumerate(findings):
        # Insert a page break before every fifth finding (i.e., 5th, 10th, 15th, ...)
        if index != 0 and index % 4 == 0:
            html += '<div style="page-break-before: always; margin-top: 20mm;"></div>'

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
    # Ensure the template directory exists
    template_dir = BASE_DIR / "v1" / "services" / "template"
    template_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = template_dir / pdf_filename

    html_file_path = template_dir / f"{pdf_filename}.html"
    with open(html_file_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    await html_to_pdf(html_file_path, pdf_path)
    os.remove(html_file_path)

    return pdf_path


def combine_pdfs(report_pdf_path):
    cover_page_path = BASE_DIR / "v1" / "services" / "template" / "cover_page.pdf"
    disclaimer_page_path = BASE_DIR / "v1" / "services" / "template" / "disclaimer_page.pdf"
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
