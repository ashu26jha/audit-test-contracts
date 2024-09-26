import os
from pathlib import Path

from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import get_full_scan_result
from common import logger
from common.email_utils import send_pdf_email
from common.pdf_generation import (
    create_contract_div,
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
    Generate a PDF from the scan data and send it via email.
    """
    try:
        scans = await get_scan(scan_id)
        full_result = await get_full_scan_result(scan_id)

        summary = full_result.summary
        repository_name = scans.repositoryName
        branch_name = scans.branchName
        vulnerabilities_found = full_result.total_findings

        loc = (scans.linesOfCode)["total_lines"]
        organisations = extract_organization_name(scans.repositoryURL)
        contracts = scans.contractFiles

        findings_list = []
        for finding in full_result.findings:

            # Convert severity to chip color
            if finding.Severity == "Critical":
                severity = "chip1"
            elif finding.Severity == "High":
                severity = "chip2"
            elif finding.Severity == "Medium":
                severity = "chip3"
            elif finding.Severity == "Low":
                severity = "chip4"
            elif finding.Severity == "Info":
                severity = "chip5"
            elif finding.Severity == "Best Practices":
                severity = "chip6"

            finding = {
                "Issue": finding.Issue,
                "Severity": severity,
                "Contracts": finding.Contracts,
                "Description": finding.Description,
            }
            findings_list.append(finding)

        html_content = await create_html_file(
            summary,
            vulnerabilities_found,
            contracts,
            loc,
            str(scan_id),
            organisations,
            repository_name,
            branch_name,
            contracts,
            findings_list,
        )
        updated_html_content = "\n".join(html_content)

        # Ensure the template directory exists
        template_dir = BASE_DIR / "v1" / "services" / "template"
        template_dir.mkdir(parents=True, exist_ok=True)
        pdf_name = f"audit-agent-report_{str(scans.scan_number)}.pdf"

        template_path = template_dir / f"{str(scan_id)}.html"
        middle_path = template_dir / f"{str(scan_id)}.pdf"
        front_page_path = template_dir / "frame48096177.pdf"
        final_pdf_path = template_dir / pdf_name
        disclaimer_path = template_dir / "disclaimer.pdf"

        with open(template_path, "w", encoding="utf-8") as file:
            file.write(updated_html_content)

        await html_to_pdf(template_path, middle_path)
        await combine_pdfs(front_page_path, middle_path, disclaimer_path, final_pdf_path)

        # Send the PDF via email
        await send_pdf_email(settings.EMAIL_ADDRESS, str(final_pdf_path), scan_id)

        os.remove(middle_path)
        os.remove(template_path)
        # os.remove(pdf_name)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during scan initiation: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")


async def create_html_file(
    summary,
    vulnerabilities_found,
    contracts,
    loc,
    scan_id,
    organization,
    repository,
    branch,
    contracts_files,
    findings_list,
):
    template_path = BASE_DIR / "v1" / "services" / "template" / "updated_frame48096177.html"
    html_content = read_html(template_path).splitlines()
    for i, line in enumerate(html_content):
        if "<!--vulnerabilties_found-->" in line:
            html_content[i] = line.replace(
                "<!--vulnerabilties_found-->", str(vulnerabilities_found)
            )

        elif "<!--Contracts_Scanned-->" in line:
            html_content[i] = line.replace("<!--Contracts_Scanned-->", str(len(contracts)))

        elif "<!--LoC-->" in line:
            html_content[i] = line.replace("<!--LoC-->", str(loc))

        elif "<!--scanId-->" in line:
            html_content[i] = line.replace("<!--scanId-->", str(scan_id))

        elif "<!--summary-->" in line:
            html_content[i] = line.replace("<!--summary-->", str(summary))

        elif "<!--organization-->" in line:
            html_content[i] = line.replace("<!--organization-->", str(organization))

        elif "<!--repository-->" in line:
            html_content[i] = line.replace("<!--repository-->", str(repository))

        elif "<!--branch-->" in line:
            html_content[i] = line.replace("<!--branch-->", str(branch))

        elif "<!--contracts_files-->" in line:
            list_of_contracts = contracts_files
            to_append = ""
            for contract in list_of_contracts:
                to_append += (
                    """<div class="frame48096177-frame2085660335"> <span class="frame48096177-text147 textSmall">"""
                    + contract
                    + """</span></div></br>"""
                )
            html_content[i] = line.replace("<!--contracts_files-->", to_append)

        elif "<!--findings-->" in line:
            list_of_findings = findings_list
            to_append = ""
            for index, finding in enumerate(list_of_findings):
                description = finding["Description"]
                description = description.replace("\n", "<br>")
                content = create_contract_div(
                    index + 1,
                    len(list_of_findings),
                    finding["Severity"],
                    finding["Issue"],
                    finding["Contracts"],
                    description,
                )

                content = content.replace(
                    "```solidity",
                    '<div class="frame48096177-code"> <span class="frame48096177-text169 textSmmonofontNormal">',
                )
                content = content.replace("```", "</span></div>")

                to_append += content
            html_content[i] = line.replace("<!--findings-->", to_append)
    return html_content


async def combine_pdfs(pdf1_path, pdf2_path, pdf3_path, output_path):
    writer = PdfWriter()

    reader1 = PdfReader(pdf1_path)
    for page in reader1.pages:
        writer.add_page(page)

    reader2 = PdfReader(pdf2_path)
    for page in reader2.pages:
        writer.add_page(page)

    reader3 = PdfReader(pdf3_path)
    for page in reader3.pages:
        writer.add_page(page)

    with open(output_path, "wb") as f:
        writer.write(f)
