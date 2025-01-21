from pathlib import Path
from typing import Dict, List

from pypdf import PdfReader, PdfWriter

from core.models.scan import Finding

from ..config import TEMPLATE_DIR


def prepare_findings_data(findings: List[Finding]) -> List[Dict[str, str]]:
    """
    Transform and sort findings data by severity.

    Args:
        findings: List of Finding objects

    Returns:
        List of dictionaries containing processed finding data
    """
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


def combine_pdfs(report_pdf_path: Path) -> Path:
    """
    Combine report PDF with cover and disclaimer pages.

    Args:
        report_pdf_path: Path to the main report PDF

    Returns:
        Path to the final combined PDF
    """
    cover_page_path = TEMPLATE_DIR / "cover_page.pdf"
    disclaimer_page_path = TEMPLATE_DIR / "disclaimer_page.pdf"
    final_pdf_path = report_pdf_path.with_name(f"final_{report_pdf_path.name}")

    pdf_writer = PdfWriter()

    _add_pdf_pages(pdf_writer, cover_page_path)
    _add_pdf_pages(pdf_writer, report_pdf_path)
    _add_pdf_pages(pdf_writer, disclaimer_page_path)

    # Write the combined PDF
    with open(str(final_pdf_path), "wb") as out_file:
        pdf_writer.write(out_file)

    return final_pdf_path


def _add_pdf_pages(pdf_writer: PdfWriter, pdf_path: Path) -> None:
    """
    Add all pages from a source PDF to a PDF writer.

    Args:
        pdf_writer: The PdfWriter instance to add pages to
        pdf_path: Path to the source PDF file
    """
    pdf_reader = PdfReader(str(pdf_path))
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)
