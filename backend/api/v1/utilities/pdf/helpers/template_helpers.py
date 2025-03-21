import html
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import markdown
from markdown.extensions.attr_list import AttrListExtension
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.nl2br import Nl2BrExtension
from markdown.extensions.sane_lists import SaneListExtension

from core.utils.errors import PDFGenerationError
from core.utils.logger import logger

from ..config import TEMPLATE_DIR
from ..helpers.pdf_assembly import prepare_findings_data

# Type definitions
SeverityTextMap = Dict[str, str]
SEVERITY_TEXT_MAP: SeverityTextMap = {
    "chip1": "Critical",
    "chip2": "High Risk",
    "chip3": "Medium Risk",
    "chip4": "Low Risk",
    "chip5": "Info",
    "chip6": "Best Practices",
}


def extract_organization_name(url: str) -> Optional[str]:
    """Extract organization name from repository URL."""
    try:
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip("/").split("/")

        if len(path_parts) > 0:
            organization_name = path_parts[0]
            return organization_name

        return None
    except Exception as e:
        logger.warning(f"Failed to extract organization name from URL {url}: {str(e)}")
        return None


def read_html(file_path: Path) -> str:
    """
    Read and process HTML file content.

    Args:
        file_path: Path to the HTML file

    Returns:
        Processed HTML content

    Raises:
        PDFGenerationError: If there's an error reading the template file
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            html_content = file.read()

        html_lines = [line.lstrip() for line in html_content.splitlines()]
        processed_html_content = "\n".join(html_lines)
        return processed_html_content
    except FileNotFoundError as e:
        error_msg = f"Template file not found: {file_path}"
        logger.error(error_msg)
        raise PDFGenerationError(error_msg) from e
    except IOError as e:
        error_msg = f"Error reading template file {file_path}: {str(e)}"
        logger.error(error_msg)
        raise PDFGenerationError(error_msg) from e
    except Exception as e:
        error_msg = f"Unexpected error reading template file {file_path}: {str(e)}"
        logger.error(error_msg)
        raise PDFGenerationError(error_msg) from e


def create_finding_section(
    index: int,
    total_findings: int,
    risk_level: str,
    issue_title: str,
    contract_files: List[str],
    description: str,
) -> str:
    """Generate HTML for a single finding section."""
    contract_files_html = "".join(
        f"""<span class="file-name">{html.escape(file)}</span>""" for file in contract_files
    )

    severity_text = SEVERITY_TEXT_MAP.get(risk_level, "Unknown")

    # Convert markdown description to HTML with code highlighting and fenced code handling
    description_html = markdown_to_html(description)

    # Same for issue title
    issue_title_html = markdown_to_html(issue_title)

    # Add the custom class to all paragraphs in the issue title
    issue_title_html = issue_title_html.replace("<p>", '<p class="finding-issue-text">')

    # Store the final HTML content
    final_html = f"""
    <div class="findings-section">
      <div class="finding-header">
        <div class="info-row">
          <span class="finding-title">
            <img
              alt="Findings stars"
              src="public/findings_stars.svg"
            />
            <span> {index} of {total_findings} Findings </span>
          </span>

          <div class="info-row">
            <span class="finding-title">
              <img
                alt="Folder icon"
                src="public/folder_icon.svg"
              />

              <div class="contracts-list">
                {contract_files_html}
              </div>
            </span>
          </div>
        </div>
      </div>

      <div class="finding-content">
        <span class="finding-issue">
          {issue_title_html}
        </span>
        <div class="severity-chip {risk_level}">
          <span class="elipsis"></span>
          <span class="severity-text">{severity_text}</span>
        </div>
      </div>

      <div class="horizontal-divider"></div>

      <div class="finding-description">
        <div class="description-text">
          {description_html}
        </div>
      </div>
    </div>
    """

    return final_html


def markdown_to_html(md_content: str) -> str:
    """Convert markdown content to HTML with code highlighting and extensions."""
    return markdown.markdown(
        md_content,
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, css_class="codehilite", pygments_style="default"),
            SaneListExtension(),
            Nl2BrExtension(),
            AttrListExtension(),
        ],
    )


def replace_placeholders(html_content: str, placeholders: Dict[str, str]) -> str:
    """Replace placeholder strings in HTML content with actual values."""
    for placeholder, value in placeholders.items():
        html_content = html_content.replace(placeholder, value)
    return html_content


def create_contract_files_html(contract_files: List[str]) -> str:
    """Generate HTML for contract files list."""
    return "".join(
        f"""<span class="file-name">{html.escape(contract)}</span>""" for contract in contract_files
    )


def create_findings_html(findings: List[Dict]) -> str:
    """
    Generate HTML for all findings.

    Args:
        findings: List of finding dictionaries with severity, issue, contracts, and description
    """
    return "".join(
        create_finding_section(
            index + 1,
            len(findings),
            finding["severity"],
            finding["issue"],
            finding["contracts"],
            finding["description"],
        )
        for index, finding in enumerate(findings)
    )


async def create_report_html_generic(
    template_filename: str,
    placeholders: Dict[str, str],
    contract_files: List[str],
    findings: List[Dict],
) -> str:
    """
    Generate complete HTML report from template and components.

    Args:
        template_filename: Name of the template file
        placeholders: Dictionary of placeholder replacements
        contract_files: List of contract file names
        findings: List of finding dictionaries
    """
    template_path = TEMPLATE_DIR / template_filename
    html_content = read_html(template_path)
    html_content = replace_placeholders(html_content, placeholders)

    contract_files_html = create_contract_files_html(contract_files)
    html_content = html_content.replace("<!--contracts_files-->", contract_files_html)

    findings_html = create_findings_html(findings)
    html_content = html_content.replace("<!--findings-->", findings_html)

    return html_content


async def create_report_html_unified(report_data: Dict, agentic: bool = False) -> str:
    """Generate unified HTML report for both regular and agentic modes."""
    # Convert markdown summary to HTML
    summary_html = markdown_to_html(report_data.get("summary", ""))

    # Prepare findings data
    findings = prepare_findings_data(report_data.get("findings", []))

    # If not agentic, we assume normal fields; otherwise we assume agentic fields
    if not agentic:
        template_name = "report_template.html"
        placeholders = {
            "<!--organization-->": str(report_data.get("organization", "")),
            "<!--scanId-->": str(report_data.get("scan_number", "")),
            "<!--repository-->": str(report_data.get("repository_name", "")),
            "<!--branch-->": str(report_data.get("branch_name", "")),
            "<!--commit_hash-->": str(report_data.get("commit_hash", "")),
            "<!--vulnerabilties_found-->": str(report_data.get("total_vulnerabilities", 0)),
            "<!--Contracts_Scanned-->": str(len(report_data.get("contract_files", []))),
            "<!--LoC-->": str(report_data.get("total_lines_of_code", 0)),
            "<!--summary-->": summary_html,
        }
    else:
        template_name = "report_template_agentic.html"
        placeholders = {
            "<!--scanId-->": str(report_data.get("scan_number", "")),
            "<!--date-->": str(report_data.get("date", "")),
            "<!--email-->": str(report_data.get("email", "")),
            "<!--ethereum_address-->": str(report_data.get("ethereum_address", "")),
            "<!--chain-->": str(report_data.get("chain", "")),
            "<!--vulnerabilties_found-->": str(report_data.get("total_vulnerabilities", 0)),
            "<!--Contracts_Scanned-->": str(len(report_data.get("contract_files", []))),
            "<!--LoC-->": str(report_data.get("total_lines_of_code", 0)),
            "<!--summary-->": summary_html,
        }

    return await create_report_html_generic(
        template_name,
        placeholders,
        report_data.get("contract_files", []),
        findings,
    )
