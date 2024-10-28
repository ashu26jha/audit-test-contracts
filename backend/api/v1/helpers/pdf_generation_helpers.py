from urllib.parse import urlparse

import markdown
from markdown.extensions.attr_list import AttrListExtension
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.nl2br import Nl2BrExtension
from markdown.extensions.sane_lists import SaneListExtension
from playwright.async_api import async_playwright


def extract_organization_name(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip("/").split("/")

    if len(path_parts) > 0:
        organization_name = path_parts[0]
        return organization_name
    else:
        return None


def read_html(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        html_content = file.read()

    html_lines = [line.lstrip() for line in html_content.splitlines()]
    processed_html_content = "\n".join(html_lines)
    return processed_html_content


def create_finding_section(
    index, total_findings, risk_level, issue_title, contract_files, description
):
    contract_files_html = "".join(
        f"""<span class="file-name">{file}</span>""" for file in contract_files
    )

    # Get the severity text based on chip number
    severity_text_map = {
        "chip1": "Critical",
        "chip2": "High Risk",
        "chip3": "Medium Risk",
        "chip4": "Low Risk",
        "chip5": "Info",
        "chip6": "Best Practices",
    }
    severity_text = severity_text_map.get(risk_level, "Unknown")

    # Convert markdown description to HTML with code highlighting and fenced code handling
    description_html = markdown.markdown(
        description,
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, css_class="codehilite", pygments_style="default"),
            SaneListExtension(),
            Nl2BrExtension(),
            AttrListExtension(),
        ],
    )

    # Same for issue title
    issue_title_html = markdown.markdown(
        issue_title,
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, css_class="codehilite", pygments_style="default"),
            Nl2BrExtension(),
            AttrListExtension(),
        ],
    )

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


async def html_to_pdf(html_file, pdf_file):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Set viewport width larger to accommodate code
        await page.set_viewport_size({"width": 1200, "height": 800})

        await page.goto(f"file://{html_file}")
        await page.wait_for_load_state("networkidle")

        # Ensure styles are loaded
        await page.wait_for_timeout(1000)

        pdf_options = {
            "path": pdf_file,
            "format": "A4",
            "print_background": True,
            "display_header_footer": False,
            "margin": {"top": "0mm", "right": "0mm", "bottom": "0mm", "left": "0mm"},
            "prefer_css_page_size": True,
        }

        await page.pdf(**pdf_options)
        await browser.close()
