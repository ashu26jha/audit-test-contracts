from urllib.parse import urlparse

import bleach
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

    # Convert markdown description to HTML with code highlighting and fenced code handling
    description_html = markdown.markdown(
        description,
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, css_class="highlight", pygments_style="default"),
            SaneListExtension(),
            Nl2BrExtension(),
            AttrListExtension(),
        ],
    )

    # Convert markdown issue title to HTML
    issue_title_html = markdown.markdown(
        issue_title,
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(linenums=False, css_class="highlight", pygments_style="default"),
            Nl2BrExtension(),
            AttrListExtension(),
        ],
    )

    # Sanitize the HTML output
    allowed_tags = bleach.ALLOWED_TAGS.union(
        {
            "p",
            "pre",
            "code",
            "span",
            "div",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "ul",
            "ol",
            "li",
            "em",  # Allow emphasis tag
            "strong",  # Allow strong tag
            "table",
            "tr",
            "td",
            "th",
        }
    )
    allowed_attributes = bleach.sanitizer.ALLOWED_ATTRIBUTES.copy()
    allowed_attributes.update(
        {
            "*": ["class", "style"],  # Allow class and style on all tags
        }
    )
    description_html = bleach.clean(
        description_html, tags=allowed_tags, attributes=allowed_attributes
    )
    issue_title_html = bleach.clean(
        issue_title_html, tags=allowed_tags, attributes=allowed_attributes
    )

    return f"""
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
        <div class="severity-chip">
          <img src="public/{risk_level}.svg" />
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


async def html_to_pdf(html_file, pdf_file):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        await page.goto(f"file://{html_file}")

        await page.wait_for_load_state("networkidle")
        # Optionally wait for a short time to ensure page is fully rendered
        await page.wait_for_timeout(1000)

        pdf_options = {
            "path": pdf_file,
            "format": "A4",
            "print_background": True,
            "display_header_footer": False,
            "margin": {"top": "0mm", "right": "0mm", "bottom": "0mm", "left": "0mm"},
        }

        await page.pdf(**pdf_options)
        await browser.close()
