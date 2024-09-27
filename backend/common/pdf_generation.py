from urllib.parse import urlparse

import markdown
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
        f"""<span class="file-name"><span>{file}</span></span>""" for file in contract_files
    )
    # Convert markdown description to HTML
    description_html = markdown.markdown(description)

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
          <span> {issue_title} </span>
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
