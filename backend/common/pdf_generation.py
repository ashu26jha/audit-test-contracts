from urllib.parse import urlparse

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
        f"""<span class="file-name textSmleading-5fontNormal"><span>{file}</span></span>"""
        for file in contract_files
    )
    return f"""
    <div class="findings-section">
      <div class="finding-header">
        <div class="info-row">
          <span class="finding-title">
            <img
              alt="interfacefolderemptyfolder2572"
              class="frame48096177-interfacefolderemptyfolder1"
              src="public/findings_stars.svg"
            />
            <span> {index} of {total_findings} Findings </span>
          </span>

          <div class="info-row">
            <span class="finding-title">
              <img
                alt="interfacefolderemptyfolder2572"
                src="public/folder_icon.svg"
                class="frame48096177-interfacefolderemptyfolder2"
              />

              <div class="contracts-list">
                {contract_files_html}
              </div>
            </span>
          </div>
        </div>
      </div>

      <div class="finding-content">
        <span class="finding-issue textSmleading-5fontMedium">
          <span> {issue_title} </span>
        </span>
        <div class="severity-chip">
          <img src="public/{risk_level}.svg" />
        </div>
      </div>

      <div class="horizontal-divider"></div>

      <div class="finding-description">
        <span class="description-text textSmleading-5fontNormal">
          <span>
            {description}
          </span>
        </span>
      </div>
    </div>
    """


async def html_to_pdf(html_file, pdf_file):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        await page.goto(f"file://{html_file}")

        await page.evaluate(
            """() => {
            const style = document.createElement('style');
            style.textContent = `
                @page {
                    size: A4;
                    margin: 0;
                }
                body {
                    margin: 0;
                    padding: 0;
                }
                .a4-container {
                    width: 210mm;
                    height: 297mm;
                    padding: 20mm;
                    box-sizing: border-box;
                }
            `;
            document.head.appendChild(style);
        }"""
        )

        await page.wait_for_load_state("networkidle")

        pdf_options = {
            "format": "A4",
            "margin": {"top": "0mm", "right": "0mm", "bottom": "0mm", "left": "0mm"},
        }

        await page.pdf(path=pdf_file, **pdf_options)

        await browser.close()
