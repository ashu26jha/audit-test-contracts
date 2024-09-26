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


def create_contract_div(
    index, total_findings, risk_level, issue_title, contract_files, description
):
    contract_files_html = "".join(
        f"""<span class="frame48096177-text161 textSmleading-5fontNormal"><span>{file}</span></span>"""
        for file in contract_files
    )
    return f"""
          <div class="frame48096177-option-wrapper4">
            <div class="frame48096177-content-wrapper4">
              <div class="frame48096177-frame2085660373">
                <div class="frame48096177-frame20856603271">
                  <img alt="interfacefolderemptyfolder2572" class="frame48096177-interfacefolderemptyfolder1"
                    src="public/external/interfacefolderemptyfolder2572-22j.svg" />
                  <span class="frame48096177-text159 textSmleading-5fontNormal">
                    <span>
                      {index}
                      of
                      {total_findings}
                      Findings
                    </span>
                  </span>

                  <div class="frame48096177-frame20856603272">
                    <img alt="interfacefolderemptyfolder2572"
                      src="public/external/interfacefolderemptyfolder2572-mwvt.svg"
                      class="frame48096177-interfacefolderemptyfolder2" />

                    <span class="frame48096177-text161 textSmleading-5fontNormal">
                      <span>
                       {contract_files_html}
                      </span>
                    </span>

                  </div>
                </div>
              </div>
            </div>
            <div class="frame48096177-content-wrapper5">
              <span class="frame48096177-text163 textSmleading-5fontMedium">
                <span>
                  {issue_title}
                </span>
              </span>
              <div class="frame48096177-chip5">
                <img src='public/external/{risk_level}.svg' />
              </div>
            </div>
            <div class="frame48096177-frame480961904">
              <div class="frame48096177-frame480961963">
                <!--ISSUE TITLE-->
                <span class="frame48096177-text167 textSmleading-5fontNormal">
                  <span>
                    {description}
                  </span>
                </span>
              </div>
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
                body {
                    background-color: black;
                    color: black;
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-size: 14px;
                }

                .frame48096177-option-wrapper4 {
                    page-break-inside: avoid;
                    break-inside: avoid;
                    margin-bottom: 20px;
                }
                img { max-width: 100%; height: auto; }
            `;
            document.head.appendChild(style);
        }"""
        )

        await page.wait_for_load_state("networkidle")

        width = await page.evaluate(
            """() => {
            return Math.max(
                document.body.scrollWidth,
                document.documentElement.scrollWidth,
                document.body.offsetWidth,
                document.documentElement.offsetWidth,
                document.body.clientWidth,
                document.documentElement.clientWidth
            );
        }"""
        )

        pdf_options = {
            "width": f"{width}px",
            "height": "1123px",
            "print_background": True,
            "margin": {"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"},
            "scale": 1.1,
        }

        await page.pdf(path=pdf_file, **pdf_options)

        await browser.close()
