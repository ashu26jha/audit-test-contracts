from typing import List
from urllib.parse import urlparse
from pathlib import Path

from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import get_full_scan_result

BASE_DIR = Path(__file__).resolve().parent.parent.parent

async def generate_pdf_from_scan(scan_id: str):
    """
    Generate a PDF from the scan data.
    """
    scans = await get_scan(scan_id)
    full_result = await get_full_scan_result(scan_id)

    summary = full_result.summary
    repository_name = scans.repositoryName
    branch_name = scans.branchName
    vulnerabilities_found = full_result.total_findings

    loc = (scans.linesOfCode)['total_lines']
    organisations = extract_organization_name(scans.repositoryURL)
    contracts = scans.contractFiles

    findings_list = []
    for finding in full_result.findings:

        # Convert severity to chip color
        if finding.Severity == 'Critical':
            severity = 'chip1'
        elif finding.Severity == 'High':
            severity = 'chip2'
        elif finding.Severity == 'Medium':
            severity = 'chip3'
        elif finding.Severity == 'Low':
            severity = 'chip4'
        elif finding.Severity == 'Info':
            severity = 'chip5'
        elif finding.Severity == 'Best Practices':
            severity = 'chip6'

        finding = {
            'Issue': finding.Issue,
            'Severity': severity,
            'Contracts': finding.Contracts,
            'Description': finding.Description
        }
        findings_list.append(finding)
    html_content = create_html_file(summary, vulnerabilities_found, contracts, loc, str(scan_id), organisations, repository_name, branch_name, contracts, findings_list)
    updated_html_content = "\n".join(html_content)

    template_path = BASE_DIR / 'v1' /'services'/ 'template' / f'{str(scan_id)}.html'
    with open(template_path, 'w', encoding='utf-8') as file:
        file.write(updated_html_content)


def extract_organization_name(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip("/").split("/")
    
    if len(path_parts) > 0:
        organization_name = path_parts[0]
        return organization_name
    else:
        return None
    
def create_html_file(
    summary, 
    vulnerabilities_found, 
    contracts, 
    loc, 
    scan_id, 
    organization, 
    repository, 
    branch, 
    contracts_files, 
    findings_list
    ):
    template_path = BASE_DIR/ 'v1' /'services'/ 'template' / 'updated_frame48096177.html'
    html_content = read_html(template_path).splitlines()
    for i, line in enumerate(html_content):
        if "<!--vulnerabilties_found-->" in line:
            html_content[i] = line.replace("<!--vulnerabilties_found-->", str(vulnerabilities_found))

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
                to_append += """<div class="frame48096177-frame2085660335"> <span class="frame48096177-text147 textSmall">""" + contract + """</span></div></br>""" 
            html_content[i] = line.replace("<!--contracts_files-->", to_append)

        elif "<!--findings-->" in line:
            list_of_findings = findings_list
            to_append = ""
            for index, finding in enumerate(list_of_findings):
                description = finding["Description"]
                description = description.replace("\n", "<br>")
                content = create_contract_div(index+1, len(list_of_findings), finding["Severity"], finding["Issue"], finding["Contracts"],description)

                content = content.replace("```solidity", "<div class=\"frame48096177-code\"> <span class=\"frame48096177-text169 textSmmonofontNormal\">")
                content = content.replace("```", "</span></div>")

                to_append += content
            html_content[i] = line.replace("<!--findings-->", to_append)
    return html_content

def read_html(file_path):
  with open(file_path, 'r', encoding='utf-8') as file:
    html_content = file.read()
  
  html_lines = [line.lstrip() for line in html_content.splitlines()]
  processed_html_content = "\n".join(html_lines)
  return processed_html_content

def create_contract_div(index, total_findings, risk_level, issue_title, contract_files, description):
    contract_files_html = "".join(f"""<span class="frame48096177-text161 textSmleading-5fontNormal"><span>{file}</span></span>""" for file in contract_files)
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
  