from typing import List
from urllib.parse import urlparse

from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import get_full_scan_result


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
    total_contracts = len(scans.contractFiles)
    contracts = scans.contractFiles

    findings = full_result.findings
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

def extract_organization_name(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip("/").split("/")
    
    if len(path_parts) > 0:
        organization_name = path_parts[0]
        return organization_name
    else:
        return None