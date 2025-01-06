from typing import List
from uuid import UUID

from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, ScanResult


async def get_partial_scan_result(scan_id: UUID) -> ScanResult:
    """Retrieve partial scan results by scan ID."""
    full_result = await ScanRepository.get_scan_result(scan_id)
    partial_findings = _get_partial_findings(full_result.findings)
    full_result.findings = partial_findings
    return full_result


def _get_partial_findings(findings: List[Finding]) -> List[Finding]:
    """
    Return only the most confident finding.
    If Confidence field doesn't exist or no findings have confidence scores, return the first finding.
    """
    if not findings:
        return []

    # Check if any finding has a Confidence field and it's not None
    has_confidence = any(
        hasattr(finding, "Confidence") and finding.Confidence is not None for finding in findings
    )

    if not has_confidence:
        # If no findings have confidence scores, return the first finding
        return [findings[0]]

    # Get the maximum confidence score
    max_confidence = max(getattr(finding, "Confidence", 0) or 0 for finding in findings)

    # Return the first finding with the maximum confidence
    for finding in findings:
        if getattr(finding, "Confidence", 0) == max_confidence:
            return [finding]

    return []
