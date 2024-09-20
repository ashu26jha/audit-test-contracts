from typing import List, Optional
from uuid import UUID

from api.v1.models.scan import ScanResult
from api.v1.schemas.context_scan_schema import Finding
from api.v1.services.scan_history_service import get_scan_result


async def get_full_scan_result(scan_id: UUID) -> Optional[ScanResult]:
    """Retrieve full scan results by scan ID."""
    return await get_scan_result(scan_id)


async def get_partial_scan_result(scan_id: UUID) -> Optional[ScanResult]:
    """Retrieve partial scan results by scan ID."""
    full_result = await get_scan_result(scan_id)
    if full_result is None:
        return None
    else:
        partial_findings = _get_partial_findings(full_result.findings)
        full_result.findings = partial_findings
        return full_result


def _get_partial_findings(findings: List[Finding]) -> List[Finding]:
    """Return a subset of findings (10% or up to 3 findings)."""
    num_findings = len(findings)
    if num_findings == 0:
        return []
    num_partial = min(max(1, num_findings // 10), 3)
    return findings[:num_partial]
