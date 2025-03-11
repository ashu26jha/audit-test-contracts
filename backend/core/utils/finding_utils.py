from typing import List

from core.models.scan import Finding
from core.utils.severity import Severity


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """
    Sort findings by severity in descending order (HIGH to BEST_PRACTICES).

    Args:
        findings: List of Finding objects to sort

    Returns:
        List of Finding objects sorted by severity
    """
    severity_order = {
        Severity.HIGH: 0,
        Severity.MEDIUM: 1,
        Severity.LOW: 2,
        Severity.INFO: 3,
        Severity.BEST_PRACTICES: 4,
    }

    return sorted(findings, key=lambda x: severity_order.get(Severity.validate(x.Severity), 999))
