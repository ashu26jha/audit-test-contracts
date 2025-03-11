from typing import List

from core.models.scan import Finding
from core.utils.finding_utils import sort_findings
from core.utils.severity import Severity


def test_sorted_findings():
    finding_1 = Finding(
        Issue="Test Issue 1",
        Contracts=["a.sol"],
        Severity="Low",
        Description="Low Sev Desc",
        Recommendation="",
    )
    finding_2 = Finding(
        Issue="Test Issue 1",
        Contracts=["a.sol"],
        Severity="High",
        Description="High Sev Desc",
        Recommendation="",
    )

    findings: List[Finding] = [finding_1, finding_2]

    sorted_finding_list = sort_findings(findings)
    assert sorted_finding_list[0].Severity == Severity.HIGH
    assert sorted_finding_list[1].Severity == Severity.LOW
