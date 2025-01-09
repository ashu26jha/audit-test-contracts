from typing import List

from api.v1.utilities.critics.helpers.duplicates import remove_duplicates_async
from api.v1.utilities.critics.helpers.mitigation import mitigate_findings_async
from core.models.scan import Finding


class CriticService:
    @staticmethod
    async def remove_duplicates(findings: List[Finding]) -> List[Finding]:
        """Returns original findings if deduplication fails."""
        return await remove_duplicates_async(findings)

    @staticmethod
    async def mitigate_findings(
        findings: List[Finding],
        flattened_contracts: str,
    ) -> List[Finding]:
        """Returns original findings if mitigation fails."""
        return await mitigate_findings_async(findings, flattened_contracts)
