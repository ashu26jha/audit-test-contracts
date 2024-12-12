from fastapi import APIRouter, status

from api.v1.helpers.mitigation_helper import mitigate_findings
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.context_scan_schema import MitigationRequest

router = APIRouter()


@router.post("/mitigate-findings", response_model=SuccessResponse, status_code=status.HTTP_200_OK)
async def test_mitigation(request: MitigationRequest):
    """Test endpoint to check mitigation results directly."""
    mitigated_findings = await mitigate_findings(
        findings=request.findings,
        flattened_contracts=request.flattened_contracts,
    )

    return SuccessResponse(
        data={
            "original_count": len(request.findings),
            "findings_count": len(mitigated_findings),
            "findings": mitigated_findings,
        }
    )
