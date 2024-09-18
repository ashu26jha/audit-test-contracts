from uuid import UUID

from api.v1.schemas import audit_agent_schema
from api.v1.services.audit_agent_service import get_partial_scan_result, get_scan_result
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


@router.get(
    "/scans/{scan_id}",
    response_model=audit_agent_schema.AuditAgentResponse,
)
async def get_audit_agent_result(scan_id: UUID):
    result = await get_scan_result(scan_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Scan result is not ready yet. Please try again later.",
            headers={"Retry-After": "10"},
        )
    elif isinstance(result, dict) and "error" in result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during scan: {result['error']}",
        )
    return result


@router.get(
    "/scans/partial/{scan_id}",
    response_model=audit_agent_schema.AuditAgentResponse,
)
async def get_partial_audit_agent_result(scan_id: UUID):
    result = await get_partial_scan_result(scan_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Scan result is not ready yet. Please try again later.",
            headers={"Retry-After": "10"},
        )
    elif isinstance(result, dict) and "error" in result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during scan: {result['error']}",
        )
    return result
