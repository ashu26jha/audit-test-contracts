from __future__ import annotations

from api.v1.schemas import audit_agent_schema
from api.v1.services import audit_agent_service
from common.logger import logger
from fastapi import APIRouter, BackgroundTasks, HTTPException, status

router = APIRouter()


@router.post("/audit-agent", response_model=audit_agent_schema.AuditAgentInitiateResponse)
async def perform_audit_agent(
    request: audit_agent_schema.AuditAgentRequest, background_tasks: BackgroundTasks
):
    try:
        # Generate the scan ID here to return it immediately
        scan_id = audit_agent_service.generate_scan_id()

        # Start the audit_agent_service in the background
        background_tasks.add_task(
            audit_agent_service.perform_audit_agent_background,
            scan_id,
            request.repositoryURL,
            request.contractFiles,
            request.authToken,
        )

        # Return the scan ID immediately
        return audit_agent_schema.AuditAgentInitiateResponse(scan_id=scan_id)
    except ValueError as e:
        logger.error(f"Value error in audit_agent: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception(f"Unexpected error in audit_agent: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later or contact support if the problem persists.",
        )
