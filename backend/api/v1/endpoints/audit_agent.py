from uuid import uuid4

from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services import audit_agent_service
from api.v1.services.auth_service import get_current_user
from fastapi import APIRouter, BackgroundTasks, Depends, status

router = APIRouter()


@router.post(
    "/audit-agent",
    response_model=SuccessResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def perform_audit_agent(
    request: audit_agent_schema.AuditAgentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    scan_id = uuid4()
    await audit_agent_service.initiate_scan(scan_id, current_user, request, background_tasks)
    return SuccessResponse(data=audit_agent_schema.AuditAgentInitiateResponse(scan_id=scan_id))
