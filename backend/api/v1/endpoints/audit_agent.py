from datetime import datetime, timezone
from uuid import uuid4

from api.v1.models.scan import Scan
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.services import audit_agent_service
from api.v1.services.auth_service import get_current_user
from fastapi import APIRouter, BackgroundTasks, Depends, status

router = APIRouter()


@router.post(
    "/audit-agent",
    response_model=audit_agent_schema.AuditAgentInitiateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def perform_audit_agent(
    request: audit_agent_schema.AuditAgentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    # Validate user has a GitHub access token on file
    audit_agent_service.validate_user_has_github_token(current_user)

    # Validate GitHub repository URL
    audit_agent_service.validate_github_url(request.repositoryURL)

    # Validate contract files
    audit_agent_service.validate_contract_files(request.contractFiles)

    # Generate the scan ID
    scan_id = uuid4()

    # Create a new Scan object and store it
    new_scan = Scan(
        scan_id=scan_id,
        user_id=str(current_user.id),
        status="pending",
        startedAt=datetime.now(timezone.utc),
        contractFiles=request.contractFiles,
    )
    await new_scan.create()

    # Start the background task
    background_tasks.add_task(
        audit_agent_service.perform_audit_agent_background,
        scan_id,
        str(current_user.id),
        request.repositoryURL,
        request.contractFiles,
        current_user.accessToken,
    )

    return audit_agent_schema.AuditAgentInitiateResponse(scan_id=scan_id)
