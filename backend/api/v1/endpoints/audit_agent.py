from datetime import datetime, timezone
from uuid import uuid4

from api.v1.models.scan import Scan
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.services import audit_agent_service
from api.v1.services.auth_service import get_current_user
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

router = APIRouter()


@router.post("/audit-agent", response_model=audit_agent_schema.AuditAgentInitiateResponse)
async def perform_audit_agent(
    request: audit_agent_schema.AuditAgentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    try:
        # Validate user access token
        if not current_user.accessToken:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User does not have a GitHub access token on file.",
            )

        # Validate GitHub URL
        if not audit_agent_service.validate_github_url(request.repositoryURL):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid GitHub repository URL.",
            )

        # Validate contract files
        if not audit_agent_service.validate_contract_files(request.contractFiles):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid contract files. All files must have a .sol extension.",
            )

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

        # Return the scan ID
        return audit_agent_schema.AuditAgentInitiateResponse(scan_id=scan_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later.",
        )
