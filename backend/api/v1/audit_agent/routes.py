from typing import Union
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, status

from api.v1.audit_agent.schema import (
    AuditAgentInitiateResponse,
    AuditAgentRequest,
    IsFreeScanAllowedResponse,
)
from api.v1.audit_agent.service import AuditAgentService
from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.validate import validate_free_scan_limit

router = APIRouter()


@router.post(
    "/audit-agent",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[AuditAgentInitiateResponse], ErrorResponse],
    status_code=status.HTTP_202_ACCEPTED,
    description="Initiate an audit agent scan",
)
async def perform_audit_agent(
    request: AuditAgentRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    """
    Initiate a full AuditAgent scan.

    Args:
        repository_url (str): URL of the GitHub repository to scan
        contract_files (List[str]): Array of relative file paths within the repository (e.g., 'contracts/MyContract.sol')
        branch_name (str): Name of the branch to scan. Defaults to 'main' if not provided.
        docs (QAResponse): Optional QA response associated with the request

    Returns:
        scan_id (UUID): Unique identifier for the scan
    """
    scan_id = uuid4()
    await AuditAgentService.create_scan(scan_id, current_user, request, background_tasks)
    return SuccessResponse(data=AuditAgentInitiateResponse(scan_id=scan_id))


@router.get(
    "/is-free-scan-allowed",
    response_model=Union[SuccessResponse[IsFreeScanAllowedResponse], ErrorResponse],
)
async def is_free_scan_allowed(current_user: User = Depends(get_current_user)):
    """
    Check if the current user can perform a free scan.
    Returns true if:
    - User is a subscriber
    - User hasn't used their free scan in the last 30 days
    """
    free_scan_status = await validate_free_scan_limit(current_user.githubId)
    return SuccessResponse(
        data=IsFreeScanAllowedResponse(
            is_allowed=free_scan_status.is_allowed,
            next_available_at=free_scan_status.next_available_at,
            message=(
                "Free scan available" if free_scan_status.is_allowed else "Free scan not available"
            ),
        ),
    )
