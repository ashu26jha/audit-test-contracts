from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, status

from api.v1.audit_agent.schema import AuditAgentInitiateResponse, AuditAgentRequest
from api.v1.audit_agent.service import AuditAgentService
from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from core.models.user import User
from core.schemas.api_response_schema import SuccessResponse

router = APIRouter()


@router.post(
    "/audit-agent",
    dependencies=[Depends(get_api_key)],
    response_model=SuccessResponse,
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
