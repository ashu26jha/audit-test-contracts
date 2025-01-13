from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks

from api.v1.audit_agent.schema import AuditAgentRequest
from api.v1.audit_agent.service import AuditAgentService
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionData, SubscriptionType
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter(prefix="/benchmark", tags=["benchmark"])


@router.post("/")
async def benchmark(request: AuditAgentRequest, background_tasks: BackgroundTasks):
    """
    Benchmarks AuditAgent, returns a scan_id
    """

    scan_id = uuid4()

    # Get existing test user or create if doesn't exist
    user = await UserRepository.get_by_username("audit-agent-benchmark")
    if not user:
        user = await UserRepository.create_test_user("audit-agent-benchmark")

    # Update subscription for benchmark testing
    user.subscription = SubscriptionData(
        isActive=True,
        type=SubscriptionType.ENTERPRISE,
        credits=10,
        monthlyCredits=10,
        expiresAt=datetime.now(timezone.utc) + timedelta(days=30),
        stripeSubscriptionId=None,
        lastRenewalAt=datetime.now(timezone.utc),
    )
    await user.save()

    await AuditAgentService.create_scan(scan_id, user, request, background_tasks)
    return SuccessResponse(data=scan_id)


@router.post("/result")
async def get_result(scan_id: UUID):
    """
    Get benchmark result for a specific scan
    """
    user = await UserRepository.get_by_username("audit-agent-benchmark")
    if not user:
        return ErrorResponse(message="user_not_found")
    full_result = await ScanRepository.get_scan_result(scan_id)
    return SuccessResponse(data=full_result)
