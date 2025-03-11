from typing import Union

from fastapi import APIRouter, BackgroundTasks, status

from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

from .schema import AutonomousAgentRequest
from .service import autonomous_agent_service

router = APIRouter()


@router.post(
    "/autonomous-agent",
    response_model=Union[SuccessResponse, ErrorResponse],
    status_code=status.HTTP_202_ACCEPTED,
    description="Initiate an autonomous agent scan",
)
async def autonomous_agent(request: AutonomousAgentRequest, background_tasks: BackgroundTasks):
    # Add the service to background tasks
    background_tasks.add_task(autonomous_agent_service, request)

    # Return immediate success response
    return SuccessResponse(data="Request accepted and processing started")
