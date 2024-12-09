from uuid import UUID

from fastapi import APIRouter, Depends

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_api_key, get_current_user
from api.v1.services.generate_pdf_service import generate_pdf_from_scan
from common.throttling import throttle

router = APIRouter()


@router.get(
    "/generate-pdf/{scan_id}", dependencies=[Depends(get_api_key)], response_model=SuccessResponse
)
@throttle(rate_limit_minutes=1, max_requests=3)
async def generate_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    await generate_pdf_from_scan(current_user, scan_id)
    return SuccessResponse(data="Audit Agent report sent by email successfully")
