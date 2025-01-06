from typing import Union
from uuid import UUID

from fastapi import APIRouter, Depends

from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from api.v1.utilities.pdf.service import generate_pdf_from_scan
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.throttling import throttle

router = APIRouter()


@router.get(
    "/generate-pdf/{scan_id}",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Generate a PDF report from a scan.",
)
@throttle(rate_limit_minutes=1, max_requests=3)
async def generate_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """
    Generate a PDF report from a scan.

    Args:
        scan_id (UUID): The ID of the scan to generate a PDF report for
        current_user (User): The authenticated user making the request

    Returns:
        SuccessResponse[str]: A message indicating the PDF report was sent by email
    """
    await generate_pdf_from_scan(current_user, scan_id)
    return SuccessResponse(data="Audit Agent report sent by email successfully")
