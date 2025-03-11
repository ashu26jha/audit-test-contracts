from typing import Union
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from api.v1.auth.helpers.dependencies import get_agentic_api_key, get_api_key, get_current_user
from api.v1.utilities.pdf.service import (
    generate_and_send_agentic_pdf,
    generate_and_send_pdf_from_scan,
)
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.throttling import throttle

router = APIRouter(tags=["utilities"])


@router.get(
    "/generate-pdf/{scan_id}",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Generate and send a PDF report from a scan.",
)
@throttle(max_requests=5)
async def generate_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """
    Generate and send a PDF report from a scan.

    Args:
        scan_id (UUID): The ID of the scan to generate a PDF report for
        current_user (User): The authenticated user making the request

    Returns:
        SuccessResponse[str]: A message indicating the PDF report was sent by email
    """
    await generate_and_send_pdf_from_scan(current_user, scan_id)
    return SuccessResponse(data="Audit Agent report sent by email successfully")


@router.get(
    "/generate-agentic-pdf/{scan_id}",
    dependencies=[Depends(get_agentic_api_key)],
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Generate and send a PDF report from an agentic scan.",
)
@throttle(max_requests=10)
async def generate_agentic_pdf(
    scan_id: UUID,
    email: str = Query(..., description="Email address to send the PDF report to"),
):
    """
    Generate and send a PDF report from an agentic scan.

    Args:
        scan_id (UUID): The ID of the scan to generate a PDF report for
        email (str): Email address to send the PDF report to

    Returns:
        SuccessResponse[str]: A message indicating the PDF report was sent by email
    """
    await generate_and_send_agentic_pdf(scan_id, email)
    return SuccessResponse(data="AuditAgent report sent by email successfully")
