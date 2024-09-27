from uuid import UUID

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.generate_pdf_service import generate_pdf_from_scan
from api.v1.services.scan_history_service import get_scan
from fastapi import APIRouter, Depends, HTTPException

router = APIRouter()


@router.get("/generate-pdf/{scan_id}", response_model=SuccessResponse)
async def generate_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    scan = await get_scan(scan_id)
    if scan.user_id != str(current_user.id):
        raise HTTPException(status_code=401, detail="User not authorized to access this scan")
    await generate_pdf_from_scan(scan_id)
    return SuccessResponse(data="Audit Agent report sent by email successfully")
