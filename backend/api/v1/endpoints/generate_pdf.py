from uuid import UUID
from api.v1.models.user import User
from api.v1.services.auth_service import get_current_user
from fastapi import APIRouter, Depends, HTTPException
from schemas import generate_pdf_schema
from services import generate_pdf_service
from api.v1.services.scan_history_service import get_scan

router = APIRouter()

@router.post("/generate-pdf")
async def generate_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    scan = await get_scan(scan_id)
    if scan.user_id != str(current_user.id):
        raise HTTPException(status_code=401, detail="User not authorized to access this scan")
    pdf_url = await generate_pdf_service.generate_pdf(scan_id)