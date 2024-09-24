from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.scan_schema import ScanResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.scan_history_service import get_scan_history_for_user
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/scans-history", response_model=SuccessResponse)
async def get_scan_history(current_user: User = Depends(get_current_user)):
    scans = await get_scan_history_for_user(current_user)
    scan_responses = [ScanResponse.model_validate(scan) for scan in scans]
    return SuccessResponse(data=scan_responses)
