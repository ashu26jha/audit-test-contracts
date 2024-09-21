from api.v1.schemas.api_response_schema import SuccessResponse
from fastapi import APIRouter, Query, status

router = APIRouter()


@router.get(
    "/payment_success",
    response_model=SuccessResponse,
    status_code=status.HTTP_201_CREATED,
)
async def payment_success(session_id: str = Query(...)):
    return SuccessResponse(data={"message": "Success payment", "session_ID": session_id})
