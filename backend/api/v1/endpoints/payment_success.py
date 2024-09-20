from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/payment_success")
async def payment_success(session_id: str = Query(...)):
    return JSONResponse(
        content={"status": "success", "message": "Success payment", "session_ID": session_id},
        status_code=201,
    )
