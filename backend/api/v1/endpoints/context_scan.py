from fastapi import APIRouter, HTTPException
from api.v1.services import context_scan_service
from api.v1.schemas import context_scan_schema

router = APIRouter()


@router.post("/context-scan", response_model=context_scan_schema.ContextScanResponse)
async def perform_context_scan(request: context_scan_schema.ContextScanRequest):
    try:
        result = await context_scan_service.perform_context_scan(
            request.summary,
            request.contracts,
            request.profile,  # Pass profile to the service
        )
        return context_scan_schema.ContextScanResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
