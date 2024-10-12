from __future__ import annotations

from fastapi import APIRouter, status

from api.v1.schemas import context_scan_schema
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services import context_scan_service

router = APIRouter()


@router.post("/context-scan", response_model=SuccessResponse, status_code=status.HTTP_200_OK)
async def perform_context_scan(request: context_scan_schema.ContextScanRequest):
    findings = await context_scan_service.perform_context_scan(
        request.summary,
        request.contracts,
        request.profile,
    )
    return SuccessResponse(data=context_scan_schema.ContextScanResponse(findings=findings))
