from __future__ import annotations

from api.v1.schemas import context_scan_schema
from api.v1.services import context_scan_service
from fastapi import APIRouter

router = APIRouter()


@router.post("/context-scan", response_model=context_scan_schema.ContextScanResponse)
async def perform_context_scan(request: context_scan_schema.ContextScanRequest):
    findings = await context_scan_service.perform_context_scan(
        request.summary,
        request.contracts,
        request.profile,
    )
    return context_scan_schema.ContextScanResponse(findings=findings)
