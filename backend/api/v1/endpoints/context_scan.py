from __future__ import annotations

from api.v1.schemas import context_scan_schema
from api.v1.schemas.context_scan_exceptions import (
    EmptyResponseError,
    InvalidFormatError,
    InvalidJSONError,
    JSONParsingError,
    NetworkError,
    UnexpectedError,
)
from api.v1.services import context_scan_service
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


@router.post("/context-scan", response_model=context_scan_schema.ContextScanResponse)
async def perform_context_scan(request: context_scan_schema.ContextScanRequest):
    try:
        findings = await context_scan_service.perform_context_scan(
            request.summary,
            request.contracts,
            request.profile,
        )
        return context_scan_schema.ContextScanResponse(findings=findings)
    except EmptyResponseError as e:
        raise HTTPException(status_code=status.HTTP_204_NO_CONTENT, detail=str(e))
    except (InvalidJSONError, InvalidFormatError, JSONParsingError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except NetworkError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except UnexpectedError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
