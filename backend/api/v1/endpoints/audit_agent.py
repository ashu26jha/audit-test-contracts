from __future__ import annotations

from api.v1.schemas import audit_agent_schema
from api.v1.schemas.context_scan_exceptions import EmptyResponseError
from api.v1.services import audit_agent_service
from common.logger import error
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


@router.post("/audit-agent", response_model=audit_agent_schema.AuditAgentResponse)
async def perform_audit_agent(request: audit_agent_schema.AuditAgentRequest):
    try:
        result = await audit_agent_service.perform_audit_agent(
            request.repositoryURL,
            request.contractFiles,
            request.authToken,
        )
        return result
    except EmptyResponseError as e:
        error(f"LLM response error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The input was too long for the AI model to process. Please reduce the size of your input.",
        )
    except ValueError as e:
        error(f"Value error in audit_agent: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        error(f"Unexpected error in audit_agent: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later or contact support if the problem persists.",
        )
