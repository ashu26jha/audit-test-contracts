from __future__ import annotations

from api.v1.schemas import audit_agent_schema
from api.v1.services import audit_agent_service
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.post("/audit-agent", response_model=audit_agent_schema.AuditAgentResponse)
async def perform_audit_agent(request: audit_agent_schema.AuditAgentRequest):
    try:
        result = await audit_agent_service.perform_audit_agent(request.contracts)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
