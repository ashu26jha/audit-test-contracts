from api.v1.services import (
    generate_summary_service,
    context_scan_service,
)
from api.v1.schemas import audit_agent_schema
from common.profiles import Profiles


async def perform_audit_agent(contracts: str):
    # Step 1: Generate Summary and detect profiles
    summary_result, detected_profile = await generate_summary_service.generate_summary(
        contracts
    )

    # Check if the detected profile is valid, otherwise default to Profiles.DEFAULT
    if detected_profile not in Profiles:
        detected_profile = Profiles.DEFAULT

    # Step 2: Perform Context Scan
    context_scan_result = await context_scan_service.perform_context_scan(
        summary_result, contracts, detected_profile
    )

    # Return summary and findings
    return audit_agent_schema.AuditAgentResponse(
        summary=summary_result,
        scan_result=context_scan_result,
    )
