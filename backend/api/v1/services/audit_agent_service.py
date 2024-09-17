from __future__ import annotations

from typing import List, Optional

from api.v1.schemas import audit_agent_schema
from api.v1.services import (
    context_scan_service,
    flatten_contracts_service,
    generate_summary_service,
)
from common.profiles import Profiles


async def perform_audit_agent(
    repository_url: str,
    contract_files: List[str],
    auth_token: Optional[str],
):
    """
    Perform an audit on the specified smart contracts.

    Args:
        repository_url (str): The URL of the GitHub repository.
        contract_files (List[str]): List of relative file paths to the contracts within the repository.
        auth_token (Optional[str]): Authentication token for private repositories.

    Returns:
        AuditAgentResponse: The audit results including summary, detected type, and scan results.
    """
    # Step 1: Flatten contracts
    flattened_contracts = await flatten_contracts_service.flatten_contracts(
        repository_url, contract_files, auth_token
    )

    # Step 2: Generate Summary and detect profile
    summary_result, detected_type = await generate_summary_service.generate_summary(
        flattened_contracts
    )

    # Map 'detected_type' to a Profiles enum member
    try:
        detected_profile = Profiles[detected_type.upper()]
    except KeyError:
        detected_profile = Profiles.DEFAULT

    print(detected_profile)

    # Step 3: Perform Context Scan
    context_scan_result = await context_scan_service.perform_context_scan(
        summary_result, flattened_contracts, detected_profile
    )

    # Return summary and findings
    return audit_agent_schema.AuditAgentResponse(
        summary=summary_result,
        type=detected_profile,
        scan_result=context_scan_result,
    )
