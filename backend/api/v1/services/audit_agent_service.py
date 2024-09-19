from __future__ import annotations

from threading import Lock
from typing import Dict, List, Optional, Union
from uuid import UUID, uuid4

from api.v1.schemas import audit_agent_schema
from api.v1.schemas.context_scan_schema import Finding
from api.v1.services import (
    context_scan_service,
    flatten_contracts_service,
    generate_summary_service,
)
from common.logger import logger
from common.profiles import Profiles

# In-memory storage for scan results (temporary solution)
_SCAN_RESULTS: Dict[UUID, Union[audit_agent_schema.AuditAgentResponse, Dict[str, str]]] = {}
_SCAN_RESULTS_LOCK = Lock()


def generate_scan_id() -> UUID:
    """Generate a unique scan ID."""
    return uuid4()


async def perform_audit_agent_background(
    scan_id: UUID,
    repository_url: str,
    contract_files: List[str],
    auth_token: Optional[str],
):
    """
    Perform audit in the background and store the result.
    """
    try:
        logger.info(f"Starting background audit scan with ID: {scan_id}")

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

        # Step 3: Perform Context Scan
        context_scan_result = await context_scan_service.perform_context_scan(
            summary_result, flattened_contracts, detected_profile
        )

        # Create the audit response
        audit_response = audit_agent_schema.AuditAgentResponse(
            scan_id=scan_id,
            summary=summary_result,
            type=detected_profile,
            scan_result=context_scan_result,
        )

        # Store the result
        await _store_scan_result(scan_id, audit_response)

        logger.info(f"Completed audit scan with ID: {scan_id}")

    except Exception as e:
        logger.exception(f"Error in background audit scan with ID {scan_id}: {str(e)}")
        # Store the error information
        await _store_scan_error(scan_id, str(e))


async def get_scan_result(
    scan_id: UUID,
) -> Optional[Union[audit_agent_schema.AuditAgentResponse, Dict[str, str]]]:
    """Retrieve the scan result by scan ID."""
    return await _retrieve_scan_result(scan_id)


async def get_partial_scan_result(
    scan_id: UUID,
) -> Optional[Union[audit_agent_schema.AuditAgentResponse, Dict[str, str]]]:
    """Retrieve partial scan results by scan ID."""
    full_result = await _retrieve_scan_result(scan_id)
    if full_result is None or isinstance(full_result, dict):
        # Return None or error if scan is not ready or an error occurred
        return full_result
    else:
        # Create a partial response
        partial_findings = _get_partial_findings(full_result.scan_result)
        partial_response = audit_agent_schema.AuditAgentResponse(
            scan_id=full_result.scan_id,
            summary=full_result.summary,
            type=full_result.type,
            scan_result=partial_findings,
        )
        return partial_response


def _get_partial_findings(findings: List[Finding]) -> List[Finding]:
    """Return a subset of findings (10% or up to 3 findings)."""
    num_findings = len(findings)
    num_partial = max(1, min(3, max(1, num_findings // 10)))
    partial_findings = findings[:num_partial]
    return partial_findings


async def _store_scan_result(scan_id: UUID, result: audit_agent_schema.AuditAgentResponse):
    """Store the scan result. Replace this with DB storage in the future."""
    with _SCAN_RESULTS_LOCK:
        _SCAN_RESULTS[scan_id] = result


async def _store_scan_error(scan_id: UUID, error_message: str):
    """Store an error message for a scan. Replace this with DB storage in the future."""
    with _SCAN_RESULTS_LOCK:
        _SCAN_RESULTS[scan_id] = {"error": error_message}


async def _retrieve_scan_result(
    scan_id: UUID,
) -> Optional[Union[audit_agent_schema.AuditAgentResponse, Dict[str, str]]]:
    """Retrieve the scan result or error message. Replace this with DB retrieval in the future."""
    with _SCAN_RESULTS_LOCK:
        return _SCAN_RESULTS.get(scan_id)
