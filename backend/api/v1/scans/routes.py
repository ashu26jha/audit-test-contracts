from typing import List, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from api.v1.scans.schema import FullScanResultResponse, ScanResponse
from api.v1.scans.service import ScanHistoryService, ScanResultService
from core.db.repositories.scan import ScanNotFoundError, ScanResultNotFoundError
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import (
    AuthorizationError,
    DatabaseError,
    QueryError,
    ScanError,
    ValidationError,
)
from core.utils.logger import logger

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get(
    "/result/{scan_id}",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[FullScanResultResponse], ErrorResponse],
    description="Get the full scan result for a given scan ID. Requires API key and paid status.",
)
async def get_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """
    Get the full scan result for a given scan ID.

    Args:
        scan_id (UUID): The ID of the scan to retrieve
        current_user (User): The authenticated user making the request

    Returns:
        FullScanResultResponse: Contains both scan metadata and complete scan results
    """
    try:
        result = await ScanResultService.get_full_result(scan_id, current_user)
        return SuccessResponse(data=result)
    except AuthorizationError as e:
        logger.warning(f"Authorization error for scan {scan_id}: {e.message}")
        raise HTTPException(status_code=403, detail=e.message)
    except ValidationError as e:
        logger.warning(f"Validation error for scan {scan_id}: {e.message}")
        raise HTTPException(status_code=400, detail=e.message)
    except (ScanError, ScanNotFoundError, ScanResultNotFoundError) as e:
        logger.warning(f"Scan error for scan {scan_id}: {e.message}")
        raise HTTPException(status_code=404, detail=e.message)
    except QueryError as e:
        logger.error(f"Query error for scan {scan_id}: {e.message}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan data")
    except DatabaseError as e:
        logger.error(f"Database error for scan {scan_id}: {e.message}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan result")
    except Exception as e:
        logger.error(f"Unexpected error retrieving scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred")


@router.get(
    "/history",
    response_model=Union[SuccessResponse[List[ScanResponse]], ErrorResponse],
    description="Get the scan history for the authenticated user.",
)
async def get_scan_history(current_user: User = Depends(get_current_user)):
    """
    Get the scan history for the authenticated user.

    Args:
        current_user (User): The authenticated user making the request

    Returns:
        List[ScanResponse]: List of all scans associated with the user
    """
    try:
        history = await ScanHistoryService.get_scan_history_for_user(current_user)
        return SuccessResponse(data=[ScanResponse.model_validate(scan) for scan in history])
    except QueryError as e:
        logger.error(f"Query error retrieving scan history: {e.message}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan history")
    except Exception as e:
        logger.error(f"Unexpected error retrieving scan history: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred")
