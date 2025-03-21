from typing import Union
from uuid import UUID, uuid4

from fastapi import APIRouter, status

from api.v1.scanner.benchmark.schema import BenchmarkInitiateResponse, BenchmarkScanRequest
from api.v1.scanner.benchmark.service import BenchmarkService
from core.db.repositories.scan import ScanRepository
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.schemas.scan_schema import ScanType
from core.utils.decorators import handle_domain_errors

router = APIRouter(prefix="/benchmark", tags=["scanner"])


@router.post(
    "/launch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=Union[SuccessResponse[BenchmarkInitiateResponse], ErrorResponse],
    description="Initiate a benchmark scan",
)
@handle_domain_errors(scan_type="benchmark")
async def benchmark(request: BenchmarkScanRequest):
    """
    Launch a benchmark scan.

    This endpoint initiates a benchmark scan which can be either:
    - A full scan (typeOfScan=AUDIT_AGENT) using all available detectors
    - A model-only scan (typeOfScan=MODEL) using a specific LLM model

    Args:
        request (BenchmarkScanRequest): The request object containing:
            - repositoryURL (str): URL of the GitHub repository to scan
            - contractFiles (List[str]): Array of contract files to analyze
            - branchName (str): Branch to scan (defaults to 'main')
            - docs (Optional[str]): Project documentation to use for multi-agent scans
            - typeOfScan (TypeOfScan): Type of scan to perform
            - model (Optional[str]): LLM model to use (required for model-only scans)
            - mode (Optional[ModeType]): Mode to use (defaults to FEW_SHOTS)

    Returns:
        SuccessResponse: Response containing the scan_id
    """
    scan_id = uuid4()
    service = BenchmarkService()
    await service.create_scan(scan_id, scan_type=ScanType.BENCHMARK, request=request)
    return SuccessResponse(data=scan_id)


@router.get("/result/{scan_id}")
async def get_result(scan_id: str):
    """
    Get benchmark result for a specific scan.

    Args:
        scan_id (str): The ID of the scan to retrieve results for

    Returns:
        SuccessResponse: Response containing the scan results
        ErrorResponse: If the scan is not found
    """
    full_result = await ScanRepository.get_scan_result(UUID(scan_id))
    if not full_result:
        return ErrorResponse(message="scan_not_found", code=404)
    return SuccessResponse(data=full_result)
