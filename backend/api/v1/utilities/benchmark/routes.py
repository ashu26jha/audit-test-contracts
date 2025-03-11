from uuid import UUID, uuid4

from fastapi import APIRouter

from api.v1.utilities.benchmark.schema import BenchmarkScanRequest
from api.v1.utilities.benchmark.service import BenchmarkService
from core.db.repositories.scan import ScanRepository
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.schemas.scan_schema import ScanType

router = APIRouter(prefix="/benchmark", tags=["scanner"])


@router.post("/launch")
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
