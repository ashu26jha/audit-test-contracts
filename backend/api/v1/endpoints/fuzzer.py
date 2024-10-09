from api.v1.schemas.fuzzer_schema import FuzzerRequest, FuzzerResponse
from api.v1.services.fuzzing_service import run_fuzzer
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.post("/fuzzer", response_model=FuzzerResponse)
async def execute_fuzzer(request: FuzzerRequest):
    try:
        result = await run_fuzzer(
            request.github_url,
            request.oauth_token,
            request.selected_contracts,
            request.setup_result,
            request.slither_output,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during the fuzzing process: {str(e)}",
        )
