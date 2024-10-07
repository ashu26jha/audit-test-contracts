from api.v1.schemas import static_analyzer_schema
from api.v1.services import static_analyzer_service
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.post("/static-analyzer", response_model=static_analyzer_schema.StaticAnalyzerResponse)
async def analyze_repository(request: static_analyzer_schema.StaticAnalyzerRequest):
    try:
        result = await static_analyzer_service.clone_and_analyze_repo(
            request.github_url, request.oauth_token
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during the analysis process: {str(e)}",
        )
