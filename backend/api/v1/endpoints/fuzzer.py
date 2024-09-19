import os
import shutil
import tempfile
import uuid
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from api.v1.schemas.fuzzer_schema import FuzzerRequest, FuzzerResponse
from api.v1.services.fuzzing_service import run_fuzzer

router = APIRouter()

@router.post("/fuzzer", response_model=FuzzerResponse)
async def execute_fuzzer(request: FuzzerRequest):
    try:
        result = await run_fuzzer(request.contract, request.contract_name)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"contract_name": request.contract_name, "error": str(e), "fuzz_test": None, "fuzz_results": None, "analysis": None})
