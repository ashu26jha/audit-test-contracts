from typing import Union

from fastapi import APIRouter, Depends, HTTPException, status

from api.v1.auth.helpers.dependencies import get_api_key
from api.v1.utilities.invariants.schema import InvariantsRequest, InvariantsResponse
from api.v1.utilities.invariants.service import generate_invariants
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.logger import logger

router = APIRouter(tags=["utilities"])


@router.get(
    "/generate-invariants",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[InvariantsResponse], ErrorResponse],
)
async def get_invariants(request: InvariantsRequest):
    """
    Generate up to 50 invariants for a contract.
    Requires API key authentication.
    """
    try:
        invariants = await generate_invariants(
            contracts_in_scope=request.contracts_in_scope,
            flattened_contracts=request.flattened_contracts,
            docs=request.docs,
            max_invariants=50,
        )
        return SuccessResponse(data=invariants)
    except Exception as e:
        logger.error(f"[Invariants] Error in invariants route: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while generating invariants",
        )
