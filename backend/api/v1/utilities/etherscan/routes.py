from typing import Union

from fastapi import APIRouter, HTTPException, status

from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import EtherscanError
from core.utils.logger import logger

from .schema import ContractSourceCodeResponse, GetContractSourceCodeRequest
from .service import EtherscanService

router = APIRouter(prefix="/etherscan", tags=["utilities"])


@router.post(
    "/source-code",
    response_model=Union[SuccessResponse[ContractSourceCodeResponse], ErrorResponse],
)
async def get_contract_source_code(request: GetContractSourceCodeRequest):
    """
    Fetch the source code of a deployed contract from Etherscan.
    This endpoint is only available in development mode.

    Args:
        contract_address: The address of the contract.
        chain_id: The ID of the EVM compatible chain (default is 1 for mainnet).

    Returns:
        The source code of the contract or an error response.
    """
    try:
        source_code = await EtherscanService.get_contract_source(
            contract_address=request.contractAddress,
            chain_id=request.chainId,
        )
        return SuccessResponse(data=source_code)
    except EtherscanError as e:
        logger.error(f"[Etherscan] Error retrieving source code: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving source code: {e}",
        )
