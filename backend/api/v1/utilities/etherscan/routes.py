from typing import Union

from fastapi import APIRouter

from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

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
    source_code = await EtherscanService.get_contract_source(
        contract_address=request.contractAddress,
        chain_id=request.chainId,
    )
    return SuccessResponse(data=source_code)
