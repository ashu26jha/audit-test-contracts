from typing import Optional

import aiohttp
from fastapi import HTTPException

from config.settings import BASE_ETHERSCAN_URL, ETHERSCAN_API_KEY
from core.utils import logger

from .helpers.etherscan_helper import parse_source_code, remove_external_libraries
from .schema import ContractSourceCodeResponse

if not ETHERSCAN_API_KEY:
    raise ValueError("ETHERSCAN_API_KEY is not set in the environment variables")


class EtherscanService:
    @staticmethod
    async def get_contract_source(
        contract_address: str,
        chain_id: int,
    ) -> Optional[ContractSourceCodeResponse]:
        """
        Fetch smart contract source code from Etherscan using v2 API

        Args:
            contract_address: Contract address
            chain_id: Chain ID

        Returns:
            ContractSourceCodeResponse: Mapping of .sol file names to their content, or None if failed
        """
        try:
            logger.info(
                f"[Etherscan] Fetching source code for contract {contract_address} on chain {chain_id}..."
            )

            params = {
                "chainid": chain_id,
                "module": "contract",
                "action": "getsourcecode",
                "address": contract_address,
                "apikey": ETHERSCAN_API_KEY,
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(BASE_ETHERSCAN_URL, params=params) as response:
                    if response.status != 200:
                        logger.error(f"[Etherscan] Etherscan API error: {response.status}")
                        return None

                    data = await response.json()

                    if data["status"] != "1" or data["message"] != "OK":
                        logger.error(
                            f"[Etherscan] Etherscan API error: {data.get('message', 'Unknown error')}"
                        )
                        return None

                    result = data["result"][0]

                    if result["SourceCode"] == "":
                        logger.error(
                            f"[Etherscan] No source code found for contract {contract_address}"
                        )
                        raise HTTPException(
                            status_code=404, detail="Source code not found or not verified"
                        )

                    parsed_source_code = parse_source_code(result["SourceCode"])
                    cleaned_source_code = await remove_external_libraries(parsed_source_code)

                    logger.info(
                        f"[Etherscan] Source code fetched and cleaned for contract {contract_address}"
                    )
                    return cleaned_source_code
        except Exception as e:
            logger.error(f"[Etherscan] Error fetching contract source code: {str(e)}")
            raise HTTPException(
                status_code=500, detail="Error fetching contract source code"
            ) from e
