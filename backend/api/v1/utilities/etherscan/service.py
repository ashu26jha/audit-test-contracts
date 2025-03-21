import aiohttp

from config.settings import BASE_ETHERSCAN_URL, ETHERSCAN_API_KEY
from core.utils import logger
from core.utils.errors import EtherscanError

from .helpers.etherscan_helper import parse_source_code, remove_external_libraries
from .schema import ContractSourceCodeResponse

if not ETHERSCAN_API_KEY:
    raise ValueError("ETHERSCAN_API_KEY is not set in the environment variables")


class EtherscanService:
    @staticmethod
    async def get_contract_source(
        contract_address: str,
        chain_id: int,
    ) -> ContractSourceCodeResponse:
        """
        Fetch smart contract source code from Etherscan using v2 API

        Args:
            contract_address: Contract address
            chain_id: Chain ID

        Returns:
            ContractSourceCodeResponse: Mapping of .sol file names to their content

        Raises:
            EtherscanError: If there is an error fetching or parsing the source code
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
                        error_msg = f"Etherscan API returned status {response.status}"
                        logger.error(f"[Etherscan] {error_msg}")
                        raise EtherscanError(error_msg)

                    data = await response.json()

                    if data["status"] != "1" or data["message"] != "OK":
                        error_msg = f"Etherscan API error: {data.get('message', 'Unknown error')}"
                        logger.error(f"[Etherscan] {error_msg}")
                        raise EtherscanError(error_msg)

                    result = data["result"][0]

                    if result["SourceCode"] == "":
                        error_msg = f"No source code found for contract {contract_address}"
                        logger.error(f"[Etherscan] {error_msg}")
                        raise EtherscanError(error_msg)

                    parsed_source_code = parse_source_code(result["SourceCode"])
                    if not parsed_source_code:
                        raise EtherscanError(
                            f"Failed to parse source code for contract {contract_address}"
                        )

                    cleaned_source_code = await remove_external_libraries(parsed_source_code)

                    logger.info(
                        f"[Etherscan] Source code fetched and cleaned for contract {contract_address}"
                    )
                    return cleaned_source_code
        except EtherscanError:
            raise
        except Exception as e:
            error_msg = f"Error fetching contract source code: {str(e)}"
            logger.error(f"[Etherscan] {error_msg}")
            raise EtherscanError(error_msg) from e
