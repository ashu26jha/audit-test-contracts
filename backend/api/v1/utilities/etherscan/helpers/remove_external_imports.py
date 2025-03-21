from api.v1.utilities.etherscan.schema import ContractSourceCodeResponse, RemoveLibraryResponse
from config.prompts.remove_library_prompts import LIBRARY_REMOVE_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils import logger


async def remove_external_imports(
    source_code: ContractSourceCodeResponse,
) -> ContractSourceCodeResponse:
    """
    Send source code to LLM to identify libraries to remove and remove them
    If LLM call fails, returns the original source code.

    Args:
        source_code: Dictionary mapping file names to their content and token length

    Returns:
        ContractSourceCodeResponse: Source code with identified libraries removed
    """
    logger.info(f"[Etherscan] Removing external imports from {len(source_code)} files...")

    try:
        # Format libraries for LLM
        libraries = "\n".join(source_code.keys())
        prompt = LIBRARY_REMOVE_PROMPT.format(libraries=libraries)

        # Send the prompt to LLM
        response = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY, messages=prompt, response_model=RemoveLibraryResponse
        )

        # Check if the LLM returned a valid response
        if not response or not response.libraries_to_remove:
            logger.warning(
                "[Etherscan] No libraries to remove returned from LLM, returning original source code"
            )
            return source_code

        libraries_to_remove = response.libraries_to_remove

        # Remove identified libraries from source code
        for lib in libraries_to_remove:
            if lib in source_code:
                source_code.pop(lib)

        return source_code
    except Exception as e:
        logger.error(f"[Etherscan] Error removing external imports: {str(e)}")
        # Return original source code on error
        return source_code
