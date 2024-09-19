import re

def extract_fuzz_test(llm_response: str) -> str:
    """
    Extracts the Solidity fuzz test from the LLM response.

    Args:
        llm_response (str): The response from the LLM containing the fuzz test.

    Returns:
        str: The extracted Solidity fuzz test code.
    """
    # Use regex to find the Solidity code block
    solidity_match = re.search(r'```solidity\n(.*?)```', llm_response, re.DOTALL)
    
    if solidity_match:
        # Extract the Solidity code and remove any leading/trailing whitespace
        fuzz_test = solidity_match.group(1).strip()
        
        # Remove any remaining "```" if present
        fuzz_test = fuzz_test.replace('```', '')
        
        return fuzz_test
    else:
        # If no Solidity code block is found, return an empty string or raise an exception
        raise ValueError("No Solidity fuzz test found in the LLM response.")