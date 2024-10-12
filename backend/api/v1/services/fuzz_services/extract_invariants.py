import json
from typing import List


def extract_invariants(llm_response: str) -> List[dict]:
    """
    Extracts the invariants from the LLM response.

    Args:
        llm_response (str): The response from the LLM containing the invariants.

    Returns:
        List[dict]: A list of extracted invariants.
    """
    # Strip the ```json from the llm_response and convert it to JSON data
    try:
        # Remove the code block markers
        invariants_data = json.loads(llm_response.strip("```json").strip("```"))

        return invariants_data.get("invariants", [])
    except json.JSONDecodeError as e:
        raise ValueError("Failed to decode JSON from LLM response") from e
