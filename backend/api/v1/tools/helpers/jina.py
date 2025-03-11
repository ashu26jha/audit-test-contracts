import requests

BASE_URL = "https://r.jina.ai"


async def jina_parse(url: str) -> str:
    try:
        jina_url = f"{BASE_URL}/{url}"
        response = requests.get(jina_url)
        return response.text
    except Exception as e:
        return f"Error parsing {url}: {e}"


def get_description() -> str:
    """
    Returns the description for the jina_parse tool.
    """
    return "jina_parse: Parses content from URLs using Jina's API and returns the result text."
