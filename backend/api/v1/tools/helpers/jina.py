import requests


class JinaParser:
    def __init__(self):
        self.base_url = "https://r.jina.ai"

    async def parse(self, url: str) -> str:
        try:
            jina_url = f"{self.base_url}/{url}"
            response = requests.get(jina_url)
            return response.text
        except Exception as e:
            return f"Error parsing {url}: {e}"


jina_parser = JinaParser()


async def parse(url: str) -> str:
    return await jina_parser.parse(url)


def get_description() -> str:
    """
    Returns the description for the jina_parse tool.
    """
    return "jina_parse: Parses content from URLs using Jina's API and returns the result text."
