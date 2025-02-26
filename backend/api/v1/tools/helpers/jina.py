import requests

from config.settings import JINA_API_KEY
from core.utils.logger import logger


class JinaParser:
    def __init__(self):
        self.base_url = "https://r.jina.ai"
        self.headers = {"Authorization": f"Bearer {JINA_API_KEY}"}

    async def parse(self, url: str) -> str:
        try:
            jina_url = f"{self.base_url}/{url}"
            response = requests.get(jina_url, headers=self.headers)
            return response.text
        except Exception as e:
            error_msg = f"Unexpected error with Jina API: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}


jina_parser = JinaParser()


async def parse(url: str) -> str:
    return await jina_parser.parse(url)


def get_description() -> str:
    """
    Returns the description for the jina_parse tool.
    """
    return "jina_parse: Parses content from URLs using Jina's API and returns the result text."
