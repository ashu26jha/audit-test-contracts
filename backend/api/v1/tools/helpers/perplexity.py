import json

from perplexity import Perplexity


class PerplexitySearcher:
    def __init__(self):
        self.client = None

    async def search(self, query: str) -> str:
        try:
            if not self.client:
                self.client = Perplexity()

            answer = self.client.search(query)

            for response in answer:
                if response["status"] == "completed":
                    return json.loads(response["text"])["answer"]
                elif response["status"] == "failed":
                    return f"Error searching on Perplexity: {response['error']}"

            return "No complete response received from Perplexity"

        except Exception as e:
            return f"Error searching on Perplexity: {e}"
        finally:
            if self.client:
                self.client.close()
                self.client = None


perplexity_searcher = PerplexitySearcher()


async def search(query: str) -> str:
    return await perplexity_searcher.search(query)


def get_description() -> str:
    """
    Returns the description for the perplexity_search tool.
    """
    return "perplexity_search: Uses Perplexity to answer queries with help on internet search. AI summarise the results. Good for quick answers."
