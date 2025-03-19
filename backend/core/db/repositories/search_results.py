from datetime import datetime, timedelta, timezone

from core.models.search_results import CachedContent


class SearchResults:
    """
    Stores the summarised content of the visited websites.
    """

    @staticmethod
    async def check_if_visited(url: str) -> bool:
        """
        Returns True if the URL has been visited and its summarised content is stored in the database.
        Otherwise, returns False.
        """
        return (await CachedContent.find_one({"link": url})) is not None

    @staticmethod
    async def fetch_link_content(url: str) -> str:
        """
        Fetches content of a link from DB.
        """
        result = await CachedContent.find_one({"link": url})
        return result.content if result is not None else ""

    @staticmethod
    async def add_content(url: str, content: str):
        """
        Adds content for a URL
        """
        new_entry = CachedContent(link=url, content=content)
        await new_entry.insert()

    @staticmethod
    async def cleanup_old_results(days: int = 14):
        """
        Deletes cached content older than the specified number of days.
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        deletion_result = await CachedContent.find({"created_at": {"$lt": cutoff_date}}).delete()
        return deletion_result
