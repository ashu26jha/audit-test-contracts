from datetime import datetime, timezone

import pytest

from core.db.repositories.search_results import SearchResults
from core.models.search_results import CachedContent

pytestmark = pytest.mark.asyncio


class TestSearchResultsRepository:
    """Tests for the SearchResults repository."""

    @pytest.fixture(autouse=True)
    async def cleanup_db(self, setup_db):
        """Clean up the database before each test."""
        await CachedContent.delete_all()
        yield
        await CachedContent.delete_all()

    async def test_check_if_visited_url_exists(self):
        """Test check_if_visited returns True when URL exists."""
        test_url = "https://example.com/test"
        test_content = "Test content for example.com"
        await CachedContent(
            link=test_url,
            content=test_content,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ).insert()

        result = await SearchResults.check_if_visited(test_url)

        assert result is True

    async def test_check_if_visited_url_not_exists(self):
        """Test check_if_visited returns False when URL does not exist."""
        test_url = "https://example.com/nonexistent"

        result = await SearchResults.check_if_visited(test_url)

        assert result is False

    async def test_fetch_link_content_url_exists(self):
        """Test fetch_link_content returns content when URL exists."""
        test_url = "https://example.com/fetch-test"
        test_content = "Content to be fetched"
        await CachedContent(
            link=test_url,
            content=test_content,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ).insert()

        result = await SearchResults.fetch_link_content(test_url)

        assert result == test_content

    async def test_fetch_link_content_url_not_exists(self):
        """Test fetch_link_content returns empty string when URL does not exist."""
        test_url = "https://example.com/nonexistent-fetch"

        result = await SearchResults.fetch_link_content(test_url)

        assert result == ""

    async def test_add_content(self):
        """Test add_content adds a new entry to the database."""
        test_url = "https://example.com/add-test"
        test_content = "Content to be added"

        await SearchResults.add_content(test_url, test_content)

        saved_content = await CachedContent.find_one({"link": test_url})
        assert saved_content is not None
        assert saved_content.content == test_content
        assert saved_content.link == test_url
        assert isinstance(saved_content.created_at, datetime)
        assert isinstance(saved_content.updated_at, datetime)
