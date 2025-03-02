from datetime import datetime, timezone
from typing import Optional

from core.models.docs import QAResponse, ReadmeDocs
from core.utils.errors import QueryError
from core.utils.logger import logger


class DocsRepository:
    """Repository for managing repository documentation records in the database."""

    @staticmethod
    async def get_docs(repository_url: str, user_id: str) -> Optional[ReadmeDocs]:
        """
        Get docs for a repository and user.

        Raises:
            QueryError: If the database query fails
        """
        try:
            return await ReadmeDocs.find_one({"repository_url": repository_url, "user_id": user_id})
        except Exception as e:
            logger.error(f"[Scan Init] Failed to fetch repository docs: {str(e)}")
            raise QueryError(
                message="Failed to fetch repository docs",
                details={"repository_url": repository_url, "user_id": user_id, "error": str(e)},
            ) from e

    @staticmethod
    async def store_docs(repository_url: str, user_id: str, docs: QAResponse) -> None:
        """Store or update repository documentation."""
        try:
            existing_docs = await DocsRepository.get_docs(repository_url, user_id)

            if existing_docs:
                existing_docs.docs = docs
                existing_docs.updated_at = datetime.now(timezone.utc)
                await existing_docs.save()
            else:
                new_docs = ReadmeDocs(
                    repository_url=repository_url,
                    user_id=user_id,
                    docs=docs,
                )
                await new_docs.save()

            logger.info(
                f"[Scan Init] Stored docs for repository {repository_url} and user {user_id}"
            )
        except Exception as e:
            logger.error(f"[Scan Init] Failed to store repository docs: {str(e)}")
            # Don't raise the exception - we don't want to fail the scan if docs storage fails
