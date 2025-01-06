from typing import Optional

from api.v1.github.helpers.github_api_client import GitHubAPIClient
from core.db.repositories.docs import DocsRepository
from core.models.docs import QAResponse
from core.utils.logger import logger

github_api_client = GitHubAPIClient()


async def get_formatted_docs(
    repository_url: str,
    user_id: str,
    access_token: str,
    branch: str = "main",
) -> Optional[str]:
    """
    Get formatted documentation for use in LLM prompts.
    Returns a formatted string combining readme contents and QA data, or None if no docs exist.
    """
    try:
        docs = await DocsRepository.get_docs(repository_url, user_id)
        if not docs:
            return None

        formatted_text = ["# Repository Documentation\n"]

        # Fetch and add README contents if available
        if docs.docs.readme:
            formatted_text.append("## README Contents\n")
            owner, repo = github_api_client.parse_github_url(repository_url)

            for readme_path in docs.docs.readme:
                try:
                    content = await github_api_client.get_file_content(
                        access_token, owner, repo, readme_path, branch
                    )
                    formatted_text.append(f"### {readme_path}\n{content}\n")
                except Exception as e:
                    logger.error(f"Failed to fetch readme content for {readme_path}: {str(e)}")
                    continue

        # Add Q&A content
        if docs.docs.qa:
            formatted_text.append("## Additional Documentation\n")
            for question_num, answer in sorted(docs.docs.qa.items(), key=lambda x: int(x[0])):
                formatted_text.append(f"Answer {question_num}: {answer}\n")

        return "\n".join(formatted_text)

    except Exception as e:
        logger.error(f"Error formatting repository docs: {str(e)}")
        return None


async def get_json_docs(repository_url: str, user_id: str) -> Optional[QAResponse]:
    """
    Get repository documentation in its original JSON format.
    Returns the QAResponse object as it was stored, or None if no docs exist.
    """
    try:
        docs = await DocsRepository.get_docs(repository_url, user_id)
        if not docs:
            return None

        return docs.docs

    except Exception as e:
        logger.error(f"Error retrieving repository docs: {str(e)}")
        return None


async def format_docs_for_prompt(
    docs: QAResponse, access_token: str, owner: str, repo: str, branch_name: str
) -> Optional[str]:
    """
    Format the QAResponse data into a string suitable for the context scan prompt.
    This includes fetching the actual readme contents and formatting Q&A data.
    """

    formatted_sections = []

    # Handle README files if present
    if docs.readme:
        formatted_sections.append("# Project Documentation\n")

        for readme_path in docs.readme:
            try:
                content = await github_api_client.get_file_content(
                    access_token, owner, repo, readme_path, branch_name
                )
                formatted_sections.append(f"## {readme_path}\n{content}\n")
            except Exception as e:
                logger.error(f"Failed to fetch readme content for {readme_path}: {str(e)}")
                continue

    # Handle Q&A data if present
    if docs.qa:
        formatted_sections.append("\n# Additional Documentation\n")
        # Sort by question number to maintain consistent order
        for question_num, answer in sorted(docs.qa.items(), key=lambda x: int(x[0])):
            formatted_sections.append(f"Q{question_num}: {answer}\n")

    return "\n".join(formatted_sections) if formatted_sections else None
