from pydantic import BaseModel


class GitHubRepoResponse(BaseModel):
    repo_name: str
    repo_full_name: str
    owner: str
    default_branch: str
    repo_url: str
