# core/schemas/context_protocols.py
from typing import Dict, Optional, Protocol, runtime_checkable

from core.schemas.scan_schema import ModeType, SetupResult, TypeOfScan


@runtime_checkable
class GitHubContext(Protocol):
    """Protocol for contexts that support GitHub operations."""

    repository_name: Optional[str]
    repository_url: str
    branch_name: str
    commit_hash: Optional[str]


@runtime_checkable
class ChainContext(Protocol):
    """Protocol for contexts that support blockchain operations."""

    contract_address: str
    chain_id: int
    contracts_dict: Optional[Dict[str, str]]


@runtime_checkable
class UserContext(Protocol):
    """Protocol for contexts that contain user information."""

    user_id: str
    user_email: Optional[str]
    user_name: Optional[str]
    user_access_token: Optional[str]


@runtime_checkable
class CompilationContext(Protocol):
    """Protocol for contexts that support GitHub operations."""

    repo_dir: Optional[str]
    temp_dir: Optional[str]
    setup_result: Optional[SetupResult]


@runtime_checkable
class BenchmarkContext(Protocol):
    """Protocol for contexts that support benchmark operations."""

    type_of_scan: TypeOfScan
    model: Optional[str]
    mode: Optional[ModeType]
