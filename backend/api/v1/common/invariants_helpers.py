from typing import Dict, List, Optional

from core.db.repositories.scan import ScanRepository
from core.models.scan import Invariant
from core.utils.errors import QueryError, RepositoryError, ScanError
from core.utils.logger import logger


async def get_saved_invariants(repository_url: str, user_id: str) -> Optional[List[Invariant]]:
    """
    Get saved invariants for a specific repository.
    Returns the Invariant list, or None if no invariants exist.
    """
    try:
        invariants = await ScanRepository.get_invariants(repository_url, user_id)
        if not invariants:
            return None

        return invariants

    except (ScanError, QueryError):
        raise
    except Exception as e:
        logger.error(f"Error retrieving repository invariants: {str(e)}")
        raise RepositoryError("Error retrieving repository invariants", {"error": str(e)})


def flatten_contracts(
    contract_contents: Dict[str, str], selected_invariants: List[Invariant]
) -> str:
    flattened_contracts = ""
    for path, content in contract_contents.items():
        for invariant in selected_invariants:
            if path == invariant.path:
                flattened_contracts += f"// File: {path}\n"
                flattened_contracts += content + "\n\n"
                break
    return flattened_contracts
