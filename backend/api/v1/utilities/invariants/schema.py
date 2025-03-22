from typing import Annotated, List, Optional

from pydantic import BaseModel, Field


class Invariant(BaseModel):
    description: Annotated[str, Field(description="The description of the invariants")]
    function: Annotated[str, Field(description="The function name of the invariant")]
    condition: Annotated[str, Field(description="The condition of the invariant")]
    path: Annotated[
        Optional[str], Field(description="The path to the file where the invariant applies")
    ]


class InvariantsRequest(BaseModel):
    contracts_in_scope: Annotated[
        List[str],
        Field(
            description="List of contract file paths to analyze (e.g., ['src/ContestManager.sol', 'src/Pot.sol'])"
        ),
    ]
    flattened_contracts: Annotated[
        str,
        Field(description="The complete flattened source code of all contracts"),
    ]
    docs: Optional[str]


class InvariantsResponse(BaseModel):
    invariants: list[Invariant]
