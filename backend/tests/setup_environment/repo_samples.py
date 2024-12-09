import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RepoConfig:
    """Repository configuration for testing"""

    url: str
    project_type: str
    contract_paths: List[str]
    description: str
    branch: str = "main"
    is_subrepo: bool = False
    expected_root: Optional[str] = None

    def __str__(self):
        return f"{self.description} ({self.url})"


TEST_REPOS = [
    # Foundry Projects in Root
    RepoConfig(
        url="https://github.com/Pedrojok01/repo-0-",
        project_type="foundry",
        contract_paths=["src/registry.sol", "src/factory/Factory.sol"],
        description="Basic Foundry project at root",
    ),
    RepoConfig(
        url="https://github.com/PWNDAO/pwn_dao",
        project_type="foundry",
        contract_paths=[
            "src/PWNEpochClock.sol",
            "src/governance/permmission/DAOExecuteAllowlist.sol",
        ],
        description="Foundry project with dependencies",
    ),
    RepoConfig(
        url="https://github.com/Pedrojok01/deploy-to-skale.git",
        project_type="foundry",
        contract_paths=[
            "src/pool/PoolConfigurator.sol",
            "src/pool/Pool.sol",
            "src/providers/PoolAddressesProvider.sol",
        ],
        description="Foundry project with submodules",
    ),
    # Foundry Projects in Subfolder
    RepoConfig(
        url="https://github.com/Pedrojok01/fury-racing",
        project_type="foundry",
        contract_paths=[
            "contracts/src/Racing.sol",
            "contracts/src/ChainlinkFeed.sol",
            "contracts/src/FunctionsSource.sol",
        ],
        is_subrepo=True,
        expected_root="contracts",
        description="Foundry project in contracts/ subdirectory",
    ),
    RepoConfig(
        url="https://github.com/Pedrojok01/PackMyNFT",
        project_type="foundry",
        contract_paths=[
            "foundry/src/PackMyNFT.sol",
            "foundry/src/interfaces/IPackMyNFT.sol",
        ],
        is_subrepo=True,
        expected_root="foundry",
        description="Foundry project in foundry/ subdirectory",
    ),
    # Hardhat Projects in Root
    RepoConfig(
        url="https://github.com/Pedrojok01/SmartContracts-GamingPlatform",
        project_type="hardhat",
        contract_paths=[
            "contracts/Game.sol",
            "contracts/GameFactory.sol",
            "contracts/PaymentManager.sol",
        ],
        description="Standard Hardhat project at root",
    ),
    RepoConfig(
        url="https://github.com/Pedrojok01/loyalty_contracts",
        project_type="hardhat",
        contract_paths=[
            "contracts/loyaltyProgram/LoyaltyProgram.sol",
            "contracts/subscriptions/Subscriptions.sol",
        ],
        description="Hardhat project with simple structure",
    ),
    RepoConfig(
        url="https://github.com/idriss-xyz/contracts",
        project_type="hardhat",
        contract_paths=[
            "src/contracts/SendToHash.sol",
            "src/contracts/IDrissWrapperContract.sol",
            "src/contracts/structs/IDrissStructs.sol",
        ],
        description="Hardhat project with src/contracts structure",
    ),
    # Hardhat Projects in Subfolder
    RepoConfig(
        url="https://github.com/Pedrojok01/CryptoCats",
        project_type="hardhat",
        contract_paths=[
            "contracts/CatContract.sol",
            "contracts/CatMarketplace.sol",
            "contracts/interface/ICatMarketplace.sol",
        ],
        branch="nextJS",
        is_subrepo=True,
        expected_root=os.path.join("hardhat", "foundry_project"),
        description="Hardhat project in hardhat/ subdirectory",
    ),
    RepoConfig(
        url="https://github.com/NexusMutual/smart-contracts",
        project_type="hardhat",
        contract_paths=[
            "contracts/modules/cover/Cover.sol",
            "contracts/modules/governance/Governance.sol",
            "contracts/modules/capital/Pool.sol",
        ],
        description="Complex Hardhat project with modules",
        branch="release-candidate",
        is_subrepo=False,
    ),
]
