##################################################
#                   SLITHER
##################################################

# Confidence levels of detection to include
CONFIDENCE_LEVELS = ["high", "medium"]

# Mapping of known packages to their repositories
PACKAGE_MAPPING = {
    "openzeppelin-contracts-upgradeable": "openzeppelin/openzeppelin-contracts-upgradeable",
    "openzeppelin-contracts": "openzeppelin/openzeppelin-contracts",
    "chainlink": "smartcontractkit/chainlink",
    "solady": "Vectorized/solady",
    "solmate": "rari-capital/solmate",
    # Add more known packages here if needed
}


##################################################
#               FRAMEWORKS CONFIG
##################################################

SOLIDITY_EXTENSION = ".sol"
POSSIBLE_CONTRACT_FOLDERS = ["contracts", "src"]

FOUNDRY_CONFIG = "foundry.toml"
HARDHAT_CONFIGS = [
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
]
BROWNIE_CONFIGS = ["brownie-config.yaml", "brownie-config.json"]
