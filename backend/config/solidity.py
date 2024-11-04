##################################################
#               FRAMEWORKS CONFIG
##################################################

SOLIDITY_EXTENSION = ".sol"

FOUNDRY_CONFIGS = ["foundry.toml", "foundry.config.toml"]
HARDHAT_CONFIGS = [
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
    "hardhat.config.json",
    "hardhat.config.esm.mjs",
]
BROWNIE_CONFIGS = ["brownie-config.yaml", "brownie-config.json", "brownie-config.yml"]


##################################################
#                 FORGE COMMANDS
##################################################

FORGE_INIT_COMMAND = ["forge", "init", "--force", "--no-commit"]
FORGE_INSTALL_COMMAND = ["forge", "install", "--no-commit"]
FORGE_REMAP_COMMAND = ["forge", "remappings"]
FORGE_BUILD_COMMAND = ["forge", "build"]
FORGE_TEST_COMMAND = ["forge", "test", "-vvvv"]


##################################################
#                   SLITHER
##################################################

# Confidence levels of detection to include
CONFIDENCE_LEVELS = ["high"]

# Mapping of known Solidity package names to their GitHub repositories (Currently not used)
PACKAGE_MAPPING = {
    "@openzeppelin/contracts": {
        "github": "OpenZeppelin/openzeppelin-contracts",
        "import_path": "@openzeppelin/contracts",
        "lib_folder": "openzeppelin-contracts/contracts",
    },
    "@openzeppelin/contracts-upgradeable": {
        "github": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "import_path": "@openzeppelin/contracts-upgradeable",
        "lib_folder": "openzeppelin-contracts-upgradeable",
    },
    "@chainlink/contracts": {
        "github": "smartcontractkit/chainlink",
        "import_path": "@chainlink/contracts",
        "lib_folder": "chainlink",
    },
    "@chainlink/hardhat-chainlink": {
        "github": "smartcontractkit/hardhat-chainlink",
        "import_path": "@chainlink/hardhat-chainlink",
        "lib_folder": "",
    },
    "solady": {
        "github": "Vectorized/solady",
        "import_path": "solady",
        "lib_folder": "",
    },
    "solmate": {
        "github": "transmissions11/solmate",
        "import_path": "solmate",
        "lib_folder": "",
    },
    "synthetix": {
        "github": "Synthetixio/synthetix",
        "import_path": "synthetix",
        "lib_folder": "",
    },
    "@layerzerolabs/contracts": {
        "github": "LLayerZero-Labs/LayerZero",
        "import_path": "@layerzerolabs/contracts",
        "lib_folder": "",
    },
    "@aave/core-v3": {
        "github": "aave/aave-v3-core",
        "import_path": "@aave/core-v3",
        "lib_folder": "",
    },
    "@aave/periphery-v3": {
        "github": "aave/aave-v3-periphery",
        "import_path": "@aave/periphery-v3",
        "lib_folder": "",
    },
    "@ensdomains/ens-contracts": {
        "github": "ensdomains/ens-contracts",
        "import_path": "@ensdomains/ens-contracts",
        "lib_folder": "",
    },
    "@balancer-labs/v2-interfaces": {
        "github": "balancer/balancer-v2-monorepo",
        "import_path": "@balancer-labs/v2-interfaces",
        "lib_folder": "",
    },
    "@uniswap/v3-periphery": {
        "github": "Uniswap/v3-periphery",
        "import_path": "@uniswap/v3-periphery",
        "lib_folder": "",
    },
    "@uniswap/v3-core": {
        "github": "Uniswap/v3-core",
        "import_path": "@uniswap/v3-core",
        "lib_folder": "",
    },
    "@uniswap/v2-periphery": {
        "github": "Uniswap/v2-periphery",
        "import_path": "@uniswap/v2-periphery",
        "lib_folder": "",
    },
    "@uniswap/v2-core": {
        "github": "Uniswap/v2-core",
        "import_path": "@uniswap/v2-core",
        "lib_folder": "",
    },
    "@0x/contracts-zero-ex": {
        "github": "0xProject/protocol",
        "import_path": "@0x/contracts-zero-ex",
        "lib_folder": "",
    },
    # Add more known Solidity packages here
}
