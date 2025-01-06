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
