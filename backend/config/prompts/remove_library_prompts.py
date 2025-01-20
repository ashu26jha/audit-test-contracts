LIBRARY_REMOVE_PROMPT = """
You are given a list of imported smart contract paths that are used in a solidity project. To audit this projects, I need to identify the contracts in scope, and filter the externak libraries out. Your task is to identify and remove all external libraries that are not in the project scope so I can easily remove them from the project's code base. In addition to all popular librairies like OpenZeppelin, the easiest way to identify the contracts in scope is o look for local imports. There are usually either in the src/ folder for foundry projects, or in the contracts/ folder for hardhat projects.

**Additional considerations:**
- Do not change path of the imported contracts.
- Do not change the name of the imported contracts.
- Remove all popular libraries and contracts that are not in the project scope.

Return the list of libraries that should not be included in the scope of a professional audit in a JSON array format with the following structure:

```json
    {{
        "libraries_to_remove": ["@openzeppelin/contract1", "@external/contract2", "lib/contract3"]
    }}
```

List of the libraries to check and filter:
{libraries}
"""
