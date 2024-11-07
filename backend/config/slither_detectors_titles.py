SLITHER_DETECTOR_MAP = {
    "abiencoderv2-array": {
        "title": "Unsafe ABIEncoderV2 Array Encoding",
        "description": "Identifies potential vulnerabilities in storage arrays encoded using ABIEncoderV2. This issue may lead to data corruption or unexpected behavior in contract interactions.",
    },
    "arbitrary-send-erc20": {
        "title": "Unauthorized ERC20 Token Transfer",
        "description": "Detects functions that allow arbitrary transfer of ERC20 tokens without proper access controls. This vulnerability could lead to unauthorized token movements and potential fund loss.",
    },
    "array-by-reference": {
        "title": "Unintended Storage Array Modification",
        "description": "Highlights instances where arrays passed by reference may lead to unintended storage modifications. This can result in unexpected state changes and potential security vulnerabilities.",
    },
    "encode-packed-collision": {
        "title": "ABI Encoding Collision Risk",
        "description": "Identifies potential collisions in ABI packed encoding that could lead to data misinterpretation. This issue may result in contract vulnerabilities or unexpected behavior in cross-contract interactions.",
    },
    "incorrect-shift": {
        "title": "Incorrect Bit Shift Operation",
        "description": "Detects bit shift operations that may produce unexpected results or lead to incorrect data manipulation. This can cause logical errors or vulnerabilities in arithmetic operations.",
    },
    "multiple-constructors": {
        "title": "Multiple Constructor Definitions",
        "description": "Identifies contracts with multiple constructor definitions, which is invalid in Solidity. This can lead to unexpected initialization behavior and potential security risks.",
    },
    "name-reused": {
        "title": "Duplicate Contract Name",
        "description": "Detects the reuse of contract names within the project, which can cause naming conflicts and lead to unexpected behavior during deployment or interaction.",
    },
    "protected-vars": {
        "title": "Inadequately Protected Critical Variables",
        "description": "Identifies critical variables with insufficient access controls, potentially exposing sensitive data or allowing unauthorized modifications to contract state.",
    },
    "public-mappings-nested": {
        "title": "Exposed Nested Mapping Data",
        "description": "Detects public nested mappings that may unintentionally expose internal data structures, potentially leading to information leakage or manipulation.",
    },
    "rtlo": {
        "title": "Right-To-Left Override Character Usage",
        "description": "Identifies the use of Right-To-Left Override (RTLO) Unicode characters, which can be exploited to obfuscate malicious code and mislead auditors or developers.",
    },
    "shadowing-state": {
        "title": "State Variable Shadowing",
        "description": "Detects state variables that are shadowed by local variables or parameters, potentially leading to confusion, errors, and unexpected contract behavior.",
    },
    "suicidal": {
        "title": "Unprotected Self-Destruct Functionality",
        "description": "Identifies contracts that can be destroyed via `selfdestruct` without proper access controls, posing a significant risk to contract permanence and user funds.",
    },
    "uninitialized-state": {
        "title": "Uninitialized State Variables",
        "description": "Detects state variables that are left uninitialized, which may lead to unexpected default values and potential vulnerabilities in contract logic.",
    },
    "uninitialized-storage": {
        "title": "Uninitialized Storage Variables",
        "description": "Identifies uninitialized storage variables that can cause unexpected behavior or vulnerabilities due to reading from arbitrary storage locations.",
    },
    "unprotected-upgrade": {
        "title": "Insufficiently Protected Upgrade Functionality",
        "description": "Detects upgradeable contracts with inadequate access controls for the upgrade process, potentially allowing unauthorized modifications to contract logic.",
    },
    "codex": {
        "title": "AI-Detected Potential Vulnerability",
        "description": "Highlights potential vulnerabilities or code smells detected through AI-powered analysis. These findings warrant further manual review and validation.",
    },
    "arbitrary-send-erc20-permit": {
        "title": "Unauthorized ERC20 Transfer with Permit",
        "description": "Identifies potential vulnerabilities in ERC20 token transfers using the permit function without proper authorization checks, which could lead to unauthorized token movements.",
    },
    "arbitrary-send-eth": {
        "title": "Arbitrary Ether Sending Vulnerability",
        "description": "Detects functions that allow arbitrary sending of Ether without proper access controls, potentially leading to unauthorized fund transfers or contract drainage.",
    },
    "controlled-array-length": {
        "title": "Externally Manipulable Array Length",
        "description": "Identifies arrays with lengths that can be manipulated externally, potentially leading to out-of-bounds access, DoS conditions, or other security issues.",
    },
    "controlled-delegatecall": {
        "title": "Externally Controlled Delegatecall Target",
        "description": "Detects delegatecall operations where the target address can be influenced by external actors, posing a significant security risk for arbitrary code execution.",
    },
    "delegatecall-loop": {
        "title": "Delegatecall within Loops",
        "description": "Identifies delegatecall operations inside loops, which can lead to gas exhaustion, reentrancy vulnerabilities, or unexpected state changes across multiple iterations.",
    },
    "incorrect-exp": {
        "title": "Incorrect Exponentiation Implementation",
        "description": "Detects incorrect implementations of exponentiation operations that may lead to unexpected results, precision loss, or potential vulnerabilities in mathematical calculations.",
    },
    "incorrect-return": {
        "title": "Improper Return Value Handling in Assembly",
        "description": "Identifies incorrect handling of return values in inline assembly blocks, which may lead to unexpected behavior or vulnerabilities in low-level operations.",
    },
    "msg-value-loop": {
        "title": "Repeated ETH Value Access in Loops",
        "description": "Detects repeated access to `msg.value` within loops, which can lead to logical errors, excessive gas consumption, or potential vulnerabilities in Ether handling.",
    },
    "reentrancy-eth": {
        "title": "Ether-based Reentrancy Vulnerability",
        "description": "Identifies potential reentrancy vulnerabilities in functions handling Ether transfers, which could lead to unexpected state changes or theft of funds.",
    },
    "return-leave": {
        "title": "Inconsistent Function Exit in Assembly",
        "description": "Detects inconsistent or improper function exit handling in assembly blocks, which can lead to unexpected control flow or potential vulnerabilities.",
    },
    "storage-array": {
        "title": "Signed Integer Array Vulnerability",
        "description": "Identifies potential vulnerabilities or unexpected behavior in storage arrays of signed integers, which may lead to under/overflow issues or logical errors.",
    },
    "unchecked-transfer": {
        "title": "Unchecked Token Transfer",
        "description": "Detects token transfers that do not check for successful execution, potentially leading to silent failures and discrepancies between intended and actual token movements.",
    },
    "weak-prng": {
        "title": "Weak Pseudo-Random Number Generation",
        "description": "Identifies the use of weak or predictable pseudo-random number generation methods, which can be exploited in scenarios requiring unpredictability or fairness.",
    },
    "domain-separator-collision": {
        "title": "EIP-2612 Domain Separator Collision",
        "description": "Identifies potential collisions in domain separators for EIP-2612 signatures, which may cause misinterpretation.",
    },
    "enum-conversion": {
        "title": "Unsafe Enum Conversion",
        "description": "Detects unsafe conversions between integers and enums that can lead to unexpected values.",
    },
    "erc20-interface": {
        "title": "Non-Standard ERC20 Implementation",
        "description": "Warns about ERC20 implementations that do not conform to the standard interface, leading to potential incompatibilities.",
    },
    "erc721-interface": {
        "title": "Non-Standard ERC721 Implementation",
        "description": "Flags ERC721 implementations that deviate from the standard interface, posing compatibility issues.",
    },
    "incorrect-equality": {
        "title": "Risky Strict Equality Check",
        "description": "Identifies risky use of strict equality checks (==) on floating point or complex data types.",
    },
    "locked-ether": {
        "title": "Permanently Locked Ether",
        "description": "Detects contracts that may have Ether locked within them without a way to recover it.",
    },
    "mapping-deletion": {
        "title": "Incomplete Mapping Deletion",
        "description": "Warns about incomplete mapping deletions that may leave some elements behind, causing potential issues.",
    },
    "shadowing-abstract": {
        "title": "Abstract Contract Variable Shadowing",
        "description": "Detects variables in abstract contracts that are shadowed by derived contracts, causing confusion.",
    },
    "tautological-compare": {
        "title": "Self-Comparison Issue",
        "description": "Detects comparisons where a variable is compared to itself, which is always true or false.",
    },
    "tautology": {
        "title": "Always True/False Condition",
        "description": "Flags conditions that are always true or false, leading to dead or unreachable code.",
    },
    "write-after-write": {
        "title": "Redundant State Variable Write",
        "description": "Detects multiple writes to the same state variable in a single transaction, wasting gas.",
    },
    "boolean-cst": {
        "title": "Boolean Constant Misuse",
        "description": "Flags improper use of boolean constants, which may cause unexpected behavior or inefficiencies.",
    },
    "constant-function-asm": {
        "title": "State-Changing Constant Function (Assembly)",
        "description": "Warns about constant functions that change state in inline assembly, breaking Solidity's guarantees.",
    },
    "constant-function-state": {
        "title": "State-Changing Constant Function",
        "description": "Detects constant functions that improperly change the contract state, violating Solidity's expectations.",
    },
    "divide-before-multiply": {
        "title": "Precision Loss in Arithmetic",
        "description": "Warns about division before multiplication, which may lead to precision loss in arithmetic operations.",
    },
    "out-of-order-retryable": {
        "title": "Out-of-Order Retryable Transaction",
        "description": "Detects retryable transactions executed out of order, which may cause unexpected results.",
    },
    "reentrancy-no-eth": {
        "title": "Reentrancy Vulnerability (No Ether Theft)",
        "description": "Identifies reentrancy vulnerabilities even in functions that don't deal with Ether.",
    },
    "reused-constructor": {
        "title": "Reused Base Constructor",
        "description": "Detects constructors that are reused across multiple base contracts, which may lead to initialization issues.",
    },
    "tx-origin": {
        "title": "Unsafe Transaction Origin Usage",
        "description": "Flags use of `tx.origin`, which can lead to security vulnerabilities like phishing attacks.",
    },
    "unchecked-lowlevel": {
        "title": "Unchecked Low-Level Call",
        "description": "Warns about low-level calls (e.g., `call`) that are unchecked for success, leading to potential failure or security risks.",
    },
    "unchecked-send": {
        "title": "Unchecked Ether Sending",
        "description": "Detects functions that send Ether without checking for successful transfer, risking Ether loss.",
    },
    "uninitialized-local": {
        "title": "Uninitialized Local Variable",
        "description": "Flags uninitialized local variables that may hold unpredictable values, leading to unexpected behavior.",
    },
    "unused-return": {
        "title": "Ignored Return Value",
        "description": "Detects instances where the return value of a function is ignored, which may indicate an error or vulnerability.",
    },
    "incorrect-modifier": {
        "title": "Incorrect Modifier Implementation",
        "description": "Detects incorrect usage or implementation of function modifiers, which may lead to unexpected behavior.",
    },
    "shadowing-builtin": {
        "title": "Built-in Symbol Shadowing",
        "description": "Warns about variables or functions that shadow Solidity's built-in symbols, causing confusion or errors.",
    },
    "shadowing-local": {
        "title": "Local Variable Shadowing",
        "description": "Detects local variables that shadow other variables, potentially causing unexpected behavior.",
    },
    "uninitialized-fptr-cst": {
        "title": "Uninitialized Function Pointer in Constructor",
        "description": "Flags uninitialized function pointers in constructors, which may lead to vulnerabilities.",
    },
    "variable-scope": {
        "title": "Incorrect Variable Scope Usage",
        "description": "Detects variables that are declared in the wrong scope, potentially causing security or logic issues.",
    },
    "void-cst": {
        "title": "Missing Constructor Implementation",
        "description": "Flags constructors that are declared but not implemented, which may lead to incomplete initialization.",
    },
    "calls-loop": {
        "title": "Multiple External Calls in Loop",
        "description": "Detects multiple external calls within loops, which may cause reentrancy issues or excessive gas usage.",
    },
    "events-access": {
        "title": "Missing Event for Critical Operation",
        "description": "Warns about critical operations that are not logged through events, reducing traceability.",
    },
    "events-maths": {
        "title": "Missing Event for Arithmetic Operation",
        "description": "Detects arithmetic operations without corresponding events, limiting transparency and debugging ability.",
    },
    "incorrect-unary": {
        "title": "Dangerous Unary Expression",
        "description": "Detects dangerous or unexpected use of unary operators, which may lead to incorrect logic.",
    },
    "missing-zero-check": {
        "title": "Missing Zero Address Check",
        "description": "Flags instances where functions do not check for zero addresses, which may lead to invalid operations.",
    },
    "reentrancy-benign": {
        "title": "Benign Reentrancy Vulnerability",
        "description": "Detects reentrancy vulnerabilities that are less critical but still pose risks to contract logic.",
    },
    "reentrancy-events": {
        "title": "Event Ordering Vulnerability",
        "description": "Warns about event ordering issues that may lead to incorrect assumptions or misinterpretation of events.",
    },
    "return-bomb": {
        "title": "Unexpected Gas Consumption in External Call",
        "description": "Detects external calls that may consume an unexpectedly high amount of gas, leading to failed transactions.",
    },
    "timestamp": {
        "title": "Unsafe Timestamp Usage",
        "description": "Warns about reliance on block timestamps for critical logic, which can be manipulated by miners.",
    },
    "assembly": {
        "title": "Low-Level Assembly Usage",
        "description": "Flags the use of inline assembly, which can introduce security risks or be difficult to audit.",
    },
    "assert-state-change": {
        "title": "State Change in Assert Statement",
        "description": "Detects state-changing operations inside `assert`, which is meant to check conditions without side effects.",
    },
    "boolean-equal": {
        "title": "Unnecessary Boolean Comparison",
        "description": "Flags comparisons where a boolean variable is compared to `true` or `false`, which is redundant.",
    },
    "cyclomatic-complexity": {
        "title": "High Function Complexity",
        "description": "Warns about functions with high cyclomatic complexity, which are harder to understand and more error-prone.",
    },
    "deprecated-standards": {
        "title": "Usage of Deprecated Solidity Features",
        "description": "Detects the usage of deprecated Solidity features that may become unsupported in future versions.",
    },
    "erc20-indexed": {
        "title": "Non-Indexed ERC20 Event Parameter",
        "description": "Detects ERC20 event parameters that should be indexed for better traceability and filtering.",
    },
    "function-init-state": {
        "title": "Function Initializing State Variable",
        "description": "Warns about functions that initialize state variables, potentially leading to reinitialization vulnerabilities.",
    },
    "incorrect-using-for": {
        "title": "Incorrect Library Usage",
        "description": "Detects incorrect use of `using for` with libraries, which may cause unexpected behavior or contract failures.",
    },
    "low-level-calls": {
        "title": "Low-Level Call Usage",
        "description": "Flags low-level calls (e.g., `call`, `delegatecall`, `staticcall`) that may lead to unexpected behavior or security risks.",
    },
    "missing-inheritance": {
        "title": "Missing Contract Inheritance",
        "description": "Detects contracts that do not inherit necessary parent contracts, leading to incomplete functionality.",
    },
    "naming-convention": {
        "title": "Non-Standard Naming Convention",
        "description": "Warns about functions, variables, or contracts that do not follow common naming conventions, reducing readability.",
    },
    "pragma": {
        "title": "Inconsistent Solidity Version",
        "description": "Detects inconsistent or unsafe pragma versioning that may introduce compatibility issues.",
    },
    "redundant-statements": {
        "title": "Redundant Code",
        "description": "Detects redundant or unnecessary code that does not contribute to the logic and can be removed.",
    },
    "solc-version": {
        "title": "Outdated Solidity Version",
        "description": "Warns about the use of outdated Solidity versions that may be missing important security updates.",
    },
    "unimplemented-functions": {
        "title": "Unimplemented Function",
        "description": "Detects function declarations that are not implemented, which can cause deployment issues.",
    },
    "unused-import": {
        "title": "Unused Import",
        "description": "Flags unused import statements that can be removed to improve code clarity and reduce gas consumption.",
    },
    "unused-state": {
        "title": "Unused State Variable",
        "description": "Warns about state variables that are declared but never used, increasing gas costs and reducing clarity.",
    },
    "costly-loop": {
        "title": "Expensive Operation in Loop",
        "description": "Detects expensive operations within loops, which can lead to excessive gas consumption and out-of-gas errors.",
    },
    "dead-code": {
        "title": "Unused Function",
        "description": "Flags functions that are declared but never used, contributing to dead code and wasted gas.",
    },
    "reentrancy-unlimited-gas": {
        "title": "Potential Reentrancy with Unlimited Gas",
        "description": "Detects reentrancy vulnerabilities that could exploit unlimited gas, leading to unpredictable execution.",
    },
    "too-many-digits": {
        "title": "Non-Standard Number Notation",
        "description": "Warns about the use of non-standard number notation, which can reduce readability or cause misunderstandings.",
    },
    "cache-array-length": {
        "title": "Inefficient Array Length Usage in Loop",
        "description": "Detects inefficient access to array length in loops, which can increase gas consumption unnecessarily.",
    },
    "constable-states": {
        "title": "Non-Constant State Variable",
        "description": "Flags state variables that could be constant but are not marked as such, leading to higher gas costs.",
    },
    "external-function": {
        "title": "Non-External Public Function",
        "description": "Detects public functions that should be marked as `external` to optimize gas usage.",
    },
    "immutable-states": {
        "title": "Non-Immutable State Variable",
        "description": "Warns about state variables that could be immutable but are not marked as such, reducing efficiency.",
    },
    "var-read-using-this": {
        "title": "Unnecessary 'this' Usage",
        "description": "Detects instances where the `this` keyword is unnecessarily used to access state variables, increasing gas costs.",
    },
}
