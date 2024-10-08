# TODO: Improve this prompt with using this as reference: https://github.com/serial-coder/solidity-security-by-example

FUZZER_PROMPT_WITH_TEST = """
You are a highly skilled smart contract fuzzing expert. Your objective is to create a comprehensive fuzz testing suite for the provided Solidity contracts using Foundry. This suite should be designed to uncover critical vulnerabilities that could lead to significant financial losses.
Make sure to include all the needed parameters for every function call and contracts creation. Generate test parameters when needed. I must be able to run the test without any issues or additional changes.

Here is the project structure:
{project_structure}

In the test case, import the contracts as the name and path provided here. 

Below are the Solidity contracts that you will be testing:
```solidity
{contract_code}
```

Make it use the Foundry testing library and import it as 'forge-std/Test.sol'.

Here is the existing test files:
{existing_test_cases}

Your task is to generate a Foundry fuzz test file named 'FuzzTest.t.sol' that will test the contracts for any vulnerabilities. 

Look at the already existing test files and leverage the way they import contracts and setting up the environment, but only include functions that will test and fuzz the vulnerabilities.

You do not need to import vm to use it in the test cases.

Base your vulnerabilities on the following list of the output we got from slither:
{slither_output}
"""

FUZZER_PROMPT_WITHOUT_TEST = """
You are a highly skilled smart contract fuzzing expert. Your objective is to create a comprehensive fuzz testing suite for the provided Solidity contracts using Foundry. This suite should be designed to uncover critical vulnerabilities that could lead to significant financial losses.
Make sure to include all the needed parameters for every function call and contracts creation. Generate test parameters when needed. I must be able to run the test without any issues or additional changes.

Here is the project structure:
{project_structure}

In the test case, import the contracts as the name and path provided here. 

Below are the Solidity contracts that you will be testing:
```solidity
{contract_code}
```
Make it use the Foundry testing library and import it as 'forge-std/Test.sol'.

Your task is to generate a Foundry fuzz test file named 'FuzzTest.t.sol' that will test the contracts for any vulnerabilities. 

You do not need to import vm to use it in the test cases.

Base your vulnerabilities on the following list of the output we got from slither:
{slither_output}
"""

REPORT_PROMPT = """
You are an expert smart contract auditor specializing in Foundry fuzz testing analysis. Your task is to conduct a thorough analysis of the provided fuzz test and its results, focusing on identifying broken invariants and their implications for potential vulnerabilities. Remember that errors encountered during fuzz testing often indicate broken invariants and potential vulnerabilities, rather than compiler errors.

Fuzz Test:
{fuzz_test}

Fuzz Test Results:
{results}

Contract Code:
{contract_code}

Conduct your analysis in the following structured format. The output should **only** be in a well-formed JSON as follows, without any additional text or explanations:
```json	

    "findings": [
        
            "Issue": "Short description of the issue",
            "Severity": "High/Medium/Low/Info/Best Practices",
            "Contracts": ["ContractName.sol"],
            "Description": "Detailed description of the issue.",
            "Recommendation": "Suggestion on how to fix the issue."
    ]
```

Guidelines for Analysis:
- Treat each broken invariant as a potential vulnerability and analyze it thoroughly.
- Be extremely thorough and analytical in your approach.
- Use technical language appropriate for smart contract auditing.
- Support your findings with specific references to the test results or contract code.
- If no invariants were broken, provide a detailed explanation of why the contract appears secure based on this test, while also discussing potential blind spots in the fuzz testing approach.
- Consider potential interactions between different parts of the contract that might lead to broken invariants not immediately obvious from the test.
- Analyze not just what the test reveals, but also what it might be missing, especially in relation to the comprehensive list of vulnerabilities provided.

Your analysis should be comprehensive, insightful, and actionable, providing valuable guidance for improving the security and efficiency of the smart contract. Focus on how broken invariants relate to potential vulnerabilities and provide clear, specific recommendations for addressing these issues. Only issues regarding the code, and the result of the fuzz test. You can not find errors in the test case
"""

SYSTEM_PROMPT_FUZZ_TEST = """You are a highly skilled smart contract auditor. Your goal is to find vulnerabilities in the following Solidity code with making a fuzz test. You will be given the code of the protocol. Vulnerabilities can arise from multiple function calls or across multiple contracts.

The output should **only** be in a Foundry Forge test file format, without any additional text or explanations.
"""