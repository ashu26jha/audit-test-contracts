context_prompt_with_summary = """
    Analyze the following Solidity smart contracts using the provided summary for context. Look for any potential vulnerabilities and list the 8 most valid identified issues in the JSON format below.
    Most valid are the issues for which you are sure that they are not false positives. Then order them by decreasing severity.
    For each issue, include a description, severity level, affected contract(s), and code snippets.
    
    **Additional Considerations:**
    - Make sure that there is no duplicate issue. 
    - If you find less than 8 vulnerabilities, only report what you found.
    - Make sure every finding is valid and that you do not report false-positives.
    
    Summary: {summary}

    Audit Format:
    ```json
    [
        {{
            "Issue": "A short description of the vulnerability or issue",
            "Severity": "Info | Best Practices | Low | Medium | High | Critical",
            "Contracts": ["ContractName"],
            "Description": "A detailed description of the issue and why it is problematic"
        }}
    ]
    ```

    ### Contracts to audit: 
    ```solidity 
    {flattened_contracts}
    ```
"""

context_prompt_without_summary = """
    Analyze the following Solidity smart contracts and look for any potential vulnerabilities. Then list the 8 most valid identified issues in the JSON format below.
    Most valid are the issues for which you are sure that they are not false positives. Then order them by decreasing severity.
    For each issue, include a description, severity level, affected contract(s), and code snippets.
    
    **Additional Considerations:**
    - Make sure that there is no duplicate issue. 
    - If you find less than 8 vulnerabilities, only report what you found.
    - Make sure every finding is valid and that you do not report false-positives.
    
    Audit Format:
    ```json
    [
        {{
            "Issue": "A short description of the vulnerability or issue",
            "Severity": "Info | Best Practices | Low | Medium | High | Critical",
            "Contracts": ["ContractName"],
            "Description": "A detailed description of the issue and why it is problematic"
        }}
    ]
    ```

    ### Contracts to audit: 
    ```solidity 
    {flattened_contracts}
    ```
"""
