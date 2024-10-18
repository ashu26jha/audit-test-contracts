DUPLICATE_PROMPT = """
You are a smart contracts security expert. Your task is to analyze carefully the following list of vulnerabilities and identify any duplicates or similar findings.
If you find a duplicate vulnerability, keep the one with the most information and/or the best description and/or combine them into a single one and remove the other one.
Return the list of unique vulnerabilities, excluding any duplicates. Keep the exact same format as the input list.

Your response should be a valid JSON object containing a single key "findings" with a value that is an array of unique vulnerabilities.

**List of vulnerabilities:**
{vulnerabilities}

Return the output in the following JSON format, without any additional text or explanations:
    ```json
    {{
        "findings": [
            {{
            "Issue": "Short description of the issue",
            "Severity": "High/Medium/Low/Info/Best Practices",
            "Contracts": ["ContractName.sol"],
            "Description": "Detailed description of the issue, with code snippet when needed.",
            "Recommendation": "Suggestion on how to fix the issue."
            }}
        ]
    }}
    ```
"""
