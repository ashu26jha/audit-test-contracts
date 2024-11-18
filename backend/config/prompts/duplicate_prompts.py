DUPLICATE_PROMPT = """
You are a smart contracts security expert. Your task is to carefully analyze the following list of vulnerabilities and identify any duplicates or similar findings:
- For duplicate vulnerabilities, keep the one with the most information and/or the best description, add any missing information or code snippets from the other finding to the description, then remove the other one.
- For similar vulnerabilities, combine them into a single one and remove the other one. Make sure to keep as many details as possible. For instance, if there are 2 contants that should be marked as immutable, merge them into a single findings mentioning both occurrences.
Finally, return the list of unique findings with the most information and/or the best description, excluding any duplicates.

**Additional considerations:**
- Make sure to keep as many details as possible for each finding's description and all code snippets. The more details, the better.
- Combine findings when possible, but do not lose any details.
- Make sure everything is properly formatted: proper JSON, containing attributes with proper strings, containing proper markdown, etc.

Return the output in the following JSON format, without any additional text or explanations:
```json
{{
    "findings": [
        {{
            "Issue": "Short description of the issue",
            "Severity": "High/Medium/Low/Info/Best Practices",
            "Contracts": ["ContractName.sol"],
            "Description": "Detailed description of the issue. Example:\\n```solidity\\nfunction vulnerable() {{\\n    // show exact vulnerable code here\\n}}\\n```\\nExplain why this is vulnerable...",
            "Recommendation": ""
        }}
    ]
}}
```

**List of vulnerabilities:**
{vulnerabilities}
"""
