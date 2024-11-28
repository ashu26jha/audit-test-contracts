DUPLICATE_PROMPT = """
You are a smart contracts security expert tasked with removing exact duplicates from the following list of findings:

**List of findings:**
{vulnerabilities}

**Additional considerations:**
- You are not allowed to edit the findings in any way. Just remove the duplicates.
- Do not merge or combine similar findings.
- Do not summarize or consolidate findings.
- Do not remove findings just because they are related.

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
"""
