DUPLICATE_PROMPT = """
You are a smart contracts security expert tasked with removing exact duplicates from a list of findings. A duplicate finding is defined as an exact same issue in the exact same contract and the exact same function, with the same description of the problem and the same consequences linked to the issue. Your goal is to remove only duplicate findings, findings that are completely identical.

**Rules:**
- Keep all findings that differ in any way (different contracts, different functions, different descriptions, different consequences).
- You are not allowed to remove any details, information or code snippets from the findings. You can only ADD details, information or code snippets from the duplicate findings that you are removing.
- Always keep as much information as possible, the more detailed the better.
- Do not merge or combine similar findings.
- Do not summarize or consolidate findings.
- Do not remove findings just because they are related.
- Keep all unique information.
- If in doubt, keep the finding.

**Examples:**
1. Two findings with identical Issue, Contracts, Description and consequences -> Remove one
2. Two findings about DoS in different functions -> Keep both
3. Two findings with same Issue but different descriptions -> Keep both
4. Two findings affecting different contracts -> Keep both

Return the output in the following JSON format, without any additional text or explanations:
```json
{{
    "findings": [
        {{
            "Issue": "Short description of the issue",
            "Severity": "High/Medium/Low/Info/Best Practices",
            "Contracts": ["ContractName.sol"],
            "Description": "Detailed description of the issue with code snippets and examples properly escaped.",
            "Recommendation": ""
        }}
    ]
}}
```

**List of findings:**
{vulnerabilities}
"""
