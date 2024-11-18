CONFIDENCE_SORT_PROMPT = """
You are given a list of findings from a junior Solidity smart contract auditor. Your task is to add a "Confidence" property to each finding, indicating the likelihood that the finding is a true positive. Analyse the findings with the help of the flattened contracts and the summary of the contracts.

**Additional considerations:**
- Do not change the description or the order of the findings. Only add the confidence score.
- The confidence score should be a number between 0 and 100.
- The findings are sorted by severity, from high to low. But the severity is irrelevant for the confidence score. No conclusion should be made based of the severity, or the order of the findings. For instance, a highest severity finding could be less likely to be a true positive than a lower severity finding.

Return the findings in the following JSON array format:
```json
{{
    "findings": [
        {{
            "Issue": "Short description of the issue",
            "Severity": "High/Medium/Low/Info/Best Practices",
            "Contracts": ["ContractName.sol"],
            "Description": "Detailed description of the issue, with code snippet when needed.",
            "Recommendation": "",
            "Confidence": number
        }}
    ]
}}
```

**Findings, for which you have to add a confidence score:**
{findings}

**Summary of the contracts:**
{contract_summary}

**Flattened contracts:**
{flattened_contracts}
"""
