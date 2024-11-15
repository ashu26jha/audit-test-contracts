CONFIDENCE_SORT_PROMPT = """
You are given a list of findings from a junior Solidity smart contract auditor. Your task is to add a "Confidence" property to each finding,
indicating the likelihood that the finding is a true positive. Analyse the findings with help of the contract summary and flattened contracts.

Here is the summary of the contracts:
{contract_summary}

Here are the flattened contracts:
{flattened_contracts}

Here is the array of findings, for which you have to add a confidence score:
{findings}

Do not change the description or order of the findings, only add the confidence score.
It is also not necessary that the input findings which are on the top have higher confidence,
order of input findings is irrelevant and no conculsion should be made on basis of input order of findings.
For example it is not necessary that the first finding is always the most confident.
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
            "Confidence": number // It should be between 0 and 100
        }}
    ]
}}
```
"""
