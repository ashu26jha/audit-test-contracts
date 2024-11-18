INTERESTING_FINDINGS_PROMPT = """
From the following list of smart contract security findings, select the 5 most interesting findings for further analysis. Focus on:
1. Higher severity issues
2. Findings that appear more specific/detailed
3. Findings affecting core protocol functions

Return ONLY a JSON object with the indices of the 5 most interesting findings (zero-based indexing):
```json
{{
  "interesting_findings": [3,7,10,12,15]
}}
```

**Summary of the project:**
{summary}

**Findings to Analyze:**
{findings}
"""
