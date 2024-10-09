IMPROVE_SLITHER_PROMPT = """
You are given a list of vulnerabilities found by Slither. Each vulnerability has a generic description and the issue found by Slither with the function name or variable name and the line number.
Your task is to improve the description of the vulnerability to make it more specific and helpful, and format it in markdown.
Your output should be the same list of the same length as the input with the same format, but with the improved description in correct markdown.

**Additional Considerations:**
- Make sure to remove all URLs links from the description. There should be no links in the final output as the generatedpath will not match the actual path. You can keep the line number and the function or variable name, but make sure to remove any links.

**Vulnerabilities list:**
{vulnerabilities}

Respond with only a valid JSON object containing a single key "findings" with an array of the improved vulnerabilities. Do not include any other text or formatting outside the JSON object. Each vulnerability in the array should have the following structure:

```json
{{
    "findings": [
        {{
        "Issue": "Improved issue description",
        "Severity": "High/Medium/Low/Info/Best Practices",
        "Contracts": ["ContractName.sol"],
        "Description": "Improved detailed description in markdown format",
        }}
    ]
}}
```

Ensure that all fields are present and correctly formatted for each finding. Do not include the OriginalIssue, Confidence, or Lines fields in your response.
"""
