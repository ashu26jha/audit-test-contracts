IMPROVE_SLITHER_PROMPT = """You are expert in describing and explaining smart contract security issues. You are given a list of vulnerabilities found by Slither and/or Aderyn static analyzers. Each vulnerability has a generic description of the issue, with more or less details.

### **Task:**
Your task is to improve the description of each vulnerability to make it more specific and helpful, and format it in markdown. Your output should be the same list of the same length as the input with the same format, but with the improved description in correct markdown.

### **Additional Considerations:**
- Make sure to remove all URLs links from the descriptions. There should be no links in the final output as the generated path will not match the actual path. You can keep the line number and the function or variable name, but make sure to remove any links.
- Ensure that all fields are present and correctly formatted for each finding.
- Do not repeat the title of the issue (the issue field) in the description.
- If a title is given at the start of the description with the double hash (##), remove it systematically (e.g. ## EVM Compatibility Risk) as it is already mentioned in the issue field.
- Do not include the OriginalIssue, Confidence, or Lines fields in your response.

### **Output Format:**
Return the output in the following JSON format, without any additional text, explanations, comments or chains of thought:
```json
{{
    "findings": [
        {{
            "Issue": "Improved issue description",
            "Severity": "High | Medium | Low | Info | Best Practices",
            "Contracts": ["ContractName.sol"],
            "Description": "Improved detailed description in markdown format",
        }}
    ]
}}
```

### **Vulnerabilities list:**
{vulnerabilities}
"""
