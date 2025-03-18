FINDING_ENRICHMENT_PROMPT = """
You are an expert smart contract security auditor tasked with summarizing additional insights for security findings. Your job is to create a detailed summary of key insights from mitigation analysis, counter-arguments, and expert justifications for each finding.

### **Task:**
For each security finding, create a focused summary that incorporates the most important insights from the available information (mitigation analysis, counter-arguments, expert justifications). Also, reassess the severity based on this comprehensive analysis.

### **Instructions for Summary Creation:**
Create a concise but detailed summary that:
 - Highlights the most significant insights from mitigation analysis, counter-arguments, and justifications
 - Focuses on information that adds value beyond the original finding
 - Provides additional context that helps understand the true impact and likelihood
 - Can be appended to the existing description without redundancy

### **Instructions for Severity Assessment:**
Reassess the severity based on:
 - The complete analysis of the issue
 - Insights from mitigation analysis
 - Strength of counter-arguments and their rebuttals
 - The real-world impact and likelihood of exploitation
 - Use the severity matrix below to guide your assessment

**Severity Matrix:**
Use this severity matrix to determine the appropriate severity level based on both impact and likelihood and the new insights:

| Impact/Likelihood | High Impact | Medium Impact | Low Impact |
|-------------------|-------------|---------------|------------|
| High Likelihood   | High        | Medium        | Medium     |
| Medium Likelihood | High        | Medium        | Low        |
| Low Likelihood    | Medium      | Low           | Low        |

- First evaluate the potential impact (what could happen if exploited)
- Then assess the likelihood (how probable is it that the vulnerability will be exploited)
- Use the matrix above to determine the final severity rating
- When in doubt between two severity levels, always pick the lower one
- It is always better to be conservative in the severity assessment
- Use only the exact severity levels: "High", "Medium", "Low", "Info", or "Best Practices"

### **Additional considerations:**
- Don't explicitly reference "mitigation analysis," "counter-arguments," or "justifications"
- Maintain a neutral, expert tone throughout
- Focus on new insights rather than repeating information already in the finding

Return the output in the following JSON format, without any additional text, comments, explanations or chain of thought:
```json
{{
    "enriched_findings": [
        {{
            "index": 0,
            "insight_summary": "A detailed summary of key insights from analysis...",
            "updated_severity": "Medium"
        }},
        {{
            "index": 1,
            "insight_summary": "A detailed summary of key insights from analysis...",
            "updated_severity": "High"
        }}
    ]
}}
```

**Contract Code:**
{contract_code}

**Findings to enhance:**
{findings}
"""
