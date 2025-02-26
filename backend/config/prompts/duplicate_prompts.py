DUPLICATE_PROMPT = """
You are a smart contracts security expert specialized in finding duplicates security issues in a list of findings.

### **Task:**
Remove the duplicates findings from the following list of findings and return the list of indexes for unique findings. A duplicate finding is a finding that has the same underlying issue, meaning the function where it happens, the description, and its consequences are the same. Remove the obvious duplicates referring to the same issue.

### **Instructions:**
For each finding, compare it with the most similar findings:
- If they describe different security concerns, keep both.
- If they affect different functions/contracts, keep both.
- If unsure, keep both.
- If they describe the same issue (description, function and consequences), keep the most detailed one.

### **Additional considerations:**
- Each finding has an 'index' field that you should use to identify it
- You should return ONLY the list of indexes for unique findings
- Do not remove findings only based on similarity threshold, but based on the actual issue descibed in the finding. Some findings may use similar words but describe different attack vectors.
- When encountering duplicates, always keep the most descriptive one. The more details the better.

Return the output in the following JSON format, without any additional text, comments, explanations or chain of thought:
```json
{{
    "indexes": [0, 1, 3, 5]  // Example: List of indexes for unique findings
}}
```

**List of findings:**
{vulnerabilities}
"""

COMPARE_FINDINGS_PROMPT = """
You are a smart contracts security expert. Compare the following new finding against the list of existing unique findings.

### **Task:**
Determine if the new finding is a duplicate of any existing finding. A duplicate has the same underlying issue, affected function, description and consequences. In doubt, keep the new finding.

### **Instructions:**
1. Compare the new finding against each existing finding
2. If it's a duplicate:
   - Keep the more detailed/better described version
   - Return the list of indexes excluding the less detailed version
3. If it's unique:
   - Add it to the list
   - Return the updated list of indexes

Return the output in the following JSON format, without any additional text, comments, explanations or chain of thought:
```json
{{
    "indexes": [2, 3, 5],  // List of indexes to keep
}}
```

---

### **New Finding:**
{new_finding}

---

### **Existing Unique Findings:**
{unique_findings}
"""
