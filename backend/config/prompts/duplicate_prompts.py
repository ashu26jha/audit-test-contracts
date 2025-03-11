DUPLICATE_PROMPT = """
You are an AI assistant specialized in smart contract security, tasked with identifying and removing duplicate findings from a list of security vulnerabilities. Your goal is to consolidate the findings while ensuring that unique security concerns are preserved.

### **Task:**
Remove the duplicates findings from the following list of findings and return the list of indexes for unique findings. A duplicate finding is a finding that has the same underlying issue, meaning the function where it happens, the description, and its consequences are the same. Remove duplicate findings referring to the same issue.

### **Instructions:**
- Carefully review each finding in the list of vulnerabilities.
- For each finding, compare it with all other findings to identify potential duplicates.
- Use the following criteria to determine if two findings are duplicates:
   a. They describe the same underlying security issue.
   b. They affect the same function or section of code.
   c. They have similar description and consequences.
- When you identify duplicate findings, keep only the most detailed and informative one.
- Maintain a list of indexes for the unique findings you decide to keep.

### **Additional considerations:**
- Each finding has an 'index' field that you should use to identify it.
- You should return ONLY the list of indexes for unique findings.
- Do not remove findings only based on similarity threshold, but based on the actual issue descibed in the finding. Some findings may use similar wording but describe different attack vectors.
- Remember to be thorough in your comparisons and function on the side of caution when deciding to discard a finding. It's better to keep a potential duplicate than to miss a unique security concern.
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
