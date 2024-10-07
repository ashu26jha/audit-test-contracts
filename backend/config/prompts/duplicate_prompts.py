DUPLICATE_PROMPT = """
You are a smart contracts security expert. Your task is to analyze carefully the following list of vulnerabilities and identify any duplicates.
If you find a duplicate vulnerability, keep the one with the most information and/or the best description and remove the other one.
Return the list of unique vulnerabilities, excluding any duplicates. Keep the exact same format as the input list.

Your response should be a valid JSON object containing a single key "findings" with a value that is an array of unique vulnerabilities.

**List of vulnerabilities:**
{vulnerabilities}

Respond with only the JSON object containing the "findings" key and the array of unique vulnerabilities. Do not include any other text or formatting outside the JSON object.
"""
