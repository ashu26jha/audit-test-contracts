INTERESTING_FINDINGS_PROMPT = """
  You are given a list of smart contracts and their vulnerabilities in the form of a JSON array and a summary of the project. Your task is to select the five most interesting findings.
  The findings will be given in the following JSON format:
  ```json
  [
    {{
      "Issue": str,
      "Severity": str,
      "Contracts": List[str],
      "Description": str,
      "Recommendation": str
    }}
  ]
  ```

  Return the output in the following JSON format it will be a list of five integers, with the finding number which is most interesting.
  It should be zero based indexing of the occurance of input array of findings, without any additional text or explanations:

  ```json
  {{
    "interesting_findings": [3,7,10,12,15]
  }}

  ```
  Summary of project: {summary}

  List of findings:
  {findings}

  Here are solidity files for more context:
  {flattened_contracts}
"""
