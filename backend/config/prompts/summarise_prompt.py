SUMMARISE_PROMPT = """
You are a helpful assistant that summarises the content of a given text.

### Key considerations:
    * You must ensure that no details are lost in the process.
    * Security related points are crucial and must not be lost.
    * Do not cut off any part of the text. You must be as descriptive as possible
    * It should be well described and easy to understand.
    * It must have separate section for security related points.
    * For EIPs, do not make changes to `Security Considerations` section.
    * For EIPs, focus on correct implementation of the EIP.
    * Skip parts like admin, governance, decentralization, events, etc.
    * Try to preserve code snippets and mark them with ```solidity ```

### Text to summarise:
{text}
"""

BEST_LINK_SELECTION_PROMPT = """
You are a helpful assistant that selects the best link from a given list of links. You will be given a list of links and a query. You must select atmost 2 links that is most relevant to the query. You can also select none.

The links must have the following characteristics:
- The links must be relevant to the query.
- It should have web3 or blockchain oriented info
- Brownie points if it has security related info
- Do not pick links which are about compiler issues. Learn about the new version

### Key considerations:
    * You must pick the links that are most relevant to the query.
    * You must pick the links which helps LLM fill it's own information gap.
    * Avoid picking links which are not relevant to the query.
    * Avoid picking links which compare to Rust.
    * Links of EIPs, docs are important.
    * Pick those links which makes most sense for a security audit.

### Response Format:
Return the output in the following JSON format, without any additional text, explanations, comments or chains of thought:
```json
{{
    "results": [
        {{
            "title": "Title of the link",
            "href": "href of the link",
            "body": "Body of the link"
        }}
    ]
}}
```

### Query:
{query}

### Links:
{links}
"""

CLEAN_RESPONSE_PROMPT = """
You are given three pieces of information related to a blockchain protocol:
    1. Some additional documentation related to the protocol
    2. The tree structure of the protocol as an AST
    3. Some search results from DuckDuckGo web search

### Task:
1. Carefully read through each section (search results, AST, and docs).
2. Filter and retain only the the most relevant information from the search results according to these criterias:
- The content must be directly related to the smart contracts and their documentation.
- The content should help an auditor to assess the security of the smart contracts.
- Do not to summarise the content. You are only allowed to discard the parts of it when it is not relevant to the query.
- Remove:
    * Any content that represents a 404 error or "page not found" message.
    * Any content that is not related to smart contracts, their documentation or security.

### Response Format:
Return the filtered content as a string.

### 1. Docs
{docs}

### 2. AST
{ast}

### 3. Search Results to be filtered
{search_results}
"""
