SUMMARISE_PROMPT = """
You are a helpful assistant that summarises the content of a given text.

* Key considerations:
    * You must ensure that no details are lost in the process.
    * Security related points are crucial and must not be lost.
    * Do not cut off any part of the text. You must be as descriptive as possible
    * It should be well described and easy to understand.
    * It must have separate section for security related points.
    * For EIPs, do not make changes to `Security Considerations` section.
    * For EIPs, focus on correct implementation of the EIP.
    * Skip parts like admin, governance, decentralization, events, etc.
{text}
"""

BEST_LINK_SELECTION_PROMPT = """
You are a helpful assistant that selects the best link from a given list of links. You will be given a list of links and a query.
You must select atmost 2 links that is most relevant to the query. You can also select none.
The links must have the following characteristics:
- The links must be relevant to the query.
- It should have web3 or blockchain oriented info
- Brownie points if it has security related info
- Do not pick links which are about compiler issues. Learn about the new version

* Key considerations:
    * You must pick the links that are most relevant to the query.
    * You must pick the links which helps LLM fill it's own information gap.
    * Avoid picking links which are not relevant to the query.
    * Avoid picking links which compare to Rust.
    * Links of EIPs, docs are important.
    * Pick those links which makes most sense for a security audit.

    * Query: {query}
    * Links: {links}
"""

CLEAN_RESPONSE_PROMPT = """
You will be given three pieces of information related to blockchain content: a summary, AST details, and documentation. Your task is to filter and retain only the relevant information based on specific criteria.

Here is the content:

**Summary**
{summary}

**AST**
{ast}

**Docs**
{docs}

Your task is to process this information and keep only what is relevant according to these criteria:
1. Information must be directly related to contracts and documentation.
2. Remove any content that represents a 404 error or "page not found" message.

Follow these steps:

1. Carefully read through each section (summary, contract, and docs).

2. For each section:
   a. Identify and retain information that is specifically about contracts or documentation.
   b. Discard any content that is not related to contracts or documentation.
   c. Remove any text that indicates a 404 error or missing page.

3. Your task is not to summarise the content. You are only allowed to discard the parts of it when it is not relevant to the query.

4. Keep most of the content as it is.

As an output only give only the modified summary do not give contracts and docs as output
"""
