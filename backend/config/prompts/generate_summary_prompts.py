SUMMARY_PROMPT = """
You are given a set of flattened smart contracts. Your tasks are as follows:
1. Summarize the protocol. The summary should not be too short and must give a complete and detailed high-level overview of the protocol.
2. After the summary, but within the `summary` section, include a list of the main entry points of the protocol and the actors involved in those entry points. By entry points, I mean all the public/external functions that are exposed to actors, whomever they are. By actors, I mean the different entities that could interact with the entry points (users, validators, owners, stakers, liquidity providers, etc.).
3. Identify the type of the protocol.

**Additional information:**
- Make sure the `summary` is written in proper markdown format.
- Do not include any main title in the summary like `Summary` or `Protocol Summary` as it will duplicate with how I format the markdown.
- Do not mention security issues in the `summary`, and only focus on the protocol itself: what it does, how it does it, and its architecture.
- Do not mention the protocol type in the `summary` section, only pass it as the `type` in the JSON response.
- In the entry points, do not include any functions protected by an `onlyOwner` modifier.
- The type of the protocol can only be one of the following. Pick the most appropriate type from the list above. If the type is not clear, pick DEFAULT.
   * DEFI (Focused on financial products like lending, borrowing, trading, and derivatives.)
   * DAO (Designed for decentralized governance, voting systems, and managing DAOs.)
   * IDENTITY (Focused on decentralized identity management and access control mechanisms.)
   * NFT (Used for managing NFTs, digital collectibles, games and gaming assets, and tokenized art.)
   * UTILITY (Provide infrastructure like oracles, cross-chain bridges, and reusable libraries.)
   * DEFAULT (If the type is not clear, pick DEFAULT.)

**For markdown format:**
Ensure proper formatting for lists in the summary. Use a single level of lists and include descriptions on the same line. For example:

- First item: This is the description of the first item.
- Second item: This is the description of the second item.
- Third item: This is the description of the third item.

1. Numbered item 1: This is the description of the first numbered item.
2. Numbered item 2: This is the description of the second numbered item.
3. Numbered item 3: This is the description of the third numbered item.

**Response Format:**
Your response should be in the following JSON format, without any additional text or explanations:

```json
{{
    "summary": "Description of protocol",
    "type": "Type of protocol"
}}
```

**Contracts to summarize:**
{contracts}
"""
