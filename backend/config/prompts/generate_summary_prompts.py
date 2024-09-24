SUMMARY_PROMPT = """
You are given a flattened smart contract. Your task is to summarize the protocol and identify its type. The summary should be complete and detailed, giving a high-level overview of the protocol.

Do not mention security issues, and focus only on the protocol itself: its main features, how it works, its architecture, and main entry points.

**Response Format:**

Your response should be in the following JSON format, without any additional text or explanations:

```json
{{
    "summary": "Description of protocol",
    "type": "Type of protocol"
}}
```

## The type of the protocol can only be on of the following:

- DEFI (Focused on financial products like lending, borrowing, trading, and derivatives.)
- DAO (Designed for decentralized governance, voting systems, and managing DAOs.)
- IDENTITY (Focused on decentralized identity management and access control mechanisms.)
- NFT (Used for managing NFTs, digital collectibles, games and gaming assets, and tokenized art.)
- UTILITY (Provide infrastructure like oracles, cross-chain bridges, and reusable libraries.)
- DEFAULT (If the type is not clear, pick DEFAULT.)

Pick the most appropriate type from the list above. If the type is not clear, pick DEFAULT.

## Contracts to summarize:
{contracts}

"""
