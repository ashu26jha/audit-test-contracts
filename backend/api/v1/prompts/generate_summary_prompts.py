SUMMARY_PROMPT = """
You are given a flattened smart contract. Your task is to summarizes the protocol and identify its type. The summary should be complete and detailed, and give a high level overview of the protocol.
The purpose of this summary is to provide a quick overview of the protocol, to be used for further analysis, and optionnaly to be adding to a documentation.
Do not mention security issues, and only focus on the protocol itself: the main features, how it works, its architecture, and main entrypoints.

## The response should be in the following JSON format:

```json
{{
    "summary": "Description of protocol"
    "type": Type of protocol
}}
```

## The type of the protocol can only be on of the following:

DAO
DEFI
IDENTITY
NFT
UTILITY
DEFAULT

Pick the most appropriate type from the list above. If the type is not clear, pick DEFAULT.

## Contracts to summarize:
{contracts}

"""
