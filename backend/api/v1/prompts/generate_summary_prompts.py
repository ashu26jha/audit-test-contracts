system_prompt = """
You are given a flattened smart contract, you need to give the description of the protocol and type of protocol. Result must only be a json of type:

```json
{
    "summary": "Description of protocol"
    "type": Type of protocol
}
```

Type of protocol can only from:

DAO
DEFI
IDENTITY
NFT
UTILITY
NONE
"""
