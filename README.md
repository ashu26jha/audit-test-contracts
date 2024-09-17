# yokai-ai-reviewer

## Front-end

## Back-end

To launch a local server:

```bash
uvicorn main:app --reload
```

To launch a prod server:

```bash
fastapi run
```

To run linter:

```bash
cd backend
```

```bash
pre-commit install
```
then: 
```bash
pre-commit run --all-files
```

To Run tests:

```bash
pytest backend/tests/ -v
```

with coverage:

Add the following package:

```bash
pip install coverage pytest-cov
```

then run:

```bash
pytest backend/tests/ -v --cov=backend
```

or generate coverage report:

```bash
pytest backend/tests/ -v --cov=backend --cov-report=html
``` 

### roadmap:

- [x] health check endpoint/service
- [x] context scan endpoint/service
- [x] generate summary endpoint/service
- [ ] critics endpoint/service
- [ ] flatten contracts endpoint/service
- [ ] scan restriction when not paid
- [ ] add missing profiles
- [ ] add test for all services

### Profiles

<details>
  <summary>NFT-Fi</summary>
  <ul>
    <li>Details about NFT-Fi</li>
  </ul>
</details>

<details>
  <summary>De-Fi</summary>
  <ul>
    <li>Total token length: 129,516</li>
    <li>NM0067: Tokens Input: 3,462</li>
    <li>NM0074: Tokens Input: 18,726</li>
    <li>NM0098: Tokens Input: 18,855</li>
    <li>NM0108: Tokens Input: 1,351</li>
    <li>NM0117: Tokens Input: 24,905</li>
    <li>NM0202: Tokens Input: 17,748</li>
    <li>NM0162: Tokens Input: 33,143</li>
    <li>NM0227: Tokens Input: 11,326</li>
  </ul>
</details>

<details>
  <summary>Utility</summary>
  <ul>
    <li>Consists of L2 Bridge & Oracle, total tokens: 35916</li>
    <li>NM0064: Tokens Input: 13,269</li>
    <li>NM0081: Tokens Input: 6,753</li>
    <li>NM0120: Tokens Input: 15,894</li>
  </ul>
</details>

<details>
  <summary>DAO</summary>
  <ul>
    <li>Consists of Token Distribution etc, total tokens: 6254</li>
    <li>NM0234: Tokens Input: 6254</li>
  </ul>
</details>

<details>
  <summary>Identity</summary>
  <ul>
    <li>Consists of Identity Management & Wallets, total tokens: 40,999</li>
    <li>NM0069: Tokens Input: 7,888</li>
    <li>NM0083: Tokens Input: 1,785</li>
    <li>NM0112: Token Input: 9,270</li>
    <li>NM0113: Token Input: 17,885</li>
    <li>NM0160: Token Input: 4,171</li>
  </ul>
</details>

<details>
  <summary>Default</summary>
  <ul>
    <li>Total tokens: 40,999</li>
    <li>NM0070: Tokens Input: 5,601</li>
    <li>NM0074: Tokens Input: 18,726</li>
    <li>NM0081: Token Input: 6753</li>
    <li>NM0117: Token Input: 24,905</li>
    <li>NM0156: Token Input: 22,588</li>
    <li>NM0225: Token Input: 13,707</li>
    <li>NM0225: Token Input: 11,326</li>
  </ul>
</details>