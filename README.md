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


### roadmap:

- [x] health check endpoint
- [x] context scan endpoint
- [ ] generate summary endpoint
- [ ] critics endpoint
