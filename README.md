# yokai-ai-reviewer

## Front-end

## Back-end

### Launch the backend

#### To launch a local server:

```bash
uvicorn main:app --reload
```

#### To launch a docker image:

```bash
docker build -t backend-image -f backend/Dockerfile.backend .
```

Then run the container:

```bash
docker run -p 8000:8000 backend-image
```

#### To launch a prod server:

```bash
fastapi run
```

### To run linter:

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

### To run tests:

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
