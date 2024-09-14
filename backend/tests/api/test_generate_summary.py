from __future__ import annotations

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_generate_summary():
    response = client.post("/api/v1/generate-summary", json={"text": "Test text"})
    assert response.status_code == 200
    assert "summary" in response.json()
