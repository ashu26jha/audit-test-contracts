from __future__ import annotations

from app import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_generate_summary():
    response = client.post("/api/v1/generate-summary", json={"text": "Test text"})
    assert response.status_code == 200
    assert "summary" in response.json()
