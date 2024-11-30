from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check(test_client):
    response = test_client.get("/api/v1/health-check")
    assert response.status_code == 200
    assert response.json() == {"success": True, "data": {"details": "All systems operational"}}
