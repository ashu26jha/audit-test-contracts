from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_generate_summary():
    # Mock the send_prompt_to_llm_async function
    with patch(
        "api.v1.services.generate_summary_service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock_send_prompt:
        mock_send_prompt.return_value = """
        ```json
        {
            "summary": "This contract handles NFT transactions.",
            "type": "NFT"
        }
        ```
        """

        response = client.post(
            "/api/v1/generate-summary",
            json={"contracts": "Test Contracts"},  # Ensure the key matches your schema
        )

        assert response.status_code == 200
        result = response.json()
        assert result["summary"] == "This contract handles NFT transactions."
        assert result["type"] == "NFT"

        # Ensure that send_prompt_to_llm_async was called
        assert mock_send_prompt.called


@pytest.mark.asyncio
async def test_generate_summary_error():
    with patch(
        "api.v1.services.generate_summary_service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock_send_prompt:
        mock_send_prompt.side_effect = Exception("LLM error")

        response = client.post(
            "/api/v1/generate-summary",
            json={"contracts": "Test Contracts"},
        )

        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error"}
