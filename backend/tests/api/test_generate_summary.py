from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.v1.schemas.generate_summary_schema import SummaryResponse
from api.v1.services import generate_summary_service
from main import app

client = TestClient(app)


@pytest.fixture
def mock_send_prompt_to_llm_async():
    with patch(
        "api.v1.services.generate_summary_service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.mark.asyncio
async def test_generate_summary_success(mock_send_prompt_to_llm_async):
    mock_summary_response = SummaryResponse(summary="This is a test summary.", type="DEFAULT")
    mock_send_prompt_to_llm_async.return_value = mock_summary_response

    summary, contract_type = await generate_summary_service.generate_summary("Test Contracts")

    assert isinstance(summary, str)
    assert len(summary) > 0
    assert contract_type in ["DEFAULT", "DEFI", "NFT", "DAO", "UTILITY"]

    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    assert isinstance(called_args[1], str)

    # Test the API response format
    response = client.post("/api/v1/generate-summary", json={"contracts": "Test Contracts"})
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["success"] is True
    assert "data" in response_data
    assert "summary" in response_data["data"]
    assert "type" in response_data["data"]


@pytest.mark.asyncio
async def test_generate_summary_error(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.side_effect = Exception("LLM error")

    response = client.post("/api/v1/generate-summary", json={"contracts": "Test Contracts"})
    assert response.status_code == 500
    error_response = response.json()
    assert error_response["success"] is False
    assert error_response["code"] == 500
    assert error_response["message"] == "Internal Server Error"
    assert error_response["details"] is None

    with pytest.raises(HTTPException) as exc_info:
        await generate_summary_service.generate_summary("Test Contracts")

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Internal Server Error"
