# pylint: disable=redefined-outer-name
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.v1.utilities.summary.schema import SummaryResponse
from api.v1.utilities.summary.service import generate_summary
from core.utils.errors import LLMError
from main import app

client = TestClient(app)


@pytest.fixture
def mock_send_prompt_to_llm_async():
    with patch(
        "api.v1.utilities.summary.service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.mark.asyncio
async def test_generate_summary_success(mock_send_prompt_to_llm_async):
    mock_summary_response = SummaryResponse(summary="This is a test summary.", type="DEFAULT")
    mock_send_prompt_to_llm_async.return_value = mock_summary_response

    summary, contract_type = await generate_summary("Test Contracts")

    assert isinstance(summary, str)
    assert len(summary) > 0
    assert contract_type in ["DEFAULT", "DEFI", "NFT", "DAO", "UTILITY"]

    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_kwargs = mock_send_prompt_to_llm_async.call_args.kwargs
    assert isinstance(called_kwargs["messages"], (str, list))

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
    error_message = "LLM error"
    mock_send_prompt_to_llm_async.side_effect = LLMError(
        message=error_message, details={"model": "test-model", "error": "test error"}
    )

    # Test the service layer - should raise LLMError
    with pytest.raises(LLMError) as service_exc:
        await generate_summary("Test Contracts")
    assert error_message in str(service_exc.value)

    # Test the API endpoint - should return 503 with error details
    response = client.post("/api/v1/generate-summary", json={"contracts": "Test Contracts"})
    assert response.status_code == 503
    response_data = response.json()
    assert response_data["success"] is False
    assert response_data["code"] == 503
    assert error_message in response_data["message"]
