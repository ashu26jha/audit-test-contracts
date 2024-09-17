from unittest.mock import AsyncMock, patch

import pytest
from api.v1.schemas.context_scan_exceptions import (
    EmptyResponseError,
    InvalidFormatError,
    JSONParsingError,
)
from api.v1.schemas.context_scan_schema import Finding
from api.v1.services import context_scan_service
from common.profiles import Profiles
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


@pytest.fixture
def mock_send_prompt_to_llm_async():
    with patch(
        "api.v1.services.context_scan_service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.mark.asyncio
async def test_perform_context_scan_success(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = """
    [
        {
            "Issue": "Test Issue",
            "Severity": "High",
            "Contracts": ["TestContract"],
            "Description": "Test Description",
            "Recommendation": "Test Recommendation"
        }
    ]
    """

    result = await context_scan_service.perform_context_scan(
        "Test Summary", "Test Contracts", Profiles.NFT
    )

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], Finding)
    assert result[0].Issue == "Test Issue"
    assert result[0].Severity == "High"
    assert result[0].Contracts == ["TestContract"]
    assert result[0].Description == "Test Description"
    assert result[0].Recommendation == "Test Recommendation"


@pytest.mark.asyncio
async def test_perform_context_scan_empty_response(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = ""

    with pytest.raises(EmptyResponseError) as exc_info:
        await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", Profiles.NFT
        )

    assert str(exc_info.value) == "LLM response was None or empty."


@pytest.mark.asyncio
async def test_perform_context_scan_no_json_content(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = "No JSON content here."

    with pytest.raises(JSONParsingError) as exc_info:
        await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", Profiles.NFT
        )

    assert str(exc_info.value) == "Failed to parse LLM response as valid JSON."


@pytest.mark.asyncio
async def test_perform_context_scan_invalid_json_syntax(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = """
    Invalid JSON syntax
    """

    with pytest.raises(JSONParsingError) as exc_info:
        await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", Profiles.NFT
        )

    assert "Failed to parse LLM response as valid JSON." in str(exc_info.value)


@pytest.mark.asyncio
async def test_perform_context_scan_invalid_json_structure(
    mock_send_prompt_to_llm_async,
):
    mock_send_prompt_to_llm_async.return_value = """
    {
        "Invalid": "JSON"
    }
    """

    with pytest.raises(InvalidFormatError) as exc_info:
        await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", Profiles.NFT
        )

    assert str(exc_info.value) == "Expected the LLM response to be a list of findings."


@pytest.mark.asyncio
async def test_perform_context_scan_different_profiles(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = """
    [
        {
            "Issue": "Test Issue",
            "Severity": "High",
            "Contracts": ["TestContract"],
            "Description": "Test Description",
            "Recommendation": "Test Recommendation"
        }
    ]
    """

    implemented_profiles = [Profiles.NFT, Profiles.DEFI, Profiles.DAO]

    for profile in implemented_profiles:
        result = await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", profile
        )
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], Finding)
        assert result[0].Issue == "Test Issue"
        assert result[0].Severity == "High"
        assert result[0].Contracts == ["TestContract"]
        assert result[0].Description == "Test Description"
        assert result[0].Recommendation == "Test Recommendation"


@pytest.mark.asyncio
async def test_perform_context_scan_claude_model(mock_send_prompt_to_llm_async, monkeypatch):
    """
    Test the perform_context_scan function when using a Claude model.
    """
    # Monkeypatch the LLM_MODEL to simulate using a Claude model
    monkeypatch.setattr("api.v1.services.context_scan_service.LLM_MODEL", "claude-3-5-20240620")

    mock_send_prompt_to_llm_async.return_value = """
    [
        {
            "Issue": "Test Issue Claude",
            "Severity": "Medium",
            "Contracts": ["TestContractClaude"],
            "Description": "Test Description Claude",
            "Recommendation": "Test Recommendation Claude"
        }
    ]
    """

    result = await context_scan_service.perform_context_scan(
        "Test Summary Claude", "Test Contracts Claude", Profiles.NFT
    )

    # Verify the results
    assert isinstance(result, list)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, Finding)
    assert finding.Issue == "Test Issue Claude"
    assert finding.Severity == "Medium"
    assert finding.Contracts == ["TestContractClaude"]
    assert finding.Description == "Test Description Claude"
    assert finding.Recommendation == "Test Recommendation Claude"

    # Ensure that send_prompt_to_llm_async was called with 'claude-3-5-20240620' as the model
    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    model_used = called_args[0]
    assert model_used == "claude-3-5-20240620"


@pytest.mark.asyncio
async def test_perform_context_scan_no_profile(mock_send_prompt_to_llm_async):
    """
    Test the perform_context_scan function when no profile is selected (Profiles.NONE).
    """
    mock_send_prompt_to_llm_async.return_value = """
    [
        {
            "Issue": "Test Issue No Profile",
            "Severity": "Low",
            "Contracts": ["TestContractNoProfile"],
            "Description": "Test Description No Profile",
            "Recommendation": "Test Recommendation No Profile"
        }
    ]
    """

    result = await context_scan_service.perform_context_scan(
        "Test Summary No Profile", "Test Contracts No Profile", Profiles.NONE
    )

    # Verify the results
    assert isinstance(result, list)
    assert len(result) == 1
    finding = result[0]
    assert isinstance(finding, Finding)
    assert finding.Issue == "Test Issue No Profile"
    assert finding.Severity == "Low"
    assert finding.Contracts == ["TestContractNoProfile"]
    assert finding.Description == "Test Description No Profile"
    assert finding.Recommendation == "Test Recommendation No Profile"

    # Ensure that the system prompt was not used (since Profiles.NONE is selected)
    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    system_prompt_used = called_args[2]
    assert system_prompt_used is None


def test_context_scan_endpoint():
    response = client.post(
        "/api/v1/context-scan",
        json={
            "summary": "Test Summary",
            "contracts": "Test Contracts",
            "profile": "nft",
        },
    )
    if response.status_code != 200:
        print("Response status code:", response.status_code)
        print("Response content:", response.text)
    assert response.status_code == 200
    result = response.json()
    assert "findings" in result
    assert isinstance(result["findings"], list)
