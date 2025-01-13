# pylint: disable=redefined-outer-name
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.v1.detectors.context_scan.schema import ContextScanResponse
from api.v1.detectors.context_scan.service import run_context_scan
from core.models.scan import Finding
from core.utils.profiles import Profiles
from main import app

client = TestClient(app)


def create_mock_context_scan_response(
    issue="Test Issue",
    severity="High",
    contracts=["TestContract"],
    description="Test Description",
    recommendation="Test Recommendation",
):
    mock_findings = [
        Finding(
            Issue=issue,
            Severity=severity,
            Contracts=contracts,
            Description=description,
            Recommendation=recommendation,
        )
    ]
    return ContextScanResponse(findings=mock_findings)


@pytest.fixture
def mock_send_prompt_to_llm_async():
    with patch(
        "api.v1.detectors.context_scan.service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.fixture
def mock_retry_async_operation():
    with patch(
        "api.v1.detectors.context_scan.service.retry_async_operation",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.mark.asyncio
async def test_run_context_scan_success(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response()
    mock_send_prompt_to_llm_async.return_value = mock_response

    result = await run_context_scan("Test Summary", None, "Test Contracts", Profiles.NFT)

    assert isinstance(result, dict)
    assert "findings" in result
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["Issue"] == "Test Issue"
    assert finding["Severity"] == "High"
    assert finding["Contracts"] == ["TestContract"]
    assert finding["Description"] == "Test Description"
    assert finding["Recommendation"] == "Test Recommendation"


@pytest.mark.asyncio
async def test_run_context_scan_empty_response(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = None

    result = await run_context_scan("Test Summary", None, "Test Contracts", Profiles.NFT)

    assert isinstance(result, dict)
    assert "findings" in result
    assert len(result["findings"]) == 0


@pytest.mark.asyncio
async def test_run_context_scan_different_profiles(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response()
    mock_send_prompt_to_llm_async.return_value = mock_response

    for profile in Profiles:
        result = await run_context_scan("Test Summary", None, "Test Contracts", profile)
        assert isinstance(result, dict)
        assert "findings" in result
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["Issue"] == "Test Issue"
        assert finding["Severity"] == "High"
        assert finding["Contracts"] == ["TestContract"]
        assert finding["Description"] == "Test Description"
        assert finding["Recommendation"] == "Test Recommendation"


@pytest.mark.asyncio
async def test_run_context_scan_claude_model(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response(
        issue="Test Issue Claude",
        severity="Medium",
        contracts=["TestContractClaude"],
        description="Test Description Claude",
        recommendation="Test Recommendation Claude",
    )
    mock_send_prompt_to_llm_async.return_value = mock_response

    result = await run_context_scan(
        "Test Summary Claude",
        None,
        "Test Contracts Claude",
        Profiles.NFT,
        "claude-3-5-sonnet-latest",
    )

    assert isinstance(result, dict)
    assert "findings" in result
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["Issue"] == "Test Issue Claude"
    assert finding["Severity"] == "Medium"
    assert finding["Contracts"] == ["TestContractClaude"]
    assert finding["Description"] == "Test Description Claude"
    assert finding["Recommendation"] == "Test Recommendation Claude"

    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    model_used = called_args[0]
    assert model_used == "claude-3-5-sonnet-latest"


@pytest.mark.asyncio
async def test_run_context_scan_no_profile(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response(
        issue="Test Issue No Profile",
        severity="Low",
        contracts=["TestContractNoProfile"],
        description="Test Description No Profile",
        recommendation="Test Recommendation No Profile",
    )
    mock_send_prompt_to_llm_async.return_value = mock_response

    result = await run_context_scan(
        "Test Summary No Profile", None, "Test Contracts No Profile", Profiles.NONE
    )

    assert isinstance(result, dict)
    assert "findings" in result
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["Issue"] == "Test Issue No Profile"
    assert finding["Severity"] == "Low"
    assert finding["Contracts"] == ["TestContractNoProfile"]
    assert finding["Description"] == "Test Description No Profile"
    assert finding["Recommendation"] == "Test Recommendation No Profile"

    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    system_prompt_used = called_args[2]
    assert system_prompt_used is None


def test_context_scan_endpoint(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response()
    mock_send_prompt_to_llm_async.return_value = mock_response

    response = client.post(
        "/api/v1/context-scan",
        json={
            "summary": "Test Summary",
            "contracts": "Test Contracts",
            "profile": "nft",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert "data" in result
    assert "findings" in result["data"]
    assert isinstance(result["data"]["findings"], list)


def test_context_scan_endpoint_error(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.side_effect = HTTPException(
        status_code=400, detail="Failed to parse LLM response as valid JSON"
    )

    response = client.post(
        "/api/v1/context-scan",
        json={
            "summary": "Test Summary",
            "contracts": "Test Contracts",
            "profile": "nft",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert "data" in result
    assert "findings" in result["data"]
    assert len(result["data"]["findings"]) == 0
