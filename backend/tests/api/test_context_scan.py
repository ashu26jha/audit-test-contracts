# pylint: disable=redefined-outer-name
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.v1.schemas.context_scan_schema import ContextScanResponse, Finding
from api.v1.services import context_scan_service
from common.profiles import Profiles
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
        "api.v1.services.context_scan_service.send_prompt_to_llm_async",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.mark.asyncio
async def test_perform_context_scan_success(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response()
    mock_send_prompt_to_llm_async.return_value = mock_response

    result = await context_scan_service.perform_context_scan(
        "Test Summary", "Test Contracts", Profiles.NFT
    )

    assert isinstance(result, ContextScanResponse)
    assert len(result.findings) == 1
    assert isinstance(result.findings[0], Finding)
    assert result.findings[0].Issue == "Test Issue"
    assert result.findings[0].Severity == "High"
    assert result.findings[0].Contracts == ["TestContract"]
    assert result.findings[0].Description == "Test Description"
    assert result.findings[0].Recommendation == "Test Recommendation"


@pytest.mark.asyncio
async def test_perform_context_scan_empty_response(mock_send_prompt_to_llm_async):
    mock_send_prompt_to_llm_async.return_value = None
    with pytest.raises(HTTPException) as exc_info:
        await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", Profiles.NFT
        )
    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "LLM response was empty or invalid"


@pytest.mark.asyncio
async def test_perform_context_scan_different_profiles(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response()
    mock_send_prompt_to_llm_async.return_value = mock_response

    for profile in Profiles:
        result = await context_scan_service.perform_context_scan(
            "Test Summary", "Test Contracts", profile
        )
        assert isinstance(result, ContextScanResponse)
        assert len(result.findings) == 1
        assert isinstance(result.findings[0], Finding)
        assert result.findings[0].Issue == "Test Issue"
        assert result.findings[0].Severity == "High"
        assert result.findings[0].Contracts == ["TestContract"]
        assert result.findings[0].Description == "Test Description"
        assert result.findings[0].Recommendation == "Test Recommendation"


@pytest.mark.asyncio
async def test_perform_context_scan_claude_model(mock_send_prompt_to_llm_async, monkeypatch):
    monkeypatch.setattr(
        "api.v1.services.context_scan_service.LLM_MODEL", "claude-3-5-sonnet-latest"
    )

    mock_response = create_mock_context_scan_response(
        issue="Test Issue Claude",
        severity="Medium",
        contracts=["TestContractClaude"],
        description="Test Description Claude",
        recommendation="Test Recommendation Claude",
    )
    mock_send_prompt_to_llm_async.return_value = mock_response

    result = await context_scan_service.perform_context_scan(
        "Test Summary Claude", "Test Contracts Claude", Profiles.NFT
    )

    assert isinstance(result, ContextScanResponse)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert isinstance(finding, Finding)
    assert finding.Issue == "Test Issue Claude"
    assert finding.Severity == "Medium"
    assert finding.Contracts == ["TestContractClaude"]
    assert finding.Description == "Test Description Claude"
    assert finding.Recommendation == "Test Recommendation Claude"

    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    model_used = called_args[0]
    assert model_used == "claude-3-5-sonnet-latest"


@pytest.mark.asyncio
async def test_perform_context_scan_no_profile(mock_send_prompt_to_llm_async):
    mock_response = create_mock_context_scan_response(
        issue="Test Issue No Profile",
        severity="Low",
        contracts=["TestContractNoProfile"],
        description="Test Description No Profile",
        recommendation="Test Recommendation No Profile",
    )
    mock_send_prompt_to_llm_async.return_value = mock_response

    result = await context_scan_service.perform_context_scan(
        "Test Summary No Profile", "Test Contracts No Profile", Profiles.NONE
    )

    assert isinstance(result, ContextScanResponse)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert isinstance(finding, Finding)
    assert finding.Issue == "Test Issue No Profile"
    assert finding.Severity == "Low"
    assert finding.Contracts == ["TestContractNoProfile"]
    assert finding.Description == "Test Description No Profile"
    assert finding.Recommendation == "Test Recommendation No Profile"

    mock_send_prompt_to_llm_async.assert_awaited_once()
    called_args = mock_send_prompt_to_llm_async.call_args[0]
    system_prompt_used = called_args[2]
    assert system_prompt_used is None


def test_context_scan_endpoint():
    with patch(
        "api.v1.services.context_scan_service.perform_context_scan",
        new_callable=AsyncMock,
    ) as mock_perform_context_scan:
        mock_perform_context_scan.return_value = [
            Finding(
                Issue="Test Issue",
                Severity="High",
                Contracts=["TestContract"],
                Description="Test Description",
                Recommendation="Test Recommendation",
            )
        ]

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


def test_context_scan_endpoint_error():
    with patch(
        "api.v1.services.context_scan_service.perform_context_scan",
        new_callable=AsyncMock,
    ) as mock_perform_context_scan:
        mock_perform_context_scan.side_effect = HTTPException(
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
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["success"] is False
        assert error_response["code"] == 400
        assert "Failed to parse LLM response as valid JSON" in error_response["message"]
        assert error_response["details"] is None
