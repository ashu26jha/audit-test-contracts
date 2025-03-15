# pylint: disable=redefined-outer-name
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.v1.detectors.context_scan.schema import ContextScanResponse, FindingList
from api.v1.detectors.context_scan.service import run_context_scan
from core.models.scan import Finding
from core.utils.profiles import Profiles
from core.utils.severity import Severity
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
            Severity=Severity.validate(severity),
            Contracts=contracts,
            Description=description,
            Recommendation=recommendation,
        )
    ]
    return FindingList(findings=mock_findings)


def create_mock_context_scan_endpoint_response(
    issue="Test Issue",
    severity="High",
    contracts=["TestContract"],
    description="Test Description",
    recommendation="Test Recommendation",
):
    mock_findings = [
        Finding(
            Issue=issue,
            Severity=Severity.validate(severity),
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
async def test_run_context_scan_success(mock_retry_async_operation):
    mock_response = create_mock_context_scan_response()
    mock_retry_async_operation.return_value = mock_response

    result = await run_context_scan(
        contracts="Test Contracts",
        summary="Test Summary",
        docs=None,
        invariants=None,
        duckduckgo_results="Test DuckDuckGo Results",
        profile=Profiles.NFT,
    )

    assert isinstance(result, FindingList)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.Issue == "Test Issue"
    # Check if Severity is an enum or a string
    severity = finding.Severity.value if hasattr(finding.Severity, "value") else finding.Severity
    assert severity == "High"
    assert finding.Contracts == ["TestContract"]
    assert finding.Description == "Test Description"
    assert finding.Recommendation == "Test Recommendation"


@pytest.mark.asyncio
async def test_run_context_scan_empty_response(mock_retry_async_operation):
    mock_retry_async_operation.return_value = None

    result = await run_context_scan(
        contracts="Test Contracts",
        summary="Test Summary",
        docs=None,
        invariants=None,
        profile=Profiles.NFT,
    )

    assert isinstance(result, FindingList)
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_run_context_scan_different_profiles(mock_retry_async_operation):
    mock_response = create_mock_context_scan_response()
    mock_retry_async_operation.return_value = mock_response

    for profile in Profiles:
        result = await run_context_scan(
            contracts="Test Contracts",
            summary="Test Summary",
            docs=None,
            invariants=None,
            profile=profile,
        )

        assert isinstance(result, FindingList)
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.Issue == "Test Issue"
        # Check if Severity is an enum or a string
        severity = (
            finding.Severity.value if hasattr(finding.Severity, "value") else finding.Severity
        )
        assert severity == "High"
        assert finding.Contracts == ["TestContract"]
        assert finding.Description == "Test Description"
        assert finding.Recommendation == "Test Recommendation"


@pytest.mark.asyncio
async def test_run_context_scan_claude_model(mock_retry_async_operation):
    mock_response = create_mock_context_scan_response(
        issue="Test Issue Claude",
        severity="Medium",
        contracts=["TestContractClaude"],
        description="Test Description Claude",
        recommendation="Test Recommendation Claude",
    )
    mock_retry_async_operation.return_value = mock_response

    result = await run_context_scan(
        contracts="Test Contracts Claude",
        summary="Test Summary Claude",
        docs=None,
        invariants=None,
        profile=Profiles.NFT,
        model="claude-3-5-sonnet-latest",
    )

    assert isinstance(result, FindingList)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.Issue == "Test Issue Claude"
    # Check if Severity is an enum or a string
    severity = finding.Severity.value if hasattr(finding.Severity, "value") else finding.Severity
    assert severity == "Medium"
    assert finding.Contracts == ["TestContractClaude"]
    assert finding.Description == "Test Description Claude"
    assert finding.Recommendation == "Test Recommendation Claude"

    mock_retry_async_operation.assert_awaited_once()
    called_kwargs = mock_retry_async_operation.call_args.kwargs
    assert called_kwargs["model_type"] == "claude-3-5-sonnet-latest"


@pytest.mark.asyncio
async def test_run_context_scan_no_profile(mock_retry_async_operation):
    mock_response = create_mock_context_scan_response(
        issue="Test Issue No Profile",
        severity="Low",
        contracts=["TestContractNoProfile"],
        description="Test Description No Profile",
        recommendation="Test Recommendation No Profile",
    )
    mock_retry_async_operation.return_value = mock_response

    result = await run_context_scan(
        contracts="Test Contracts No Profile",
        summary="Test Summary No Profile",
        docs=None,
        invariants=None,
        profile=Profiles.NONE,
    )

    assert isinstance(result, FindingList)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.Issue == "Test Issue No Profile"
    # Check if Severity is an enum or a string
    severity = finding.Severity.value if hasattr(finding.Severity, "value") else finding.Severity
    assert severity == "Low"
    assert finding.Contracts == ["TestContractNoProfile"]
    assert finding.Description == "Test Description No Profile"
    assert finding.Recommendation == "Test Recommendation No Profile"

    mock_retry_async_operation.assert_awaited_once()
    called_kwargs = mock_retry_async_operation.call_args.kwargs
    assert "model_type" in called_kwargs


def test_context_scan_endpoint(mock_retry_async_operation):
    mock_response = create_mock_context_scan_endpoint_response()
    mock_retry_async_operation.return_value = mock_response

    response = client.post(
        "/api/v1/detectors/context-scan",
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


def test_context_scan_endpoint_error(mock_retry_async_operation):
    mock_retry_async_operation.side_effect = HTTPException(
        status_code=400, detail="Failed to parse LLM response as valid JSON"
    )

    response = client.post(
        "/api/v1/detectors/context-scan",
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
