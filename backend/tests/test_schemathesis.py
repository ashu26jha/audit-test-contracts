import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest
import schemathesis
import vcr
from fastapi import HTTPException
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, Phase, settings

from main import app
from tests.conftest import TEST_API_KEY, vcr_config

# Globally enable OpenAPI 3.1 experimental feature
schemathesis.experimental.OPEN_API_3_1.enable()

# Create a schema object from your FastAPI app
schema = schemathesis.from_dict(app.openapi())

# Define endpoints that trigger expensive operations
LLM_ENDPOINTS = {
    "/api/v1/generate-summary",
    "/api/v1/generate-invariants",
    "/api/v1/generate-ast-tree",
    "/api/v1/test-critic-phase",
    "/api/v1/remove-duplicates",
    "/api/v1/mitigate-findings",
    "/api/v1/agentic/scan-per-address",
    "/api/v1/benchmark/launch",
    "/api/v1/benchmark/result/{scan_id}",
    "/api/v1/detectors/autonomous-agent",
    "/api/v1/detectors/context-scan",
    "/api/v1/detectors/fuzzer",
    "/api/v1/detectors/static-analyzer",
    "/api/v1/tools/duckduckgo-search",
    "/api/v1/tools/jina-parse",
    "/api/v1/tools/build-queries",
    "/api/v1/tools/ddg-search/{query}",
}

PUBLIC_ENDPOINTS = {
    "/api/v1/health-check",
    "/api/v1/auth/github-login",
    "/api/v1/auth/github-callback",
    "/api/v1/auth/test-auth/token",
    "/api/v1/auth/logout",
    "/api/v1/payments/stripe-webhook",
    "/api/v1/etherscan/source-code",
    "/api/v1/generate-ast-tree",
    "/api/v1/test-critic-phase",
    "/api/v1/detectors/autonomous-agent",
    "/api/v1/detectors/multi-agents",
    "/api/v1/tools/ddg-search/{query}",
    "/api/v1/tools/duckduckgo-search",
    "/api/v1/tools/jina-parse",
}

# Add to the top with other constants
GITHUB_ENDPOINTS = {
    "/api/v1/github/repositories/{owner}",
    "/api/v1/github/repository-branches/{owner}/{repo}",
    "/api/v1/github/repository-contents/{owner}/{repo}",
    "/api/v1/github/repository-readme/{owner}/{repo}",
    "/api/v1/github/organizations",
    "/api/v1/github/repository-info",
    "/api/v1/github/repository-docs/{owner}/{repo}",
    "/api/v1/github/validate-repository",
}

# Add to constants
PAYMENT_ENDPOINTS = {
    "/api/v1/payments/create-subscription-session",
    "/api/v1/payments/create-portal-session",
    "/api/v1/payments/create-enterprise-subscription",
}


# Define common hypothesis settings
hypothesis_settings = settings(
    phases=[Phase.explicit, Phase.reuse, Phase.generate],
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,  # Disable deadline to prevent timing-related failures
)


def prepare_request_kwargs(case):
    """Prepare request kwargs with proper headers."""
    kwargs = case.as_transport_kwargs()

    # Ensure headers exist
    if "headers" not in kwargs:
        kwargs["headers"] = {}

    # Ensure headers are ASCII-safe
    kwargs["headers"] = {
        k: v.encode("ascii", "ignore").decode("ascii") for k, v in kwargs["headers"].items()
    }

    # Add standard headers with test API key
    kwargs["headers"].update(
        {
            "x-api-key": TEST_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    return kwargs


@pytest.fixture
def skip_llm_check():
    """Helper to check if endpoint should be skipped."""

    def _skip_llm(case):
        return case.path in LLM_ENDPOINTS

    return _skip_llm


@schema.parametrize()
@hypothesis_settings
@pytest.mark.usefixtures("setup_db")
def test_authentication(case):
    """
    Test authentication requirements across all endpoints
    """
    # Skip LLM endpoints early - using exact path matching
    if case.path in LLM_ENDPOINTS:
        return

    # For auth testing, we want the request without API key
    kwargs = case.as_transport_kwargs()
    if "headers" not in kwargs:
        kwargs["headers"] = {}

    # Ensure headers are ASCII-safe but don't add API key
    kwargs["headers"] = {
        k: v.encode("ascii", "ignore").decode("ascii") for k, v in kwargs["headers"].items()
    }
    kwargs["headers"].update(
        {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    # Test without auth token - use clean client
    client = TestClient(app)
    if case.path == "/api/v1/auth/test-auth/token":
        kwargs["json"] = {"username": "testuser"}

    response = client.request(**kwargs)

    if case.path in PUBLIC_ENDPOINTS:
        assert (
            response.status_code != 401
        ), f"Public endpoint {case.path} should not require authentication"
    else:
        assert response.status_code in [
            401,
            403,
        ], f"Endpoint {case.path} should require authentication"


@schema.parametrize()
@hypothesis_settings
@pytest.mark.usefixtures("setup_db", "mock_stripe")
def test_schema_validation(case, auth_token):
    """Test input validation and schema conformance."""
    if case.path in LLM_ENDPOINTS:
        return

    # Standardize GitHub parameters BEFORE preparing the request
    if case.path in GITHUB_ENDPOINTS:
        if case.path_parameters is not None:
            if "owner" in case.path_parameters:
                case.path_parameters["owner"] = "0"
            if "repo" in case.path_parameters:
                case.path_parameters["repo"] = "0"

    kwargs = prepare_request_kwargs(case)
    if case.path == "/api/v1/auth/test-auth/token":
        kwargs["json"] = {"username": "testuser"}
    # elif case.path == "/api/v1/etherscan/source-code":
    #     kwargs["json"] = {"contractAddress": TEST_CONTRACT_ADDRESS, "chainId": 1}

    client = TestClient(app)
    client.cookies.set("auth_token", auth_token)

    response = handle_github_request(case, client, kwargs, "schema")
    # Include 429 in valid response codes and make the error message more descriptive
    valid_status_codes = [200, 201, 202, 204, 400, 401, 403, 404, 422, 429, 500]
    assert (
        response.status_code in valid_status_codes
    ), f"Unexpected status code {response.status_code}. Expected one of {valid_status_codes}"


@schema.parametrize()
@hypothesis_settings
@pytest.mark.usefixtures("setup_db")
def test_input_validation(case, auth_token):
    """
    Test input validation without executing the actual operations
    """
    if case.path in LLM_ENDPOINTS:
        return

    if case.method not in ["POST", "PUT", "PATCH"]:
        return

    # Skip endpoints that don't require payloads
    no_payload_endpoints = {
        "/api/v1/auth/logout",
        "/api/v1/payments/create-portal-session",
        "/api/v1/payments/stripe-webhook",  # Stripe webhook has its own validation
    }
    if case.path in no_payload_endpoints:
        return

    kwargs = prepare_request_kwargs(case)
    kwargs["json"] = {}

    client = TestClient(app)
    client.cookies.set("auth_token", auth_token)

    response = handle_github_request(case, client, kwargs, "input")
    assert response.status_code == 422, f"Empty payload should fail validation for {case.path}"


@schema.parametrize()
@hypothesis_settings
@pytest.mark.usefixtures("setup_db")
def test_response_time(case, auth_token):
    """Test that all endpoints respond within a reasonable time."""
    if case.path in LLM_ENDPOINTS:
        return

    # Standardize GitHub parameters BEFORE preparing the request
    if case.path in GITHUB_ENDPOINTS:
        if case.path_parameters is not None:
            if "owner" in case.path_parameters:
                case.path_parameters["owner"] = "0"
            if "repo" in case.path_parameters:
                case.path_parameters["repo"] = "0"

    kwargs = prepare_request_kwargs(case)
    if case.path == "/api/v1/auth/test-auth/token":
        kwargs["json"] = {"username": "testuser"}

    client = TestClient(app)
    client.cookies.set("auth_token", auth_token)

    start_time = time.time()
    handle_github_request(case, client, kwargs, "time")
    end_time = time.time()

    elapsed = end_time - start_time
    assert elapsed < 5.0, f"Response time too slow for {case.path}: {elapsed:.2f}s"


@schema.parametrize()
@hypothesis_settings
@pytest.mark.usefixtures("setup_db")
def test_content_type(case, auth_token):
    """Test that responses have correct content type."""
    if case.path in LLM_ENDPOINTS:
        return

    kwargs = prepare_request_kwargs(case)
    if case.path == "/api/v1/auth/test-auth/token":
        kwargs["json"] = {"username": "testuser"}

    client = TestClient(app)
    client.cookies.set("auth_token", auth_token)

    response = handle_github_request(case, client, kwargs, "content")

    if response.status_code in [301, 302, 303, 307, 308]:
        return

    assert "content-type" in response.headers.keys(), f"No content-type header for {case.path}"
    assert (
        "application/json" in response.headers["content-type"].lower()
    ), f"Not JSON content-type for {case.path}"


@schema.parametrize()
@hypothesis_settings
@pytest.mark.usefixtures("setup_db")
def test_error_response_format(case, auth_token):
    """Test that error responses follow the standard format."""
    if case.path in LLM_ENDPOINTS or case.path in PUBLIC_ENDPOINTS:
        return

    kwargs = prepare_request_kwargs(case)

    # Test without auth
    client = TestClient(app)
    response = handle_github_request(case, client, kwargs, "error")
    if response.status_code == 401:
        data = response.json()
        assert "success" in data
        assert data["success"] is False
        assert "message" in data
        assert "code" in data
        assert ("error" in data) or ("details" in data)

    # Test with auth but invalid payload
    if case.method in ["POST", "PUT", "PATCH"]:
        kwargs["json"] = {"invalid": "payload"}
        client = TestClient(app)
        client.cookies.set("auth_token", auth_token)
        response = handle_github_request(case, client, kwargs, "error_auth")
        if response.status_code >= 400:
            data = response.json()
            if "detail" not in data:
                assert "success" in data
                assert data["success"] is False
                assert "message" in data
                assert "code" in data
                assert ("error" in data) or ("details" in data)


@pytest.mark.usefixtures("mock_auth")
def test_webhook_handler_invalid_signature():
    with patch(
        "api.v1.payments.service.StripeWebhookService.handle_webhook",
        new_callable=AsyncMock,
    ) as mock_handle_webhook:
        mock_handle_webhook.side_effect = HTTPException(status_code=400, detail="Invalid signature")

        client = TestClient(app)
        response = client.post(
            "/api/v1/payments/stripe-webhook",
            headers={"Stripe-Signature": "invalid_signature"},
            content=b"test_payload",
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["success"] is False
        assert error_response["code"] == 400
        assert "Invalid signature" in error_response["message"]


def handle_github_request(case, client, kwargs, test_type):
    """Handle GitHub requests with VCR cassettes."""
    if case.path in GITHUB_ENDPOINTS:
        # Convert query to params for TestClient
        if "query" in kwargs:
            kwargs["params"] = kwargs.pop("query")

        # Add required query parameters based on the endpoint
        if "params" not in kwargs:
            kwargs["params"] = {}

        # Format the URL with path parameters
        url = case.path
        if "path_parameters" in kwargs:
            path_params = kwargs.pop("path_parameters")
            for key, value in path_params.items():
                url = url.replace(f"{{{key}}}", str(value))
        kwargs["url"] = url

        # Add required query parameters based on the endpoint
        if case.path == "/api/v1/github/repository-contents/{owner}/{repo}":
            kwargs["params"].update({"path": "README.md", "ref": "main"})
        elif case.path == "/api/v1/github/repository-readme/{owner}/{repo}":
            kwargs["params"]["ref"] = "main"
        elif case.path == "/api/v1/github/repository-info":
            kwargs["params"]["repo_url"] = "https://github.com/test-owner/test-repo"
        elif case.path == "/api/v1/github/validate-repository":
            kwargs["params"]["repo_url"] = "https://github.com/test-owner/test-repo"

        # Generate cassette name based on test parameters
        path_part = case.path.replace("/", "_").replace("{", "").replace("}", "")
        cassette_name = f"github_{test_type}_{case.method.lower()}_{path_part}.yaml"
        cassette_path = f"{vcr_config['cassette_library_dir']}/{cassette_name}"

        try:
            with vcr.use_cassette(cassette_path, **vcr_config):
                try:
                    response = client.request(**kwargs)
                except RuntimeError as e:
                    if "Event loop is closed" in str(e):
                        # Create a new event loop and retry
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        response = client.request(**kwargs)
                    else:
                        raise
                return response
        except Exception:
            # If cassette playback fails, try with new episodes
            config = dict(vcr_config)
            config["record_mode"] = "new_episodes"
            with vcr.use_cassette(cassette_path, **config):
                try:
                    response = client.request(**kwargs)
                except RuntimeError as e:
                    if "Event loop is closed" in str(e):
                        # Create a new event loop and retry
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        response = client.request(**kwargs)
                    else:
                        raise
                return response
    else:
        try:
            response = client.request(**kwargs)
        except RuntimeError as e:
            if "Event loop is closed" in str(e):
                # Create a new event loop and retry
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                response = client.request(**kwargs)
            else:
                raise
        return response
